//! Installation grant policy, transaction admission, and durable replay protection.
//!
//! A transaction is reserved after preflight and consumed before activation. A
//! reserved transaction can be retried while its grant is valid. A consumed one
//! needs a new grant even if activation was interrupted.

use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;

use nix::fcntl::Flock;
use nix::fcntl::FlockArg;
use reportify::bail;
use reportify::ResultExt;
use rugix_bundle::grants::InstallOperation;
use rugix_bundle::grants::InstallTarget as GrantTarget;
use rugix_bundle::grants::RebootMode;
use rugix_bundle::grants::SystemInstallOptions;
use rugix_grants::DeviceIdentity;
use rugix_grants::GrantVerifier;
use rugix_grants::VerificationContext;
use rugix_grants::VerifiedGrant;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;
use tracing::info;
use tracing::warn;

use super::BundleInstallOptions;
use super::InstallTarget;
use super::SystemRebootMode;
use crate::config::config::Config;
use crate::config::grants::GrantState;
use crate::config::grants::GrantTransaction;
use crate::config::grants::GrantsConfig;
use crate::system::SystemResult;

/// An authenticated installation holding the device's grant transaction lock.
pub(crate) struct GrantSession {
    config: GrantsConfig,
    signed: Vec<u8>,
    verified: VerifiedGrant<InstallOperation>,
    content_hash: String,
    state: GrantState,
    directory: PathBuf,
    _lock: Flock<File>,
}

impl GrantSession {
    /// Authenticate the grant and bind its arguments before any installer work.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(crate) fn begin(
        config: &Config,
        options: &BundleInstallOptions,
        target: &InstallTarget,
    ) -> SystemResult<Option<Self>> {
        let Some(policy) = &config.grants else {
            if options.grant.is_some() {
                bail!("installation grants are not configured");
            }
            return Ok(None);
        };
        if options.bundle_hash.is_some()
            || options.root_cert.is_some()
            || options.insecure_skip_bundle_verification
            || options.insecure_allow_missing_block_index
            || options.skip_compatibility_check
        {
            bail!("installation security overrides are disabled by grant policy");
        }
        let signed = options
            .grant
            .as_ref()
            .ok_or_else(|| reportify::whatever!("a detached installation grant is required"))?;
        let verified = verify(policy, signed)?;
        if verified.grant().operation.target != grant_target(target) {
            bail!("grant installation target or options do not match");
        }
        let content_hash = HashAlgorithm::Sha256
            .hash::<Vec<u8>>(
                &rugix_grants::prepare(verified.grant())
                    .whatever("unable to encode verified grant")?,
            )
            .to_string();
        let directory = state_directory(policy)?;
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("lock"))
            .whatever("unable to open grant state lock; initialize grant state first")?;
        let lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, error)| error)
            .whatever("another granted installation is in progress")?;
        let state: GrantState = serde_json::from_slice(
            &fs::read(directory.join("state.json"))
                .whatever("unable to read grant state; initialize it during provisioning")?,
        )
        .whatever("invalid grant replay state")?;
        if state.version != 1
            || state.namespace != policy.namespace
            || state.device != policy.device
        {
            bail!("grant state version or provisioned identity does not match");
        }
        let session = Self {
            config: policy.clone(),
            signed: signed.clone(),
            verified,
            content_hash,
            state,
            directory,
            _lock: lock,
        };
        session.check_replay()?;
        Ok(Some(session))
    }

    /// Authenticated bundle hash used by the streaming bundle reader.
    pub(crate) fn bundle_hash(&self) -> &HashDigest {
        &self.verified.grant().operation.bundle_hash
    }

    /// Durably reserve this transaction immediately before installation side effects.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(crate) fn reserve(&mut self) -> SystemResult<()> {
        self.revalidate()?;
        self.check_replay()?;
        self.set_transaction(false);
        self.save()?;
        info!(grant_id = %self.verified.grant().id, "installation grant reserved");
        Ok(())
    }

    /// Durably consume the grant before authorizing activation or finalizing staging.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(crate) fn consume(&mut self) -> SystemResult<()> {
        self.revalidate()?;
        self.set_transaction(true);
        self.save()?;
        info!(grant_id = %self.verified.grant().id, "installation grant consumed");
        Ok(())
    }

    fn revalidate(&self) -> SystemResult<()> {
        verify(&self.config, &self.signed)?;
        Ok(())
    }

    fn transaction(&self) -> Option<&GrantTransaction> {
        match self.verified.grant().operation.target {
            GrantTarget::Apps => self.state.apps.as_ref(),
            GrantTarget::System(_) => self.state.system.as_ref(),
        }
    }

    fn check_replay(&self) -> SystemResult<()> {
        let Some(previous) = self.transaction() else {
            return Ok(());
        };
        let grant = self.verified.grant();
        if grant.operation.sequence < previous.sequence {
            bail!("grant authorization sequence has been superseded");
        }
        if grant.operation.sequence == previous.sequence
            && (previous.consumed
                || previous.id != grant.id
                || previous.content_hash != self.content_hash)
        {
            bail!("grant authorization sequence was already used");
        }
        Ok(())
    }

    fn set_transaction(&mut self, consumed: bool) {
        let grant = self.verified.grant();
        let transaction = GrantTransaction {
            id: grant.id.clone(),
            sequence: grant.operation.sequence,
            content_hash: self.content_hash.clone(),
            consumed,
        };
        match grant.operation.target {
            GrantTarget::Apps => self.state.apps = Some(transaction),
            GrantTarget::System(_) => self.state.system = Some(transaction),
        }
    }

    fn save(&self) -> SystemResult<()> {
        let bytes = serde_json::to_vec(&self.state).whatever("unable to encode grant state")?;
        rugix_common::fsutils::atomic_write(&self.directory.join("state.json"), &bytes)
            .whatever("unable to persist grant replay state")
    }
}

/// Initialize replay state explicitly during provisioning; never replace existing state.
pub(crate) fn initialize(config: &GrantsConfig) -> SystemResult<()> {
    let directory = state_directory(config)?;
    fs::create_dir_all(&directory).whatever("unable to create grant state directory")?;
    let state = GrantState {
        version: 1,
        namespace: config.namespace.clone(),
        device: config.device.clone(),
        system: None,
        apps: None,
    };
    let bytes = serde_json::to_vec(&state).whatever("unable to encode initial grant state")?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(directory.join("state.json"))
        .whatever("unable to create grant state; existing state must not be reset")?;
    file.write_all(&bytes)
        .whatever("unable to write initial grant state")?;
    file.sync_all()
        .whatever("unable to synchronize initial grant state")?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .whatever("unable to synchronize grant state directory")?;
    Ok(())
}

/// Reject manual activation of stored content under an installation grant policy.
pub(crate) fn require_unconstrained_activation(config: &Config) -> SystemResult<()> {
    if config.grants.is_some() {
        bail!("manual activation requires a new installation with a valid grant");
    }
    Ok(())
}

/// Convert the exact caller-supplied options to the public signed contract.
fn grant_target(target: &InstallTarget) -> GrantTarget {
    match target {
        InstallTarget::Apps => GrantTarget::Apps,
        InstallTarget::System {
            reboot,
            keep_overlay,
            boot_group,
        } => GrantTarget::System(SystemInstallOptions {
            boot_group: boot_group.clone(),
            keep_overlay: *keep_overlay,
            reboot: reboot.map(|mode| match mode {
                SystemRebootMode::Yes => RebootMode::Yes,
                SystemRebootMode::No => RebootMode::No,
                SystemRebootMode::Set => RebootMode::Set,
                SystemRebootMode::Deferred => RebootMode::Deferred,
            }),
        }),
    }
}

/// Verify against provisioned identity and locally authorized grant issuers.
fn verify(config: &GrantsConfig, signed: &[u8]) -> SystemResult<VerifiedGrant<InstallOperation>> {
    if !config.trusted_system_clock {
        bail!("grant verification requires a trusted system clock");
    }
    let identity = DeviceIdentity {
        namespace: config.namespace.clone(),
        device_id: config.device.clone(),
        groups: config.groups.clone().unwrap_or_default(),
    };
    let context = VerificationContext {
        verifier: rugix_bundle::grants::VERIFIER,
        identity: &identity,
        now: SystemTime::now(),
    };
    for root in &config.roots {
        let result: SystemResult<VerifiedGrant<InstallOperation>> = fs::read(root)
            .whatever("unable to read grant root")
            .and_then(|certificate| GrantVerifier::new(&certificate).whatever("invalid grant root"))
            .and_then(|verifier| {
                verifier
                    .with_limits(
                        rugix_grants::DEFAULT_MAX_GRANT_SIZE,
                        Duration::from_secs(
                            config
                                .max_lifetime
                                .unwrap_or(rugix_grants::DEFAULT_MAX_LIFETIME.as_secs()),
                        ),
                    )
                    .verify(signed, &context)
                    .whatever("invalid installation grant")
            });
        match result {
            Ok(verified) => return Ok(verified),
            Err(error) => warn!(?error, "grant root did not accept installation grant"),
        }
    }
    bail!("no configured grant root accepted the installation grant")
}

/// Keep replay history outside resettable profiles, using the standard persistent
/// application directory on systems without Rugix state management.
fn state_directory(config: &GrantsConfig) -> SystemResult<PathBuf> {
    let path = if let Some(path) = &config.state_directory {
        PathBuf::from(path)
    } else if crate::init::state_dir()
        .try_exists()
        .whatever("unable to inspect Rugix state directory")?
    {
        Path::new(crate::system::paths::MOUNT_POINT_DATA).join(".rugix/grants")
    } else {
        PathBuf::from("/var/lib/rugix/grants")
    };
    if !path.is_absolute() {
        bail!("grant state directory must be an absolute path");
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;
    use rugix_grants::Audience;
    use rugix_grants::AudienceTarget;
    use rugix_grants::Grant;
    use rugix_grants::Operation;
    use rugix_pki::CmsSigner;

    struct Fixture {
        _directory: tempfile::TempDir,
        config: Config,
        signer: CmsSigner,
        grant: Grant<InstallOperation>,
        target: InstallTarget,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let ca_key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec![]).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let ca = params.self_signed(&ca_key).unwrap();
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec![]).unwrap();
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
            let root = directory.path().join("root.pem");
            fs::write(&root, ca.pem()).unwrap();
            let policy = GrantsConfig {
                roots: vec![root.to_str().unwrap().into()],
                mode: crate::config::grants::GrantPolicy::GrantOnly,
                namespace: "test".into(),
                device: "device-1".into(),
                groups: None,
                state_directory: Some(directory.path().join("state").to_str().unwrap().into()),
                trusted_system_clock: true,
                max_lifetime: None,
            };
            initialize(&policy).unwrap();
            let config = Config::default().with_grants(Some(policy));
            let target = InstallTarget::System {
                reboot: Some(SystemRebootMode::Set),
                keep_overlay: false,
                boot_group: Some("B".into()),
            };
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let grant = Grant {
                version: 1,
                id: "install-1".into(),
                verifier: rugix_bundle::grants::VERIFIER.into(),
                audience: Audience {
                    namespace: "test".into(),
                    target: AudienceTarget::Device("device-1".into()),
                },
                not_before: now - 1,
                expires_at: now + 300,
                operation_type: InstallOperation::TYPE.into(),
                operation: InstallOperation {
                    bundle_hash: HashAlgorithm::Sha256.hash(b"test bundle"),
                    sequence: 1,
                    target: grant_target(&target),
                },
            };
            Self {
                _directory: directory,
                config,
                signer: CmsSigner::new(cert.pem().as_bytes(), key.serialize_pem().as_bytes())
                    .unwrap(),
                grant,
                target,
            }
        }

        fn options(&self) -> BundleInstallOptions {
            BundleInstallOptions {
                grant: Some(rugix_grants::sign(&self.grant, &self.signer).unwrap()),
                bundle_hash: None,
                root_cert: None,
                insecure_skip_bundle_verification: false,
                insecure_allow_missing_block_index: false,
                skip_compatibility_check: false,
            }
        }

        fn begin(&self) -> SystemResult<Option<GrantSession>> {
            GrantSession::begin(&self.config, &self.options(), &self.target)
        }
    }

    /// A system grant binds the boot group, overlay policy, reboot mode, and operation
    /// kind.
    #[test]
    fn system_installation_options_are_authenticated() {
        let fixture = Fixture::new();
        assert!(fixture.begin().unwrap().is_some());
        for target in [
            InstallTarget::Apps,
            InstallTarget::System {
                reboot: Some(SystemRebootMode::Yes),
                keep_overlay: false,
                boot_group: Some("B".into()),
            },
            InstallTarget::System {
                reboot: Some(SystemRebootMode::Set),
                keep_overlay: true,
                boot_group: Some("B".into()),
            },
            InstallTarget::System {
                reboot: Some(SystemRebootMode::Set),
                keep_overlay: false,
                boot_group: Some("C".into()),
            },
            InstallTarget::System {
                reboot: None,
                keep_overlay: false,
                boot_group: Some("B".into()),
            },
        ] {
            assert!(GrantSession::begin(&fixture.config, &fixture.options(), &target).is_err());
        }
    }

    /// Sidex operation records and nested variants reject unknown or duplicate
    /// constraints even when their signature is valid.
    #[test]
    fn installation_contract_rejects_unknown_and_duplicate_constraints() {
        let fixture = Fixture::new();
        let content = String::from_utf8(rugix_grants::prepare(&fixture.grant).unwrap()).unwrap();
        for (field, replacement) in [
            ("\"sequence\":1", "\"sequence\":1,\"futureConstraint\":true"),
            (
                "\"keepOverlay\":false",
                "\"keepOverlay\":false,\"futureConstraint\":true",
            ),
            (
                "\"keepOverlay\":false",
                "\"keepOverlay\":false,\"keepOverlay\":true",
            ),
            (
                "\"target\":{\"System\":",
                "\"target\":{\"Apps\":null,\"System\":",
            ),
        ] {
            let altered = content.replace(field, replacement);
            assert_ne!(altered, content);
            let mut options = fixture.options();
            options.grant = Some(fixture.signer.sign(altered.as_bytes()).unwrap());
            assert!(
                GrantSession::begin(&fixture.config, &options, &fixture.target).is_err(),
                "accepted {replacement}"
            );
        }
    }

    /// Durable reservations survive a process restart but cannot change content or be
    /// reused after consumption.
    #[test]
    fn replay_state_distinguishes_retry_supersession_and_consumption() {
        let mut fixture = Fixture::new();
        let mut first = fixture.begin().unwrap().unwrap();
        first.reserve().unwrap();
        assert!(
            fixture.begin().is_err(),
            "parallel admission must hold the state lock"
        );
        drop(first);
        fixture.grant.id = "different-grant".into();
        assert!(fixture.begin().is_err());
        fixture.grant.id = "install-1".into();
        let mut retry = fixture.begin().unwrap().unwrap();
        retry.reserve().unwrap();
        retry.consume().unwrap();
        drop(retry);
        assert!(fixture.begin().is_err());
        fixture.grant.operation.sequence = 2;
        fixture.grant.id = "install-2".into();
        let mut next = fixture.begin().unwrap().unwrap();
        next.reserve().unwrap();
        next.consume().unwrap();
        drop(next);
        fixture.grant.operation.sequence = 1;
        assert!(fixture.begin().is_err());
    }

    /// Missing state, corrupt state, and a changed device identity cannot reset the
    /// sequence history.
    #[test]
    fn replay_state_fails_closed_and_initialization_never_resets_it() {
        let mut fixture = Fixture::new();
        let policy = fixture.config.grants.as_ref().unwrap();
        let state = state_directory(policy).unwrap().join("state.json");
        let saved = fs::read(&state).unwrap();
        assert!(initialize(policy).is_err());
        assert_eq!(fs::read(&state).unwrap(), saved);
        fs::remove_file(&state).unwrap();
        assert!(fixture.begin().is_err());
        fs::write(&state, b"invalid").unwrap();
        assert!(fixture.begin().is_err());
        fs::write(&state, saved).unwrap();
        fixture.config.grants.as_mut().unwrap().device = "other-device".into();
        fixture.grant.audience.target = AudienceTarget::Device("other-device".into());
        assert!(fixture.begin().is_err());
    }

    /// Grant policy cannot be downgraded with the legacy hash, certificate, or insecure
    /// options.
    #[test]
    fn required_grants_reject_legacy_overrides_and_untrusted_time() {
        let mut fixture = Fixture::new();
        let mut variants = Vec::new();
        let mut missing = fixture.options();
        missing.grant = None;
        variants.push(missing);
        let mut hash = fixture.options();
        hash.bundle_hash = Some(fixture.grant.operation.bundle_hash.clone());
        variants.push(hash);
        let mut root = fixture.options();
        root.root_cert = Some(vec![]);
        variants.push(root);
        let mut skip = fixture.options();
        skip.insecure_skip_bundle_verification = true;
        variants.push(skip);
        let mut index = fixture.options();
        index.insecure_allow_missing_block_index = true;
        variants.push(index);
        let mut compatibility = fixture.options();
        compatibility.skip_compatibility_check = true;
        variants.push(compatibility);
        for options in variants {
            assert!(GrantSession::begin(&fixture.config, &options, &fixture.target).is_err());
        }
        fixture.config.grants.as_mut().unwrap().trusted_system_clock = false;
        assert!(fixture.begin().is_err());
        assert!(require_unconstrained_activation(&fixture.config).is_err());
    }
}
