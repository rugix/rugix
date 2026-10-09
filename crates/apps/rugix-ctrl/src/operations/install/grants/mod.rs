//! Installation grant policy, admission, and durable replay protection.
//!
//! A grant is authenticated before any installer work, admitted durably before
//! installation side effects, and consumed durably before activation. An admitted
//! grant can be retried while it remains valid. A consumed grant needs a
//! replacement even if activation was interrupted.
//!
//! Authority is the intersection of two independent limits: the permissions local
//! configuration delegates to an authority, and the scope its certificate chain
//! carries. Neither can widen the other.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;

use const_oid::ObjectIdentifier;
use reportify::bail;
use reportify::ResultExt;
use rugix_grants::GrantVerifier;
use rugix_grants::RecipientIdentity;
use rugix_grants::VerificationContext;
use rugix_grants::VerifiedGrant;
use rugix_install_grants::InstallOperation;
use rugix_install_grants::InstallRequest;
use rugix_install_grants::RebootMode;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;
use tracing::info;
use tracing::warn;

use self::state::GrantStore;
use super::BundleInstallOptions;
use super::InstallTarget;
use super::SystemRebootMode;
use crate::config::config::Config;
use crate::config::grants::GrantAuthorityConfig;
use crate::config::grants::GrantsConfig;
use crate::config::grants::InstallPermission;
use crate::system::SystemResult;

mod identity;
mod state;

/// An authenticated installation holding the device's grant state lock.
pub(crate) struct GrantSession {
    policy: GrantsConfig,
    signed: Vec<u8>,
    verified: VerifiedGrant<InstallOperation>,
    hash: String,
    store: GrantStore,
}

impl GrantSession {
    /// Authenticate the grant and bind its arguments before any installer work.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(crate) fn begin(
        config: &Config,
        options: &BundleInstallOptions,
        target: &InstallTarget,
    ) -> SystemResult<Option<Self>> {
        Self::begin_in(config, options, target, state_directory()?)
    }

    /// Authenticated bundle hash used by the streaming bundle reader.
    pub(crate) fn bundle_hash(&self) -> &HashDigest {
        &self.verified.grant().operation.bundle_hash
    }

    /// Durably admit this grant immediately before installation side effects.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(crate) fn admit(&mut self) -> SystemResult<()> {
        let now = self.revalidate()?;
        let grant = self.verified.grant();
        self.store
            .admit(&self.hash, &grant.id, grant.expires_at, now)?;
        info!(grant_id = %grant.id, "installation grant admitted");
        Ok(())
    }

    /// Durably consume the grant before authorizing activation or boot selection.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(crate) fn consume(&mut self) -> SystemResult<()> {
        let now = self.revalidate()?;
        self.store.consume(&self.hash, now)?;
        info!(grant_id = %self.verified.grant().id, "installation grant consumed");
        Ok(())
    }

    /// Apply grant policy using the selected persistent state directory.
    fn begin_in(
        config: &Config,
        options: &BundleInstallOptions,
        target: &InstallTarget,
        directory: PathBuf,
    ) -> SystemResult<Option<Self>> {
        require_exclusive_grant(options)?;
        let Some(policy) = &config.grants else {
            if options.grant.is_some() {
                bail!("installation grants are not configured");
            }
            return Ok(None);
        };
        if options.insecure_skip_grant_verification {
            warn!("grant policy skipped by explicit request; this installation is unauthorized");
            return Ok(None);
        }
        let Some(signed) = &options.grant else {
            bail!(
                "a detached installation grant is required; pass \
                 --insecure-skip-grant-verification to install without one"
            );
        };
        let identity = identity::load(policy)?;
        let store = GrantStore::open(directory, &identity)?;
        let verified = verify(
            policy,
            signed,
            &identity,
            store.effective_now(SystemTime::now()),
        )?;
        if !verified
            .grant()
            .operation
            .target
            .permits(&install_request(target))
        {
            bail!("this grant does not permit the requested installation options");
        }
        let hash = content_hash(&verified);
        store.check_admissible(&hash)?;
        Ok(Some(Self {
            policy: policy.clone(),
            signed: signed.clone(),
            verified,
            hash,
            store,
        }))
    }

    /// Recheck identity, membership, grant, and certificate validity.
    fn revalidate(&self) -> SystemResult<SystemTime> {
        let identity = identity::load(&self.policy)?;
        self.store.check_identity(&identity)?;
        let now = self.store.effective_now(SystemTime::now());
        verify(&self.policy, &self.signed, &identity, now)?;
        Ok(now)
    }
}

/// Reject options that would decide an installation a grant already decides.
///
/// Destructured so that a new installation option has to be classified here before
/// it can be combined with a grant.
fn require_exclusive_grant(options: &BundleInstallOptions) -> SystemResult<()> {
    let BundleInstallOptions {
        grant,
        insecure_skip_grant_verification,
        bundle_hash,
        root_cert,
        insecure_skip_bundle_verification,
        insecure_allow_missing_block_index,
        skip_compatibility_check,
    } = options;
    if grant.is_none() {
        return Ok(());
    }
    if *insecure_skip_grant_verification
        || bundle_hash.is_some()
        || root_cert.is_some()
        || *insecure_skip_bundle_verification
        || *insecure_allow_missing_block_index
        || *skip_compatibility_check
    {
        bail!(
            "a grant decides this installation, so it cannot be combined with bundle \
             verification, block index, or compatibility overrides"
        );
    }
    Ok(())
}

/// Convert the exact caller-supplied options into the request the grant must permit.
fn install_request(target: &InstallTarget) -> InstallRequest {
    match target {
        InstallTarget::Apps => InstallRequest::Apps,
        InstallTarget::System {
            reboot,
            keep_overlay,
            boot_group,
        } => InstallRequest::System {
            boot_group: boot_group.clone(),
            keep_overlay: *keep_overlay,
            reboot: reboot.map(|mode| match mode {
                SystemRebootMode::Yes => RebootMode::Yes,
                SystemRebootMode::No => RebootMode::No,
                SystemRebootMode::Set => RebootMode::Set,
                SystemRebootMode::Deferred => RebootMode::Deferred,
            }),
        },
    }
}

/// Identify a grant by its authenticated content, independent of CMS packaging.
///
/// Two envelopes carrying the same grant with different certificates hash alike,
/// and an envelope that differs in any authenticated byte does not.
fn content_hash(verified: &VerifiedGrant<InstallOperation>) -> String {
    HashAlgorithm::Sha256
        .hash::<Vec<u8>>(verified.content())
        .to_string()
}

/// Verify against every locally authorized issuer and its delegated permissions.
fn verify(
    policy: &GrantsConfig,
    signed: &[u8],
    identity: &RecipientIdentity,
    now: SystemTime,
) -> SystemResult<VerifiedGrant<InstallOperation>> {
    let context = VerificationContext {
        service: rugix_install_grants::SERVICE,
        identity,
        now,
    };
    let mut rejections = Vec::new();
    for authority in &policy.authorities {
        let max_lifetime = Duration::from_secs(
            authority
                .max_lifetime
                .unwrap_or(rugix_grants::DEFAULT_MAX_LIFETIME.as_secs()),
        );
        let verified: SystemResult<VerifiedGrant<InstallOperation>> = fs::read(&authority.root)
            .whatever("unable to read grant authority root")
            .and_then(|certificate| {
                GrantVerifier::new(&certificate, permissions(authority))
                    .whatever("invalid grant authority root")
            })
            .and_then(|verifier| {
                verifier
                    .with_max_lifetime(max_lifetime)
                    .verify(signed, &context)
                    .whatever("grant rejected")
            });
        match verified {
            Ok(verified) => return Ok(verified),
            Err(error) => rejections.push(format!("{}: {error}", authority.root)),
        }
    }
    bail!(
        "no configured grant authority accepted the installation grant ({})",
        rejections.join("; ")
    )
}

/// Operation purposes local configuration delegates to one authority.
fn permissions(authority: &GrantAuthorityConfig) -> Vec<ObjectIdentifier> {
    authority
        .permissions
        .iter()
        .map(|permission| match permission {
            InstallPermission::Apps => rugix_install_grants::PERMISSION_APPS,
            InstallPermission::System => rugix_install_grants::PERMISSION_SYSTEM,
        })
        .collect()
}

/// Keep replay history outside resettable profiles, using the standard persistent
/// application directory on systems without Rugix state management.
fn state_directory() -> SystemResult<PathBuf> {
    if crate::init::state_dir()
        .try_exists()
        .whatever("unable to inspect Rugix state directory")?
    {
        Ok(Path::new(crate::system::paths::MOUNT_POINT_DATA).join(".rugix/grants"))
    } else {
        Ok(PathBuf::from("/var/lib/rugix/grants"))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::CustomExtension;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;
    use rugix_grants::authority::purposes_extension_der;
    use rugix_grants::authority::AuthorityScope;
    use rugix_grants::authority::ScopeTarget;
    use rugix_grants::authority::AUTHORITY_SCOPE_OID;
    use rugix_grants::authority::EXTENDED_KEY_USAGE_OID;
    use rugix_grants::Audience;
    use rugix_grants::AudienceTarget;
    use rugix_grants::Grant;
    use rugix_grants::Operation;
    use rugix_install_grants::BootGroupConstraint;
    use rugix_install_grants::RebootConstraint;
    use rugix_install_grants::SystemInstallConstraints;
    use rugix_pki::CmsSigner;

    use super::*;

    struct Fixture {
        directory: tempfile::TempDir,
        config: Config,
        signer: CmsSigner,
        grant: Grant<InstallOperation>,
        target: InstallTarget,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let (root, signer) = authority();
            let root_path = directory.path().join("root.pem");
            fs::write(&root_path, root).unwrap();
            let helper = directory.path().join("identity");
            fs::write(
                &helper,
                "#!/bin/sh\nprintf '%s\\n' '{\"device\":\"device-1\"}'\n",
            )
            .unwrap();
            fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
            let policy = GrantsConfig {
                authorities: vec![GrantAuthorityConfig {
                    root: root_path.to_str().unwrap().into(),
                    permissions: vec![InstallPermission::Apps, InstallPermission::System],
                    max_lifetime: None,
                }],
                namespace: "test".into(),
                identity_helper: helper.to_str().unwrap().into(),
                mode: None,
            };
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
                service: rugix_install_grants::SERVICE.into(),
                audience: Audience {
                    namespace: "test".into(),
                    target: AudienceTarget::Recipient("device-1".into()),
                },
                not_before: now - 1,
                expires_at: now + 300,
                operation_type: InstallOperation::TYPE.into(),
                operation: InstallOperation {
                    bundle_hash: HashAlgorithm::Sha256.hash(b"test bundle"),
                    target: rugix_install_grants::InstallTarget::System(SystemInstallConstraints {
                        boot_group: Some(BootGroupConstraint::Named("B".into())),
                        keep_overlay: Some(false),
                        reboot: Some(RebootConstraint::Mode(RebootMode::Set)),
                    }),
                },
            };
            Self {
                directory,
                config: Config::default().with_grants(Some(policy)),
                signer,
                grant,
                target,
            }
        }

        fn options(&self) -> BundleInstallOptions {
            BundleInstallOptions {
                grant: Some(rugix_grants::sign(&self.grant, &self.signer).unwrap()),
                insecure_skip_grant_verification: false,
                bundle_hash: None,
                root_cert: None,
                insecure_skip_bundle_verification: false,
                insecure_allow_missing_block_index: false,
                skip_compatibility_check: false,
            }
        }

        fn begin(&self) -> SystemResult<Option<GrantSession>> {
            self.begin_with(&self.options(), &self.target)
        }

        fn begin_with(
            &self,
            options: &BundleInstallOptions,
            target: &InstallTarget,
        ) -> SystemResult<Option<GrantSession>> {
            GrantSession::begin_in(
                &self.config,
                options,
                target,
                self.directory.path().join("state"),
            )
        }
    }

    /// Issue a trust root and a signer prepared for both installation purposes.
    fn authority() -> (String, CmsSigner) {
        let ca_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = params.self_signed(&ca_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let arcs = |oid: ObjectIdentifier| oid.arcs().map(u64::from).collect::<Vec<_>>();
        let mut purposes = CustomExtension::from_oid_content(
            &arcs(EXTENDED_KEY_USAGE_OID),
            purposes_extension_der(&[
                rugix_install_grants::PERMISSION_APPS,
                rugix_install_grants::PERMISSION_SYSTEM,
            ])
            .unwrap(),
        );
        purposes.set_criticality(true);
        params.custom_extensions.push(purposes);
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &arcs(AUTHORITY_SCOPE_OID),
                AuthorityScope::new("test", vec![ScopeTarget::any()])
                    .to_extension_der()
                    .unwrap(),
            ));
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        (
            ca.pem(),
            CmsSigner::new(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap(),
        )
    }

    /// A grant admits exactly the installation options it permits.
    #[test]
    fn requested_options_must_be_permitted() {
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
            assert!(fixture.begin_with(&fixture.options(), &target).is_err());
        }
    }

    /// A permissive grant admits any option the device chooses locally.
    #[test]
    fn unconstrained_options_admit_any_request() {
        let mut fixture = Fixture::new();
        fixture.grant.operation.target =
            rugix_install_grants::InstallTarget::System(SystemInstallConstraints {
                boot_group: None,
                keep_overlay: None,
                reboot: None,
            });
        for target in [
            InstallTarget::System {
                reboot: Some(SystemRebootMode::Deferred),
                keep_overlay: true,
                boot_group: Some("C".into()),
            },
            InstallTarget::System {
                reboot: None,
                keep_overlay: false,
                boot_group: None,
            },
        ] {
            assert!(fixture.begin_with(&fixture.options(), &target).is_ok());
        }
        assert!(fixture
            .begin_with(&fixture.options(), &InstallTarget::Apps)
            .is_err());
    }

    /// Local policy withholds a permission the certificate would otherwise grant.
    #[test]
    fn local_policy_can_withhold_a_permission() {
        let mut fixture = Fixture::new();
        fixture.config.grants.as_mut().unwrap().authorities[0].permissions =
            vec![InstallPermission::Apps];
        assert!(fixture.begin().is_err());
    }

    /// Sidex operation records and nested variants reject unknown or duplicate
    /// constraints even when their signature is valid.
    ///
    /// This is what keeps a constraint added by a future issuer from being ignored
    /// by an older device, and it holds only while payload-carrying variants are
    /// externally tagged. Adjacent and internal tagging buffer the payload, which
    /// hides unknown fields inside it from Serde's tracking adapter.
    #[test]
    fn installation_contract_rejects_unknown_and_duplicate_constraints() {
        let fixture = Fixture::new();
        let content = String::from_utf8(rugix_grants::prepare(&fixture.grant).unwrap()).unwrap();
        for (field, replacement) in [
            (
                "\"keepOverlay\":false",
                "\"keepOverlay\":false,\"futureConstraint\":true",
            ),
            (
                "\"keepOverlay\":false",
                "\"keepOverlay\":false,\"keepOverlay\":true",
            ),
            (
                "\"target\":{\"system\":",
                "\"target\":{\"apps\":null,\"system\":",
            ),
            ("\"named\":\"B\"", "\"named\":\"B\",\"local\":null"),
            (
                "\"reboot\":{\"mode\":\"set\"}",
                "\"reboot\":{\"mode\":\"set\",\"x\":1}",
            ),
            (
                "\"target\":{\"recipient\":\"device-1\"}",
                "\"target\":{\"recipient\":\"device-1\",\"group\":\"canary\"}",
            ),
        ] {
            let altered = content.replace(field, replacement);
            assert_ne!(altered, content);
            let mut options = fixture.options();
            options.grant = Some(fixture.signer.sign(altered.as_bytes()).unwrap());
            assert!(
                fixture.begin_with(&options, &fixture.target).is_err(),
                "accepted {replacement}"
            );
        }
    }

    /// An admitted grant can be retried, and a consumed one is never admitted again.
    /// Independent grants need no coordinated ordering.
    #[test]
    fn admitted_grants_retry_and_consumed_grants_are_final() {
        let mut fixture = Fixture::new();
        let mut first = fixture.begin().unwrap().unwrap();
        first.admit().unwrap();
        assert!(
            fixture.begin().is_err(),
            "concurrent admission must hold the state lock"
        );
        drop(first);
        let mut retry = fixture.begin().unwrap().unwrap();
        retry.admit().unwrap();
        retry.consume().unwrap();
        drop(retry);
        assert!(fixture.begin().is_err());
        for id in ["install-2", "install-3"] {
            fixture.grant.id = id.into();
            let mut next = fixture.begin().unwrap().unwrap();
            next.admit().unwrap();
            next.consume().unwrap();
            drop(next);
        }
        fixture.grant.id = "install-2".into();
        assert!(fixture.begin().is_err());
    }

    /// Corrupt state and a changed device identity fail closed, while a device that
    /// has no state yet gets one on first use.
    #[test]
    fn replay_state_is_created_lazily_and_otherwise_fails_closed() {
        let mut fixture = Fixture::new();
        let state = fixture.directory.path().join("state/state.json");
        assert!(
            !state.exists(),
            "state exists before the first installation"
        );
        let mut session = fixture.begin().unwrap().unwrap();
        session.admit().unwrap();
        session.consume().unwrap();
        drop(session);
        let saved = fs::read(&state).unwrap();
        fs::write(&state, b"invalid").unwrap();
        assert!(fixture.begin().is_err());
        fs::write(&state, saved).unwrap();
        assert!(fixture.begin().is_err(), "the grant was consumed");
        fs::write(
            &fixture.config.grants.as_ref().unwrap().identity_helper,
            "#!/bin/sh\nprintf '%s\\n' '{\"device\":\"other-device\"}'\n",
        )
        .unwrap();
        fixture.grant.audience.target = AudienceTarget::Recipient("other-device".into());
        assert!(fixture.begin().is_err());
    }

    /// A failing or stalling identity helper rejects the operation.
    #[test]
    fn identity_helper_failures_reject_the_operation() {
        let fixture = Fixture::new();
        let helper = &fixture.config.grants.as_ref().unwrap().identity_helper;
        for script in [
            "#!/bin/sh\nexit 1\n",
            "#!/bin/sh\nprintf 'not json'\n",
            "#!/bin/sh\nprintf '{\"device\":\"\"}'\n",
            "#!/bin/sh\nprintf '{\"device\":\"device-1\",\"groups\":[\"\"]}'\n",
        ] {
            fs::write(helper, script).unwrap();
            assert!(fixture.begin().is_err(), "accepted helper: {script}");
        }
    }

    /// A grant decides its installation, so it cannot be combined with options
    /// that would decide verification, delivery, or compatibility locally.
    #[test]
    fn grants_cannot_be_combined_with_overrides() {
        let fixture = Fixture::new();
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
        let mut skip = fixture.options();
        skip.insecure_skip_grant_verification = true;
        variants.push(skip);
        for options in variants {
            assert!(fixture.begin_with(&options, &fixture.target).is_err());
        }
    }

    /// Grant policy can be skipped explicitly, which installs nothing on its own
    /// and leaves bundle verification to the ordinary rules.
    #[test]
    fn grant_policy_can_be_skipped_explicitly() {
        let fixture = Fixture::new();
        let mut options = fixture.options();
        options.grant = None;
        assert!(fixture.begin_with(&options, &fixture.target).is_err());
        options.insecure_skip_grant_verification = true;
        assert!(
            fixture
                .begin_with(&options, &fixture.target)
                .unwrap()
                .is_none(),
            "skipping policy must not open a grant session"
        );
    }
}
