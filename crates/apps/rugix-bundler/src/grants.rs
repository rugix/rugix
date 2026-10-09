//! CLI for preparing, signing, and verifying detached installation grants.

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

use clap::Args;
use clap::Subcommand;
use clap::ValueEnum;
use const_oid::ObjectIdentifier;
use jiff::SignedDuration;
use jiff::Timestamp;
use reportify::bail;
use reportify::ResultExt;
use rugix_bundle::BundleResult;
use rugix_grants::authority::AuthorityScope;
use rugix_grants::authority::ScopeTarget;
use rugix_grants::authority::AUTHORITY_SCOPE_OID;
use rugix_grants::Audience;
use rugix_grants::AudienceTarget;
use rugix_grants::Grant;
use rugix_grants::GrantVerifier;
use rugix_grants::Operation;
use rugix_grants::RecipientIdentity;
use rugix_grants::VerificationContext;
use rugix_install_grants::BootGroupConstraint;
use rugix_install_grants::InstallOperation;
use rugix_install_grants::InstallTarget;
use rugix_install_grants::RebootConstraint;
use rugix_install_grants::SystemInstallConstraints;
use rugix_pki::CmsSignerBuilder;
use si_crypto_hashes::HashDigest;

#[derive(Debug, Subcommand)]
pub enum GrantsCommand {
    /// Prepare OpenSSL certificate extensions for a grant authority.
    AuthorityExtensions {
        #[clap(flatten)]
        scope: ScopeArgs,
        /// Issue a certificate authority that may delegate this many further
        /// authority levels. Omit to prepare a grant-signing certificate.
        #[clap(long)]
        intermediate: Option<u8>,
        /// Output OpenSSL extension configuration file.
        output: PathBuf,
    },
    /// Create and sign an installation grant.
    Sign {
        #[clap(flatten)]
        grant: GrantArgs,
        /// Signer certificate in PEM format.
        #[clap(long)]
        cert: PathBuf,
        /// Signer private key in PEM format.
        #[clap(long)]
        key: PathBuf,
        /// Intermediate certificates in PEM format.
        #[clap(long = "intermediate-cert")]
        intermediates: Vec<PathBuf>,
        /// Output CMS file.
        output: PathBuf,
    },
    /// Prepare exact grant bytes for an external CMS signer.
    Prepare {
        #[clap(flatten)]
        grant: GrantArgs,
        /// Output unsigned content file.
        output: PathBuf,
    },
    /// Verify a grant for a device identity and print its authenticated content.
    ///
    /// Prints the authenticated grant as JSON on standard output. Verification
    /// applies no device policy and inspects no replay state, so a grant this
    /// command accepts can still be refused by a device.
    Verify {
        /// CMS grant file.
        grant: PathBuf,
        /// Locally trusted root certificate in PEM format.
        #[clap(long)]
        root_cert: PathBuf,
        /// Expected identity namespace.
        #[clap(long)]
        namespace: String,
        /// Expected device identity.
        #[clap(long)]
        device: String,
        /// Independently established group membership; repeat as needed.
        #[clap(long)]
        group: Vec<String>,
        #[clap(flatten)]
        bundle: BundleArgs,
        /// Time to verify at, as an RFC 3339 timestamp. Defaults to the current time.
        ///
        /// The grant and its certificates must be valid then, so inspecting a grant
        /// outside its window needs a time inside it.
        #[clap(long)]
        at: Option<Timestamp>,
    },
}

/// Bundle a grant applies to, either locally available or identified by its hash.
#[derive(Debug, Args)]
pub struct BundleArgs {
    /// Trusted local bundle.
    #[clap(
        long,
        conflicts_with = "bundle_hash",
        required_unless_present = "bundle_hash"
    )]
    bundle: Option<PathBuf>,
    /// Hash of the bundle header, from a trusted source.
    ///
    /// Issuing against a hash needs no local copy of the bundle.
    #[clap(long)]
    bundle_hash: Option<HashDigest>,
}

impl BundleArgs {
    /// Resolve the authenticated bundle hash.
    fn hash(self) -> BundleResult<HashDigest> {
        match (self.bundle, self.bundle_hash) {
            (Some(path), None) => rugix_bundle::bundle_hash(&path),
            (None, Some(hash)) => Ok(hash),
            _ => bail!("specify exactly one of --bundle or --bundle-hash"),
        }
    }
}

/// Namespace, audiences, and operations delegated to an authority certificate.
#[derive(Debug, Args)]
pub struct ScopeArgs {
    /// Identity namespace provisioned on the devices.
    #[clap(long)]
    namespace: String,
    /// Permit any audience within the namespace.
    #[clap(long, conflicts_with_all = ["devices", "groups"])]
    any_audience: bool,
    /// Permit exactly this device; repeat as needed.
    #[clap(long = "device")]
    devices: Vec<String>,
    /// Permit exactly this group; repeat as needed.
    #[clap(long = "group")]
    groups: Vec<String>,
    /// Operation this certificate may authorize; repeat as needed.
    #[clap(long = "permission", required = true, value_enum)]
    permissions: Vec<Permission>,
}

/// Installation request and authorization window of one grant.
#[derive(Debug, Args)]
pub struct GrantArgs {
    #[clap(flatten)]
    bundle: BundleArgs,
    /// Grant identifier, unique within the issuing authority.
    #[clap(long)]
    id: String,
    /// Identity namespace provisioned on the device.
    #[clap(long)]
    namespace: String,
    /// Exact device identity.
    #[clap(long, required_unless_present = "group", conflicts_with = "group")]
    device: Option<String>,
    /// Exact provisioned group identity.
    #[clap(long)]
    group: Option<String>,
    /// Inclusive validity start as an RFC 3339 timestamp. Defaults to the current time.
    #[clap(long)]
    not_before: Option<Timestamp>,
    /// Exclusive validity end as an RFC 3339 timestamp or duration from now (e.g. 1h).
    #[clap(long, allow_hyphen_values = true)]
    expires_at: GrantExpiry,
    /// Installation scope.
    #[clap(long, value_enum)]
    target: Target,
    /// Permit only this boot group. Omit to permit any boot group.
    #[clap(long, conflicts_with = "local_boot_group")]
    boot_group: Option<String>,
    /// Permit only local selection of an inactive boot group.
    #[clap(long)]
    local_boot_group: bool,
    /// Permit only this overlay handling. Omit to permit either.
    #[clap(long)]
    keep_overlay: Option<bool>,
    /// Permit only this reboot behavior. Omit to permit any behavior.
    #[clap(long, value_enum, conflicts_with = "bundle_default_reboot")]
    reboot: Option<Reboot>,
    /// Permit only the bundle's default reboot behavior.
    #[clap(long)]
    bundle_default_reboot: bool,
}

/// Installation scope of a grant.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Target {
    System,
    Apps,
}

/// Operation an authority certificate may authorize.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Permission {
    Apps,
    System,
}

/// Post-installation system behavior.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Reboot {
    Yes,
    No,
    Set,
    Deferred,
}

pub fn run(command: GrantsCommand) -> BundleResult<()> {
    match command {
        GrantsCommand::AuthorityExtensions {
            scope,
            intermediate,
            output,
        } => {
            let extensions = scope.extensions(intermediate)?;
            fs::write(output, extensions).whatever("unable to write authority extensions")?;
        }
        GrantsCommand::Sign {
            grant,
            cert,
            key,
            intermediates,
            output,
        } => {
            let mut builder = CmsSignerBuilder::new(
                &fs::read(cert).whatever("unable to read signer certificate")?,
                &fs::read(key).whatever("unable to read signing key")?,
            )
            .whatever("unable to create grant signer")?;
            for intermediate in intermediates {
                builder = builder
                    .with_intermediate_cert(
                        &fs::read(intermediate)
                            .whatever("unable to read intermediate certificate")?,
                    )
                    .whatever("unable to add intermediate certificate")?;
            }
            let signer = builder.build().whatever("unable to build grant signer")?;
            let signed = rugix_grants::sign(&grant.build()?, &signer)
                .whatever("unable to sign installation grant")?;
            fs::write(output, signed).whatever("unable to write installation grant")?;
        }
        GrantsCommand::Prepare { grant, output } => {
            let bytes = rugix_grants::prepare(&grant.build()?)
                .whatever("unable to prepare installation grant")?;
            fs::write(output, bytes).whatever("unable to write grant content")?;
        }
        GrantsCommand::Verify {
            grant,
            root_cert,
            namespace,
            device,
            group,
            bundle,
            at,
        } => {
            let identity = RecipientIdentity {
                namespace,
                recipient_id: device,
                groups: group,
            };
            let now = match at {
                Some(timestamp) => {
                    SystemTime::UNIX_EPOCH
                        + Duration::from_secs(
                            u64::try_from(timestamp.as_second())
                                .whatever("verification time precedes the Unix epoch")?,
                        )
                }
                None => SystemTime::now(),
            };
            let context = VerificationContext {
                service: rugix_install_grants::SERVICE,
                identity: &identity,
                now,
            };
            let mut signed = Vec::new();
            fs::File::open(grant)
                .whatever("unable to open grant")?
                .take(rugix_grants::DEFAULT_MAX_GRANT_SIZE as u64 + 1)
                .read_to_end(&mut signed)
                .whatever("unable to read grant")?;
            // Inspection applies no device policy, so both permissions are accepted.
            let verifier = GrantVerifier::new(
                &fs::read(root_cert).whatever("unable to read grant root")?,
                vec![
                    rugix_install_grants::PERMISSION_APPS,
                    rugix_install_grants::PERMISSION_SYSTEM,
                ],
            )
            .whatever("unable to create grant verifier")?;
            let verified = verifier
                .verify::<InstallOperation>(&signed, &context)
                .whatever("unable to verify installation grant")?;
            if verified.grant().operation.bundle_hash != bundle.hash()? {
                bail!("grant bundle hash does not match");
            }
            println!(
                "{}",
                serde_json::to_string_pretty(verified.grant())
                    .whatever("unable to format verified grant")?
            );
        }
    }
    Ok(())
}

impl ScopeArgs {
    /// Render the OpenSSL extensions an authority certificate must carry.
    fn extensions(self, intermediate: Option<u8>) -> BundleResult<String> {
        let targets = if self.any_audience {
            vec![ScopeTarget::any()]
        } else {
            self.devices
                .into_iter()
                .map(ScopeTarget::Recipient)
                .chain(self.groups.into_iter().map(ScopeTarget::Group))
                .collect()
        };
        if targets.is_empty() {
            bail!("specify --any-audience, --device, or --group");
        }
        let scope = AuthorityScope::new(self.namespace, targets);
        let der = scope
            .to_extension_der()
            .whatever("unable to encode authority scope")?;
        let permissions = self
            .permissions
            .into_iter()
            .map(permission_oid)
            .collect::<Vec<_>>();
        let purposes = rugix_grants::authority::purposes(&permissions)
            .iter()
            .map(ObjectIdentifier::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let (basic, usage) = match intermediate {
            Some(depth) => (format!("CA:TRUE,pathlen:{depth}"), "keyCertSign"),
            None => ("CA:FALSE".to_owned(), "digitalSignature"),
        };
        Ok(format!(
            "basicConstraints=critical,{basic}\n\
             keyUsage=critical,{usage}\n\
             extendedKeyUsage=critical,{purposes}\n\
             {AUTHORITY_SCOPE_OID}=DER:{}\n",
            hex::encode(der)
        ))
    }
}

impl GrantArgs {
    fn build(self) -> BundleResult<Grant<InstallOperation>> {
        let audience = match (self.device, self.group) {
            (Some(device), None) => AudienceTarget::Recipient(device),
            (None, Some(group)) => AudienceTarget::Group(group),
            _ => bail!("specify exactly one device or group"),
        };
        let system_options = self.boot_group.is_some()
            || self.local_boot_group
            || self.keep_overlay.is_some()
            || self.reboot.is_some()
            || self.bundle_default_reboot;
        let target = match self.target {
            Target::Apps => {
                if system_options {
                    bail!("system installation options cannot be used for app grants");
                }
                InstallTarget::Apps
            }
            Target::System => InstallTarget::System(SystemInstallConstraints {
                boot_group: match (self.boot_group, self.local_boot_group) {
                    (Some(name), false) => Some(BootGroupConstraint::Named(name)),
                    (None, true) => Some(BootGroupConstraint::Local),
                    _ => None,
                },
                keep_overlay: self.keep_overlay,
                reboot: match (self.reboot, self.bundle_default_reboot) {
                    (Some(mode), false) => Some(RebootConstraint::Mode(reboot_mode(mode))),
                    (None, true) => Some(RebootConstraint::BundleDefault),
                    _ => None,
                },
            }),
        };
        let now = Timestamp::now();
        let not_before = self.not_before.unwrap_or(now);
        let expires_at = match self.expires_at {
            GrantExpiry::At(timestamp) => timestamp,
            GrantExpiry::After(duration) => now
                .checked_add(duration)
                .whatever("grant expiry is outside the supported timestamp range")?,
        };
        Ok(Grant {
            version: 1,
            id: self.id,
            service: rugix_install_grants::SERVICE.into(),
            audience: Audience {
                namespace: self.namespace,
                target: audience,
            },
            not_before: u64::try_from(not_before.as_second())
                .whatever("grant validity cannot start before the Unix epoch")?,
            expires_at: u64::try_from(expires_at.as_second())
                .whatever("grant validity cannot end before the Unix epoch")?,
            operation_type: InstallOperation::TYPE.into(),
            operation: InstallOperation {
                bundle_hash: self.bundle.hash()?,
                target,
            },
        })
    }
}

/// Key purpose authorizing one installation operation.
fn permission_oid(permission: Permission) -> ObjectIdentifier {
    match permission {
        Permission::Apps => rugix_install_grants::PERMISSION_APPS,
        Permission::System => rugix_install_grants::PERMISSION_SYSTEM,
    }
}

fn reboot_mode(reboot: Reboot) -> rugix_install_grants::RebootMode {
    match reboot {
        Reboot::Yes => rugix_install_grants::RebootMode::Yes,
        Reboot::No => rugix_install_grants::RebootMode::No,
        Reboot::Set => rugix_install_grants::RebootMode::Set,
        Reboot::Deferred => rugix_install_grants::RebootMode::Deferred,
    }
}

/// Absolute expiry or an elapsed-time offset from the issuing clock.
#[derive(Debug, Clone, Copy)]
enum GrantExpiry {
    At(Timestamp),
    After(SignedDuration),
}

impl FromStr for GrantExpiry {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(timestamp) = value.parse() {
            return Ok(Self::At(timestamp));
        }
        value.parse().map(Self::After).map_err(|error| {
            format!("expected an RFC 3339 timestamp or duration such as 1h: {error}")
        })
    }
}
