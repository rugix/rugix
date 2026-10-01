//! CLI for preparing, signing, and verifying detached installation grants.

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::SystemTime;

use clap::Args;
use clap::Subcommand;
use clap::ValueEnum;
use reportify::bail;
use reportify::ResultExt;
use rugix_bundle::grants::InstallOperation;
use rugix_bundle::grants::InstallTarget;
use rugix_bundle::grants::RebootMode;
use rugix_bundle::grants::SystemInstallOptions;
use rugix_bundle::BundleResult;
use rugix_grants::authority::AuthorityConstraints;
use rugix_grants::authority::AUTHORITY_CONSTRAINTS_OID;
use rugix_grants::authority::GRANT_AUTHORITY_EKU;
use rugix_grants::Audience;
use rugix_grants::AudienceTarget;
use rugix_grants::DeviceIdentity;
use rugix_grants::Grant;
use rugix_grants::GrantVerifier;
use rugix_grants::Operation;
use rugix_grants::VerificationContext;
use rugix_pki::CmsSignerBuilder;

#[derive(Debug, Subcommand)]
pub enum GrantsCommand {
    /// Prepare OpenSSL certificate extensions for a constrained grant authority.
    AuthorityExtensions {
        /// Sidex authority constraints in JSON format.
        policy: PathBuf,
        /// Output OpenSSL extension configuration file.
        output: PathBuf,
        /// Authorize signing subordinate certificates instead of signing grants directly.
        #[clap(long)]
        intermediate: bool,
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
    /// Verify a grant for a provisioned identity and print its authenticated content.
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
        /// Trusted local copy of the bundle to compare.
        #[clap(long)]
        bundle: PathBuf,
    },
}

/// Complete installation request and authorization window.
#[derive(Debug, Args)]
pub struct GrantArgs {
    /// Trusted local bundle to authorize.
    #[clap(long)]
    bundle: PathBuf,
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
    /// Inclusive validity start, in seconds since the Unix epoch.
    #[clap(long)]
    not_before: u64,
    /// Exclusive validity end, in seconds since the Unix epoch.
    #[clap(long)]
    expires_at: u64,
    /// Increasing authorization sequence within the system or apps scope.
    #[clap(long)]
    sequence: u64,
    /// Installation scope.
    #[clap(long, value_enum)]
    target: Target,
    /// System target boot group. Omit to authorize local inactive-group selection.
    #[clap(long)]
    boot_group: Option<String>,
    /// Authorize retaining the system target's overlay.
    #[clap(long)]
    keep_overlay: bool,
    /// Authorize explicit system reboot behavior. Omit to use the bundle default.
    #[clap(long, value_enum)]
    reboot: Option<Reboot>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Target {
    System,
    Apps,
}

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
            policy,
            output,
            intermediate,
        } => {
            let constraints = AuthorityConstraints::from_json(
                &fs::read(policy).whatever("unable to read authority policy")?,
            )
            .whatever("invalid authority policy")?;
            let depth = constraints.max_delegation_depth.unwrap_or(0);
            if !intermediate && depth != 0 {
                bail!("a grant signer cannot delegate authority");
            }
            let (basic, usage) = if intermediate {
                (format!("CA:TRUE,pathlen:{depth}"), "keyCertSign")
            } else {
                ("CA:FALSE".into(), "digitalSignature")
            };
            let der = constraints
                .to_extension_der()
                .whatever("unable to encode authority policy")?;
            let encoded = hex::encode(der);
            let extensions = format!(
                "basicConstraints=critical,{basic}\nkeyUsage=critical,{usage}\nextendedKeyUsage=critical,{GRANT_AUTHORITY_EKU}\n{AUTHORITY_CONSTRAINTS_OID}=DER:{encoded}\n"
            );
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
        } => {
            let identity = DeviceIdentity {
                namespace,
                device_id: device,
                groups: group,
            };
            let context = VerificationContext {
                verifier: rugix_bundle::grants::VERIFIER,
                identity: &identity,
                now: SystemTime::now(),
            };
            let mut signed = Vec::new();
            fs::File::open(grant)
                .whatever("unable to open grant")?
                .take(rugix_grants::DEFAULT_MAX_GRANT_SIZE as u64 + 1)
                .read_to_end(&mut signed)
                .whatever("unable to read grant")?;
            let verified =
                GrantVerifier::new(&fs::read(root_cert).whatever("unable to read grant root")?)
                    .whatever("unable to create grant verifier")?
                    .verify::<InstallOperation>(&signed, &context)
                    .whatever("unable to verify installation grant")?;
            let expected = rugix_bundle::bundle_hash(&bundle)?;
            if verified.grant().operation.bundle_hash != expected {
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

impl GrantArgs {
    fn build(self) -> BundleResult<Grant<InstallOperation>> {
        let audience = match (self.device, self.group) {
            (Some(device), None) => AudienceTarget::Device(device),
            (None, Some(group)) => AudienceTarget::Group(group),
            _ => bail!("specify exactly one device or group"),
        };
        let target = match self.target {
            Target::Apps => {
                if self.boot_group.is_some() || self.reboot.is_some() || self.keep_overlay {
                    bail!("system installation options cannot be used for app grants");
                }
                InstallTarget::Apps
            }
            Target::System => InstallTarget::System(SystemInstallOptions {
                boot_group: self.boot_group,
                keep_overlay: self.keep_overlay,
                reboot: self.reboot.map(|value| match value {
                    Reboot::Yes => RebootMode::Yes,
                    Reboot::No => RebootMode::No,
                    Reboot::Set => RebootMode::Set,
                    Reboot::Deferred => RebootMode::Deferred,
                }),
            }),
        };
        Ok(Grant {
            version: 1,
            id: self.id,
            verifier: rugix_bundle::grants::VERIFIER.into(),
            audience: Audience {
                namespace: self.namespace,
                target: audience,
            },
            not_before: self.not_before,
            expires_at: self.expires_at,
            operation_type: InstallOperation::TYPE.into(),
            operation: InstallOperation {
                bundle_hash: rugix_bundle::bundle_hash(&self.bundle)?,
                sequence: self.sequence,
                target,
            },
        })
    }
}
