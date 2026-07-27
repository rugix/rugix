//! Bundle installation operation and implementation.

use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::Path;

use reportify::bail;
use reportify::whatever;
use reportify::ResultExt;
use rugix_bundle::format;
use rugix_bundle::format::decode::decode_slice;
use rugix_bundle::reader::BundleReader;
use rugix_bundle::reader::PayloadTarget;
use rugix_bundle::source::BundleSource;
use rugix_bundle::source::ReaderSource;
use rugix_bundle::source::SkipRead;
use rugix_bundle::source::SkipSeek;
use rugix_common::pipe::PipeWriter;
use serde::Deserialize;
use serde::Serialize;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;
use si_crypto_hashes::Hasher;
use tracing::info;
use tracing::warn;

use super::local::ExecutionContext;
use super::EventSink;
use super::Operation;
use crate::apps::manager::AppManager;
use crate::config::config::Config;
use crate::config::output::ComponentsCheckOutput;
use crate::http_source::DownloadStats;
use crate::http_source::HttpSource;
use crate::http_source::RetryConfig;
use crate::payload_db;
use crate::system::boot_groups::BootGroup;
use crate::system::boot_groups::BootGroupIdx;
use crate::system::System;
use crate::system::SystemResult;
use crate::utils::lock_update;
use crate::utils::set_deferred_reboot_target;

/// Install a system or application bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallBundle {
    pub(crate) source: InstallSource,
    pub(crate) target: InstallTarget,
    pub(crate) options: BundleInstallOptions,
}

impl Operation for InstallBundle {
    type Input = BundleInput;
    type Event = BundleInstallEvent;
    type Output = ();

    fn execute(
        self,
        context: &ExecutionContext<'_>,
        input: Self::Input,
        events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        let Self {
            source,
            target,
            options,
        } = self;
        match target {
            InstallTarget::Apps => {
                events.emit(BundleInstallEvent::Started);
                context.with_app_manager(|manager| {
                    install_bundle(
                        context.config(),
                        source,
                        input,
                        options,
                        ResolvedInstallTarget::Apps(manager),
                        events,
                    )
                })
            }
            InstallTarget::System {
                reboot,
                keep_overlay,
                boot_group,
            } => {
                let _update_lock = lock_update()?;
                events.emit(BundleInstallEvent::Started);
                let system = System::initialize()?;
                if system.needs_commit()? {
                    bail!("system needs to be committed before installing an update");
                }
                let boot_group = match boot_group.as_deref() {
                    Some(group_name) => {
                        let Some(group) = system.boot_entries().find_by_name(group_name) else {
                            bail!("unable to find boot group {group_name}");
                        };
                        Some(group)
                    }
                    None => {
                        if system.boot_entries().iter().count() > 2 {
                            None
                        } else {
                            system
                                .boot_entries()
                                .iter()
                                .find(|(_, entry)| !entry.active())
                        }
                    }
                };
                if let Some((_, boot_group)) = boot_group {
                    info!("installing update to boot group {:?}", boot_group.name());
                    if boot_group.active() {
                        bail!("selected boot group {} is active", boot_group.name());
                    }
                }
                install_bundle(
                    context.config(),
                    source,
                    input,
                    options,
                    ResolvedInstallTarget::System {
                        system: &system,
                        boot_group,
                        reboot,
                        keep_overlay,
                    },
                    events,
                )
            }
        }
    }
}

/// Destination and target-specific settings for a bundle installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InstallTarget {
    /// Install application payloads.
    Apps,
    /// Install system payloads.
    System {
        reboot: Option<SystemRebootMode>,
        keep_overlay: bool,
        boot_group: Option<String>,
    },
}

/// Post-installation behavior for a system update.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SystemRebootMode {
    /// Select the installed system and reboot.
    Yes,
    /// Leave boot selection unchanged.
    No,
    /// Select the installed system without rebooting.
    Set,
    /// Defer boot selection until the next boot.
    Deferred,
}

/// An event emitted while installing a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BundleInstallEvent {
    /// Bundle installation started.
    Started,
    /// Installation progress changed.
    UpdateProgress {
        progress: f64,
        bytes_read: u64,
        bytes_total: u64,
    },
    /// A component compatibility check was skipped.
    CompatibilityCheckSkipped { scope: String, reason: String },
    /// A component compatibility check failed.
    CompatibilityCheckFailed {
        /// Component compatibility report.
        report: ComponentsCheckOutput,
    },
}

/// Source of a bundle installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InstallSource {
    /// Read the bundle from the operation input stream.
    Stream,
    /// Fetch the bundle over HTTP.
    Http {
        url: String,
        disable_range_queries: bool,
        retry: RetryConfig,
    },
}

/// Bundle data supplied alongside an install operation.
pub enum BundleInput {
    /// The bundle source does not require a data stream.
    None,
    /// A sequential input stream, such as standard input or a socket.
    Stream(Box<dyn Read + Send>),
    /// A seekable input stream, such as a local file.
    Seekable(Box<dyn ReadSeek + Send>),
}

/// A readable and seekable operation input.
pub trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// Bundle verification and compatibility options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BundleInstallOptions {
    pub(crate) bundle_hash: Option<HashDigest>,
    pub(crate) root_cert: Option<Vec<u8>>,
    pub(crate) insecure_skip_bundle_verification: bool,
    pub(crate) insecure_allow_missing_block_index: bool,
    pub(crate) skip_compatibility_check: bool,
}

mod apps;
mod system;

enum ResolvedInstallTarget<'a> {
    Apps(&'a AppManager),
    System {
        system: &'a System,
        boot_group: Option<(BootGroupIdx, &'a BootGroup)>,
        reboot: Option<SystemRebootMode>,
        keep_overlay: bool,
    },
}

enum TargetInstallOutput {
    Apps,
    System(SystemRebootMode),
}

struct BundleSourceResult<T> {
    output: T,
    download_stats: Option<DownloadStats>,
}

#[derive(Debug, Clone, Copy)]
enum BundleKind {
    App,
    System,
}

impl BundleKind {
    fn scope(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::System => "system",
        }
    }
}

fn install_bundle(
    config: &Config,
    source: InstallSource,
    input: BundleInput,
    options: BundleInstallOptions,
    target: ResolvedInstallTarget<'_>,
    events: &mut dyn EventSink<BundleInstallEvent>,
) -> SystemResult<()> {
    let kind = match &target {
        ResolvedInstallTarget::Apps(_) => BundleKind::App,
        ResolvedInstallTarget::System { .. } => BundleKind::System,
    };
    let range_queries_available = match (&source, &target) {
        (InstallSource::Http { .. }, ResolvedInstallTarget::System { system, .. }) => {
            system.slots().iter().any(|(_, slot)| {
                payload_db::get_stored_indices(slot.name())
                    .map(|indices| !indices.is_empty())
                    .unwrap_or_default()
            })
        }
        _ => false,
    };
    let BundleSourceResult {
        output,
        download_stats,
    } = with_verified_bundle(
        config,
        source,
        input,
        range_queries_available,
        &options,
        kind,
        |bundle_reader| match &target {
            ResolvedInstallTarget::Apps(manager) => {
                apps::install_payloads(config, manager, bundle_reader, &options, events)?;
                Ok(TargetInstallOutput::Apps)
            }
            ResolvedInstallTarget::System {
                system,
                boot_group,
                keep_overlay,
                ..
            } => system::install_payloads(
                system,
                config,
                bundle_reader,
                boot_group.as_ref(),
                &options,
                *keep_overlay,
                events,
            )
            .map(TargetInstallOutput::System),
        },
    )?;

    match (target, output) {
        (ResolvedInstallTarget::Apps(_), TargetInstallOutput::Apps) => Ok(()),
        (
            ResolvedInstallTarget::System {
                system,
                boot_group,
                reboot,
                ..
            },
            TargetInstallOutput::System(default_reboot),
        ) => {
            if let Some(stats) = download_stats {
                info!(
                    "downloaded {:.1}% ({}/{}) of the full bundle",
                    stats.download_ratio() * 100.0,
                    stats.bytes_read,
                    stats.total_bytes(),
                );
            }
            match reboot.unwrap_or(default_reboot) {
                SystemRebootMode::Yes => {
                    let (entry_idx, boot_group) = require_update_target(boot_group, "reboot")?;
                    info!(
                        "instructing boot flow to try booting into {:?}",
                        boot_group.name()
                    );
                    system
                        .boot_flow()
                        .set_try_next(system, entry_idx)
                        .whatever("unable to set next boot group")?;
                    info!("rebooting");
                    system.reboot()?;
                }
                SystemRebootMode::No => {}
                SystemRebootMode::Set => {
                    let (entry_idx, boot_group) =
                        require_update_target(boot_group, "boot selection")?;
                    info!(
                        "instructing boot flow to try booting into {:?}",
                        boot_group.name()
                    );
                    system
                        .boot_flow()
                        .set_try_next(system, entry_idx)
                        .whatever("unable to set next boot group")?;
                }
                SystemRebootMode::Deferred => {
                    let (_, target) = require_update_target(boot_group, "deferred reboot")?;
                    set_deferred_reboot_target(target.name())?;
                }
            }
            Ok(())
        }
        _ => unreachable!("install target output does not match the prepared target"),
    }
}

fn require_update_target<T: Copy>(target: Option<T>, operation: &str) -> SystemResult<T> {
    target.ok_or_else(|| whatever!("{operation} requires a target boot group"))
}

/// Progress thresholds shared by hooks and command-line event output.
#[derive(Debug, Default)]
pub(crate) struct ProgressCursors {
    hook: f64,
    json: f64,
}

impl ProgressCursors {
    fn should_emit_hook(&self, progress: f64) -> bool {
        (progress >= 100.0 && self.hook < 100.0) || progress - self.hook > 0.9
    }

    pub(crate) fn should_emit_json(&self, progress: f64) -> bool {
        (progress >= 100.0 && self.json < 100.0) || progress - self.json > 0.4
    }

    fn mark_hook_emitted(&mut self, progress: f64) {
        self.hook = progress;
    }

    pub(crate) fn mark_json_emitted(&mut self, progress: f64) {
        self.json = progress;
    }
}

#[derive(Debug)]
struct HashWriter<W> {
    writer: W,
    hasher: Hasher,
    size: u64,
}

impl<W> HashWriter<W> {
    fn new(algorithm: HashAlgorithm, writer: W) -> Self {
        Self {
            writer,
            hasher: algorithm.hasher(),
            size: 0,
        }
    }

    #[cfg(test)]
    fn finalize(self) -> (HashDigest, u64) {
        (self.hasher.finalize(), self.size)
    }
}

impl HashWriter<File> {
    fn finalize_synced(mut self) -> io::Result<(HashDigest, u64)> {
        self.writer.flush()?;
        self.writer.sync_all()?;
        Ok((self.hasher.finalize(), self.size))
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.writer.write(buf)?;
        self.hasher.update(&buf[..written]);
        self.size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[derive(Debug)]
struct BufferedPipeTarget {
    writer: PipeWriter,
}

impl BufferedPipeTarget {
    fn new(writer: PipeWriter) -> Self {
        Self { writer }
    }
}

impl PayloadTarget for BufferedPipeTarget {
    fn write(&mut self, bytes: &[u8]) -> rugix_bundle::BundleResult<()> {
        self.writer.write_all(bytes).whatever("write failed")
    }

    fn finalize(mut self) -> rugix_bundle::BundleResult<()> {
        self.writer.flush().whatever("flush failed")
    }
}

fn with_verified_bundle<T>(
    config: &Config,
    source: InstallSource,
    input: BundleInput,
    range_queries_available: bool,
    options: &BundleInstallOptions,
    kind: BundleKind,
    install: impl FnOnce(BundleReader<&mut dyn BundleSource>) -> SystemResult<T>,
) -> SystemResult<BundleSourceResult<T>> {
    with_bundle_source(source, input, range_queries_available, |source| {
        let bundle_reader = start_verified_bundle(config, source, options, kind)?;
        install(bundle_reader)
    })
}

fn run_compatibility_check(
    options: &BundleInstallOptions,
    kind: BundleKind,
    events: &mut dyn EventSink<BundleInstallEvent>,
    check: impl FnOnce(&mut dyn EventSink<BundleInstallEvent>) -> SystemResult<()>,
) -> SystemResult<()> {
    if options.skip_compatibility_check {
        report_compatibility_skip(
            kind.scope(),
            "explicit --skip-compatibility-check option",
            events,
        );
        return Ok(());
    }
    check(events)
}

fn enforce_bundle_component_policy(
    config: &Config,
    components_present: bool,
    bundle_kind: &str,
) -> SystemResult<()> {
    if !components_present && requires_bundle_components(config) {
        bail!(
            "{bundle_kind} bundle does not declare required component metadata; use --skip-compatibility-check to bypass the configured policy"
        );
    }
    Ok(())
}

fn report_compatibility_skip(
    scope: &str,
    reason: &str,
    events: &mut dyn EventSink<BundleInstallEvent>,
) {
    warn!(scope, reason, "skipping component compatibility check");
    events.emit(BundleInstallEvent::CompatibilityCheckSkipped {
        scope: scope.to_owned(),
        reason: reason.to_owned(),
    });
}

fn require_compatible_components(
    report: ComponentsCheckOutput,
    events: &mut dyn EventSink<BundleInstallEvent>,
) -> SystemResult<()> {
    if report.consistent {
        return Ok(());
    }
    events.emit(BundleInstallEvent::CompatibilityCheckFailed { report });
    bail!("component compatibility check failed")
}

fn with_bundle_source<T>(
    source: InstallSource,
    input: BundleInput,
    range_queries_available: bool,
    install: impl FnOnce(&mut dyn BundleSource) -> SystemResult<T>,
) -> SystemResult<BundleSourceResult<T>> {
    match source {
        InstallSource::Stream => {
            let output = match input {
                BundleInput::None => bail!("bundle input stream is required"),
                BundleInput::Stream(input) => {
                    let mut source = ReaderSource::<_, SkipRead>::from_unbuffered(input);
                    install(&mut source)?
                }
                BundleInput::Seekable(input) => {
                    let mut source = ReaderSource::<_, SkipSeek>::from_unbuffered(input);
                    install(&mut source)?
                }
            };
            Ok(BundleSourceResult {
                output,
                download_stats: None,
            })
        }
        InstallSource::Http {
            url,
            disable_range_queries,
            retry,
        } => {
            if !matches!(input, BundleInput::None) {
                bail!("HTTP bundle source does not accept an input stream");
            }
            let mut source = HttpSource::new(
                &url,
                range_queries_available && !disable_range_queries,
                retry,
            )
            .whatever("unable to create HTTP source")?;
            let output = install(&mut source)?;
            Ok(BundleSourceResult {
                output,
                download_stats: Some(source.get_download_stats()),
            })
        }
    }
}

fn start_verified_bundle<'source>(
    config: &Config,
    source: &'source mut dyn BundleSource,
    options: &BundleInstallOptions,
    kind: BundleKind,
) -> SystemResult<BundleReader<&'source mut dyn BundleSource>> {
    let bundle_reader = match kind {
        BundleKind::App => BundleReader::start(source, options.bundle_hash.clone())
            .whatever("unable to read app bundle")?,
        BundleKind::System => BundleReader::start(source, options.bundle_hash.clone())
            .whatever("unable to read bundle")?,
    };
    let root_certs = configured_signature_roots(config, options.root_cert.as_deref());
    let bundle_verified =
        options.bundle_hash.is_some() || verify_bundle_signature(&root_certs, &bundle_reader)?;
    if !bundle_verified && !options.insecure_skip_bundle_verification {
        match kind {
            BundleKind::App => {
                bail!("bundle verification failed, refusing to install app bundle")
            }
            BundleKind::System => {
                bail!("bundle verification failed, refusing to install update")
            }
        }
    }
    Ok(bundle_reader)
}

fn configured_signature_roots<'a>(
    config: &'a Config,
    explicit: Option<&'a [u8]>,
) -> Vec<SignatureRoot<'a>> {
    if let Some(explicit) = explicit {
        return vec![SignatureRoot::ExplicitCertificate(explicit)];
    }
    config
        .signatures
        .as_ref()
        .map(|config| {
            config
                .roots
                .iter()
                .map(|root| SignatureRoot::ConfiguredPath(Path::new(root)))
                .collect()
        })
        .unwrap_or_default()
}

fn verify_bundle_signature<S: BundleSource>(
    root_certs: &[SignatureRoot<'_>],
    bundle_reader: &BundleReader<S>,
) -> SystemResult<bool> {
    if root_certs.is_empty() {
        return Ok(false);
    }
    let Some(signatures) = bundle_reader.signatures() else {
        warn!(
            root_count = root_certs.len(),
            "root certificates configured but no signatures found"
        );
        return Ok(false);
    };
    let mut verifiers = Vec::new();
    let mut root_errors = 0usize;
    for (root_index, root_cert) in root_certs.iter().enumerate() {
        let verifier: SystemResult<rugix_pki::CmsVerifier> = match root_cert {
            SignatureRoot::ConfiguredPath(path) => fs::read(path)
                .whatever("unable to read root certificate")
                .and_then(|cert_pem| {
                    rugix_pki::CmsVerifier::new(&cert_pem).whatever("unable to create CMS verifier")
                }),
            SignatureRoot::ExplicitCertificate(cert_pem) => {
                rugix_pki::CmsVerifier::new(cert_pem).whatever("unable to create CMS verifier")
            }
        };
        match verifier {
            Ok(verifier) => verifiers.push((root_index, verifier)),
            Err(error) => {
                root_errors += 1;
                warn!(root_index, error = ?error, "unable to load signature root");
            }
        }
    }
    info!(
        signature_count = signatures.cms_signatures.len(),
        root_count = verifiers.len(),
        "checking bundle signatures"
    );
    let mut verification_errors = 0usize;
    for (signature_index, signature) in signatures.cms_signatures.iter().enumerate() {
        for (root_index, verifier) in &verifiers {
            let result = match verifier.verify(&signature.raw) {
                Ok(result) => result,
                Err(error) => {
                    verification_errors += 1;
                    info!(signature_index, root_index, error = %error, "signature did not verify");
                    continue;
                }
            };
            let signed_metadata = match decode_slice::<format::SignedMetadata>(&result.content) {
                Ok(metadata) => metadata,
                Err(error) => {
                    verification_errors += 1;
                    info!(signature_index, root_index, error = ?error, "signed metadata is invalid");
                    continue;
                }
            };
            if signed_metadata.header_hash
                == bundle_reader.header_hash(signed_metadata.header_hash.algorithm())
            {
                info!(signature_index, root_index, "found valid signature");
                return Ok(true);
            }
        }
    }
    warn!(
        root_errors,
        verification_errors, "no configured signature root accepted a bundle signature"
    );
    Ok(false)
}

fn requires_bundle_components(config: &Config) -> bool {
    config
        .compatibility
        .as_ref()
        .and_then(|config| config.require_bundle_components)
        .unwrap_or(false)
}

enum SignatureRoot<'a> {
    ConfiguredPath(&'a Path),
    ExplicitCertificate(&'a [u8]),
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Write;

    use super::enforce_bundle_component_policy;
    use super::require_update_target;
    use super::requires_bundle_components;
    use super::HashWriter;
    use super::ProgressCursors;
    use crate::config::config::Config;

    #[test]
    fn reboot_modes_without_a_target_return_command_errors() {
        assert!(require_update_target::<usize>(None, "reboot").is_err());
        assert_eq!(require_update_target(Some(1usize), "reboot").unwrap(), 1);
    }

    #[test]
    fn hash_writer_accounts_only_for_bytes_actually_written() {
        struct ShortWriter;

        impl Write for ShortWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                Ok(buffer.len().min(2))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut writer = HashWriter::new(si_crypto_hashes::HashAlgorithm::Sha256, ShortWriter);
        assert_eq!(writer.write(b"four").unwrap(), 2);
        let (_, size) = writer.finalize();
        assert_eq!(size, 2);
    }

    #[test]
    fn hook_and_json_progress_use_independent_cursors() {
        let mut cursors = ProgressCursors::default();
        assert!(cursors.should_emit_hook(1.0));
        assert!(cursors.should_emit_json(1.0));

        cursors.mark_hook_emitted(1.0);
        assert!(!cursors.should_emit_hook(1.4));
        assert!(cursors.should_emit_json(1.4));

        cursors.mark_json_emitted(1.4);
        assert!(cursors.should_emit_hook(2.0));
        assert!(cursors.should_emit_json(2.0));
    }

    #[test]
    fn final_progress_is_always_emitted_once() {
        let mut cursors = ProgressCursors::default();
        cursors.mark_hook_emitted(99.8);
        cursors.mark_json_emitted(99.8);
        assert!(cursors.should_emit_hook(100.0));
        assert!(cursors.should_emit_json(100.0));
        cursors.mark_hook_emitted(100.0);
        cursors.mark_json_emitted(100.0);
        assert!(!cursors.should_emit_hook(100.0));
        assert!(!cursors.should_emit_json(100.0));
    }

    #[test]
    fn component_metadata_policy_is_explicit_and_defaults_to_compatible() {
        let default = Config::default();
        assert!(!requires_bundle_components(&default));

        let required: Config =
            toml::from_str("[compatibility]\nrequire-bundle-components = true\n").unwrap();
        assert!(requires_bundle_components(&required));
        assert!(toml::to_string(&required)
            .unwrap()
            .contains("require-bundle-components = true"));
        assert!(enforce_bundle_component_policy(&default, false, "system").is_ok());
        assert!(enforce_bundle_component_policy(&required, true, "system").is_ok());
        assert!(enforce_bundle_component_policy(&required, false, "system").is_err());
        assert!(enforce_bundle_component_policy(&required, false, "app").is_err());
    }
}
