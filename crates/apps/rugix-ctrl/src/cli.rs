//! Definition of the command line interface (CLI).

use std::fs::File;
use std::fs::{self};
use std::io::Read;
use std::io::Write;
use std::io::{self};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use rugix_bundle::manifest::ChunkerAlgorithm;
use rugix_cli::widgets::ProgressBar;
use rugix_cli::widgets::ProgressSpinner;
use rugix_cli::widgets::Widget;
use rugix_cli::StatusSegment;
use rugix_common::disk::blkdev::find_block_device;
use rugix_common::disk::blkdev::BlockDevice;
use rugix_common::mount::is_mount_point;
use rugix_common::path::ValidatedRelativePath;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::config::events::AppActivationResultEvent;
use crate::config::events::CompatibilityCheckSkippedEvent;
use crate::config::events::Event;
use crate::config::events::UpdateProgressEvent;
use crate::config::load_ctrl_config;
use crate::system::boot_groups::BootGroupIdx;
use crate::system::slots::SlotKind;
use crate::system::System;
use crate::system::SystemResult;
use clap::Parser;
use clap::ValueEnum;
use reportify::bail;
use reportify::whatever;
use reportify::ResultExt;
use rugix_common::stream_hasher::StreamHasher;

use crate::config::output::BlockDeviceInfo;
use crate::daemon::client::DaemonClient;
use crate::daemon::DaemonOperation;
use crate::http_source::RetryConfig;
use crate::operations::apps::ActivateApp;
use crate::operations::apps::AppLifecycleEvent;
use crate::operations::apps::DeactivateApp;
use crate::operations::apps::GarbageCollectApps;
use crate::operations::apps::ListApps;
use crate::operations::apps::QueryApp;
use crate::operations::apps::RemoveApp;
use crate::operations::apps::RollbackApp;
use crate::operations::apps::StartApp;
use crate::operations::apps::StopApp;
use crate::operations::install::BundleInput;
use crate::operations::install::BundleInstallEvent;
use crate::operations::install::BundleInstallOptions;
use crate::operations::install::InstallBundle;
use crate::operations::install::InstallSource;
use crate::operations::install::InstallTarget;
use crate::operations::install::ProgressCursors;
use crate::operations::install::SystemRebootMode;
use crate::operations::local::LocalExecutor;
use crate::operations::state::FactoryReset;
use crate::operations::system::CheckComponents;
use crate::operations::system::CommitSystem;
use crate::operations::system::QuerySystem;
use crate::operations::system::RebootSystem;
use crate::operations::EventSink;
use crate::operations::Executor;
use crate::operations::NoEvent;
use crate::operations::Operation;
use crate::payload_db::{self};
use crate::state::clear_state_flag;
use crate::state::create_state_runtime_directory;
use crate::state::set_state_flag;
use crate::utils::clear_flag;
use crate::utils::lock_update;
use crate::utils::reboot;
use crate::utils::set_flag;
use crate::utils::DEFERRED_SPARE_REBOOT_FLAG;

pub fn main() -> SystemResult<()> {
    rugix_cli::CliBuilder::new().init();

    let args = Args::parse();
    match &args.command {
        Command::State(state_cmd) => match state_cmd {
            StateCommand::Reset {
                backup,
                backup_name,
            } => {
                execute_operation(
                    FactoryReset {
                        backup: *backup,
                        backup_name: backup_name.clone(),
                    },
                    (),
                )?;
            }
            StateCommand::Overlay(overlay_cmd) => match overlay_cmd {
                OverlayCommand::ForcePersist { persist } => match persist {
                    Boolean::True => {
                        create_state_runtime_directory()?;
                        set_state_flag("force-persist-overlay", None)?;
                    }
                    Boolean::False => {
                        clear_state_flag("force-persist-overlay")?;
                    }
                },
            },
        },
        Command::Update(update_cmd) => match update_cmd {
            UpdateCommand::Install {
                bundle,
                insecure_skip_bundle_verification,
                insecure_allow_missing_block_index,
                skip_compatibility_check,
                root_cert,
                bundle_hash,
                reboot: reboot_type,
                keep_overlay,
                boot_group,
                disable_range_queries,
                http_max_retries,
                http_retry_initial_backoff,
                http_retry_max_backoff,
            } => {
                let retry_config = RetryConfig {
                    max_retries: *http_max_retries,
                    initial_backoff: Duration::from_secs(*http_retry_initial_backoff),
                    max_backoff: Duration::from_secs(*http_retry_max_backoff),
                };
                let (source, input) = resolve_cli_bundle_source(
                    bundle,
                    *disable_range_queries,
                    retry_config,
                    "error opening image",
                )?;
                let operation = InstallBundle {
                    source,
                    target: InstallTarget::System {
                        reboot: reboot_type.as_ref().map(system_reboot_mode),
                        keep_overlay: *keep_overlay,
                        boot_group: boot_group.clone(),
                    },
                    options: BundleInstallOptions {
                        bundle_hash: bundle_hash.clone(),
                        root_cert: read_explicit_root_certificate(root_cert.as_deref())?,
                        insecure_skip_bundle_verification: *insecure_skip_bundle_verification,
                        insecure_allow_missing_block_index: *insecure_allow_missing_block_index,
                        skip_compatibility_check: *skip_compatibility_check,
                    },
                };
                execute_operation(operation, input)?;
            }
        },
        Command::System(sys_cmd) => match sys_cmd {
            SystemCommand::Info { json } => {
                let output = execute_operation(QuerySystem, ())?;
                rugix_cli::json::print_json(&output, *json)
                    .whatever("unable to write system info to stdout")?;
            }
            SystemCommand::Commit => {
                execute_operation(CommitSystem, ())?;
            }
            SystemCommand::Reboot { spare } => {
                execute_operation(RebootSystem { spare: *spare }, ())?;
            }
        },
        Command::Components(cmd) => match cmd {
            ComponentsCommand::List => {
                let components = crate::components::InstalledComponents::load()?;
                let output = components.output();
                rugix_cli::json::print_json(&output, false)
                    .whatever("unable to write component list to stdout")?;
            }
            ComponentsCommand::Info { component } => {
                let components = crate::components::InstalledComponents::load()?;
                let output = components.output_for_component(component)?;
                rugix_cli::json::print_json(&output, false)
                    .whatever("unable to write component info to stdout")?;
            }
            ComponentsCommand::Check => {
                let check = execute_operation(CheckComponents, ()).and_then(|output| {
                    let consistent = output.consistent;
                    rugix_cli::json::print_json(&output, false)
                        .whatever("unable to write component check report to stdout")?;
                    Ok(consistent)
                });
                match check {
                    Ok(true) => {}
                    Ok(false) => std::process::exit(1),
                    Err(report) => {
                        eprintln!("{report:?}");
                        std::process::exit(2);
                    }
                }
            }
        },
        Command::Data(cmd) => match cmd {
            DataCommand::Wipe { yes, no_reboot } => {
                run_data_wipe(*yes, *no_reboot)?;
            }
        },
        Command::Unstable(command) => match command {
            UnstableCommand::SetDeferredSpareReboot { value } => match value {
                Boolean::True => set_flag(DEFERRED_SPARE_REBOOT_FLAG)?,
                Boolean::False => clear_flag(DEFERRED_SPARE_REBOOT_FLAG)?,
            },
            UnstableCommand::PrintSystemInfo => {
                let system = System::initialize()?;
                eprintln!("Config:");
                eprintln!("{:#?}", system.config());
                eprintln!("Root:");
                eprintln!("{:#?}", system.root());
                eprintln!("Slots:");
                for (_, slot) in system.slots().iter() {
                    eprintln!("{:#?}", slot)
                }
                eprintln!("Boot Entries");
                eprintln!("{:#?}", system.boot_entries());
            }
        },
        Command::Slots(slots_command) => match slots_command {
            SlotsCommand::Inspect { slot } => {
                let indices = payload_db::get_stored_indices(slot)?;
                #[derive(serde::Serialize)]
                struct SlotInspectOutput<'a> {
                    indices: &'a [payload_db::StoredBlockIndex],
                }
                rugix_cli::json::print_json(&SlotInspectOutput { indices: &indices }, false)
                    .whatever("unable to write slot info to stdout")?;
            }
            SlotsCommand::CreateIndex {
                slot,
                chunker: chunker_algorithm,
                hash_algorithm,
            } => {
                let system = System::initialize()?;
                let Some((_, slot)) = system.slots().find_by_name(slot) else {
                    bail!("slot {slot} not found")
                };
                match slot.kind() {
                    SlotKind::Block(_) => {
                        let device = slot.require_available_block()?;
                        payload_db::add_index(
                            slot.name(),
                            device.path(),
                            chunker_algorithm,
                            hash_algorithm,
                        )?;
                    }
                    SlotKind::File { path } => {
                        payload_db::add_index(
                            slot.name(),
                            path,
                            chunker_algorithm,
                            hash_algorithm,
                        )?;
                    }
                    SlotKind::Custom { .. } => {
                        bail!("cannot create indices on custom slots");
                    }
                }
            }
            SlotsCommand::Verify { slot } => {
                let system = System::initialize()?;
                let Some((_, slot)) = system.slots().find_by_name(slot) else {
                    bail!("slot {slot} not found")
                };
                let Some(slot_state) = payload_db::get_stored_state(slot.name())? else {
                    bail!("no stored state for slot {}", slot.name());
                };
                if !slot.is_immutable() {
                    bail!("slot {} is not immutable, cannot verify", slot.name());
                }
                let Some((_, hash)) = &slot_state.hashes.iter().next() else {
                    bail!("no hashes stored for slot {}", slot.name());
                };
                let mut hasher = hash.algorithm().hasher();
                let mut file = match slot.kind() {
                    SlotKind::Block(_) => {
                        let device = slot.require_available_block()?;
                        File::open(device).whatever("error opening block device")?
                    }
                    SlotKind::File { path } => File::open(path).whatever("error opening file")?,
                    SlotKind::Custom { .. } => {
                        bail!("cannot create indices on custom slots");
                    }
                };
                info!(expected_hash = %hash, slot_name = slot.name(), size = slot_state.size.map(|s| s.raw), "verifying slot");
                let mut buffer = [0; 4096];
                let mut remaining = slot_state.size.map(|s| s.raw).unwrap_or(u64::MAX);
                let mut bytes_hashed = 0;
                while remaining > 0 {
                    let read = file.read(&mut buffer).whatever("error reading slot file")?;
                    if read == 0 {
                        break;
                    }
                    let chunk = &buffer[..(read as u64).min(remaining) as usize];
                    hasher.update(chunk);
                    bytes_hashed += chunk.len() as u64;
                    remaining = remaining.saturating_sub(read as u64);
                }
                debug!("hashed {} bytes from slot {}", bytes_hashed, slot.name());
                let found = hasher.finalize();
                if found != **hash {
                    bail!(
                        "hash mismatch for slot {}: expected {}, found {}",
                        slot.name(),
                        hash,
                        found
                    );
                }
                info!(slot_name = slot.name(), "slot verified successfully");
            }
        },
        Command::Boot(cmd) => match cmd {
            BootCommand::MarkGood { group } => {
                let system = System::initialize()?;
                let boot_group = resolve_mark_good_group(
                    system.boot_entries(),
                    system.active_boot_entry(),
                    group.as_deref(),
                )?;
                info!(
                    "marking boot group {} as good",
                    system.boot_entries()[boot_group].name()
                );
                system
                    .boot_flow()
                    .mark_good(&system, boot_group)
                    .whatever("unable to mark boot group as good")?;
            }
            BootCommand::MarkBad { group } => {
                let system = System::initialize()?;
                let Some((group, _)) = system.boot_entries().find_by_name(group) else {
                    bail!("unable to find boot group {group}")
                };
                info!(
                    "marking boot group {} as bad",
                    system.boot_entries()[group].name()
                );
                system
                    .boot_flow()
                    .mark_bad(&system, group)
                    .whatever("unable to mark boot group as bad")?;
            }
        },
        Command::Utils(cmd) => match cmd {
            UtilsCommand::FindBlockDevice { path } => {
                let Some(device) =
                    find_block_device(path).whatever("error finding block device")?
                else {
                    bail!("unable to find block device");
                };
                rugix_cli::json::print_json(
                    &BlockDeviceInfo {
                        device: device.path().to_string_lossy().into_owned(),
                        parent: device
                            .find_parent()
                            .ok()
                            .flatten()
                            .map(|parent| parent.path().to_string_lossy().into_owned()),
                        partition: device.is_partition().ok().flatten(),
                    },
                    false,
                )
                .whatever("unable to write block device info to stdout")?;
            }
            UtilsCommand::IsMountPoint { path } => {
                rugix_cli::json::print_json(&is_mount_point(path), false)
                    .whatever("unable to write mount point info to stdout")?;
            }
            UtilsCommand::ResolvePartition { disk, partition } => {
                let system = System::initialize()?;
                let disk = if let Some(disk) = disk {
                    BlockDevice::new(disk).whatever("unable to open disk")?
                } else {
                    system
                        .root()
                        .as_ref()
                        .ok_or_else(|| whatever!("unable to determine the system root device"))?
                        .device
                        .clone()
                };
                let Some(device) = disk
                    .get_partition(*partition)
                    .whatever("unable to get partition")?
                else {
                    bail!("partition not found");
                };
                rugix_cli::json::print_json(
                    &BlockDeviceInfo {
                        device: device.path().to_string_lossy().into_owned(),
                        parent: device
                            .find_parent()
                            .ok()
                            .flatten()
                            .map(|parent| parent.path().to_string_lossy().into_owned()),
                        partition: device.is_partition().ok().flatten(),
                    },
                    false,
                )
                .whatever("unable to write partition info to stdout")?;
            }
        },
        Command::Daemon { command } => match command {
            Some(DaemonCommand::Info { json }) => {
                let info =
                    DaemonClient::new(crate::daemon::load_daemon_settings()?).query_info()?;
                rugix_cli::json::print_json(&info, *json)
                    .whatever("unable to write daemon information to stdout")?;
            }
            None => crate::daemon::run()?,
        },
        Command::Apps(cmd) => {
            warn!("edge application orchestration is experimental");
            match cmd {
                AppsCommand::Install {
                    bundle,
                    insecure_skip_bundle_verification,
                    insecure_allow_missing_block_index,
                    skip_compatibility_check,
                    root_cert,
                    bundle_hash,
                    http_max_retries,
                    http_retry_initial_backoff,
                    http_retry_max_backoff,
                } => {
                    let retry_config = RetryConfig {
                        max_retries: *http_max_retries,
                        initial_backoff: Duration::from_secs(*http_retry_initial_backoff),
                        max_backoff: Duration::from_secs(*http_retry_max_backoff),
                    };
                    let (source, input) = resolve_cli_bundle_source(
                        bundle,
                        false,
                        retry_config,
                        "unable to open app bundle",
                    )?;
                    let operation = InstallBundle {
                        source,
                        target: InstallTarget::Apps,
                        options: BundleInstallOptions {
                            bundle_hash: bundle_hash.clone(),
                            root_cert: read_explicit_root_certificate(root_cert.as_deref())?,
                            insecure_skip_bundle_verification: *insecure_skip_bundle_verification,
                            insecure_allow_missing_block_index: *insecure_allow_missing_block_index,
                            skip_compatibility_check: *skip_compatibility_check,
                        },
                    };
                    execute_operation(operation, input)?;
                }
                AppsCommand::List => {
                    let entries = execute_operation(ListApps, ())?;
                    rugix_cli::json::print_json(&entries, false)
                        .whatever("unable to write apps list to stdout")?;
                }
                AppsCommand::Info { app } => {
                    let output = execute_operation(QueryApp { name: app.clone() }, ())?;
                    rugix_cli::json::print_json(&output, false)
                        .whatever("unable to write app info to stdout")?;
                }
                AppsCommand::Activate {
                    app,
                    generation,
                    skip_compatibility_check,
                } => {
                    execute_operation(
                        ActivateApp {
                            name: app.clone(),
                            generation: *generation,
                            skip_compatibility_check: *skip_compatibility_check,
                        },
                        (),
                    )?;
                }
                AppsCommand::Deactivate {
                    app,
                    skip_compatibility_check,
                } => {
                    execute_operation(
                        DeactivateApp {
                            name: app.clone(),
                            skip_compatibility_check: *skip_compatibility_check,
                        },
                        (),
                    )?;
                }
                AppsCommand::Start { app } => {
                    execute_operation(StartApp { name: app.clone() }, ())?;
                }
                AppsCommand::Stop { app } => {
                    execute_operation(StopApp { name: app.clone() }, ())?;
                }
                AppsCommand::Rollback {
                    app,
                    skip_compatibility_check,
                } => {
                    execute_operation(
                        RollbackApp {
                            name: app.clone(),
                            skip_compatibility_check: *skip_compatibility_check,
                        },
                        (),
                    )?;
                }
                AppsCommand::Remove {
                    app,
                    skip_compatibility_check,
                } => {
                    execute_operation(
                        RemoveApp {
                            name: app.clone(),
                            skip_compatibility_check: *skip_compatibility_check,
                        },
                        (),
                    )?;
                }
                AppsCommand::Generations { app } => {
                    use crate::config::output::GenerationInfoOutput;
                    let manager = load_cli_app_manager()?;
                    let generations = manager
                        .list_generations(app)
                        .whatever("unable to list generations")?;
                    let current = manager
                        .current_generation(app)
                        .whatever("unable to read app state")?;
                    let entries: Vec<_> = generations
                        .iter()
                        .map(|gen| {
                            GenerationInfoOutput::new(
                                gen.meta.number,
                                gen.meta.created_at.clone(),
                                gen.complete,
                                Some(gen.meta.number) == current,
                            )
                            .with_last_activated(gen.meta.last_activated.clone())
                        })
                        .collect();
                    rugix_cli::json::print_json(&entries, false)
                        .whatever("unable to write generations to stdout")?;
                }
                AppsCommand::Gc { app, keep } => {
                    let results = execute_operation(
                        GarbageCollectApps {
                            name: app.clone(),
                            keep: *keep,
                        },
                        (),
                    )?;
                    rugix_cli::json::print_json(&results, false)
                        .whatever("unable to write gc output to stdout")?;
                }
                AppsCommand::Recover => {
                    let manager = load_cli_app_manager()?;
                    manager.recover_all().whatever("recovery failed")?;
                }
                AppsCommand::CreateIndex {
                    app,
                    chunker,
                    hash_algorithm,
                    path,
                    generation,
                } => {
                    let manager = load_cli_app_manager()?;
                    let gen_number = match generation {
                        Some(n) => *n,
                        None => manager
                            .current_generation(app)
                            .whatever("unable to read app state")?
                            .ok_or_else(|| whatever!("no active generation for app {app}"))?,
                    };
                    let gen_dir = manager
                        .generation_dir(app, gen_number)
                        .whatever("invalid app name")?;
                    let paths: Vec<String> = match path {
                        Some(p) => vec![p.clone()],
                        None => {
                            let states =
                                crate::apps::manager::AppManager::load_payload_states(&gen_dir);
                            states.into_keys().collect()
                        }
                    };
                    for payload_path in &paths {
                        let payload_path = ValidatedRelativePath::new(payload_path.clone())
                            .whatever("invalid app-file path")?;
                        let data_file = gen_dir.join(&payload_path);
                        if !data_file.exists() {
                            bail!(
                                "file {payload_path} not found in generation {gen_number} of app {app}"
                            );
                        }
                        info!(app = %app, path = %payload_path, "creating block index");
                        payload_db::add_app_file_index(
                            &gen_dir,
                            payload_path.as_str(),
                            &data_file,
                            chunker,
                            hash_algorithm,
                        )?;
                    }
                }
                AppsCommand::ServiceManager(sm_cmd) => {
                    let manager = load_cli_app_manager()?;
                    match sm_cmd {
                        AppsServiceManagerCommand::Systemd(systemd_cmd) => match systemd_cmd {
                            AppsSystemdCommand::RestoreUnits => {
                                crate::apps::systemd::restore::restore_units(&manager)
                                    .whatever("failed to restore app units")?;
                            }
                        },
                    }
                }
            }
        }
    }
    Ok(())
}

fn resolve_cli_bundle_source(
    bundle: &str,
    disable_range_queries: bool,
    retry: RetryConfig,
    file_error_context: &'static str,
) -> SystemResult<(InstallSource, BundleInput)> {
    if bundle.starts_with("http") {
        Ok((
            InstallSource::Http {
                url: bundle.to_owned(),
                disable_range_queries,
                retry,
            },
            BundleInput::None,
        ))
    } else if bundle == "-" {
        Ok((
            InstallSource::Stream,
            BundleInput::Stream(Box::new(io::stdin())),
        ))
    } else {
        let input = File::open(bundle).whatever(file_error_context)?;
        Ok((
            InstallSource::Stream,
            BundleInput::Seekable(Box::new(input)),
        ))
    }
}

fn read_explicit_root_certificate(path: Option<&Path>) -> SystemResult<Option<Vec<u8>>> {
    path.map(|path| fs::read(path).whatever("unable to read root certificate"))
        .transpose()
}

fn load_cli_app_manager() -> SystemResult<crate::apps::manager::AppManager> {
    let config = crate::apps::config::load_apps_config().whatever("unable to load apps config")?;
    Ok(crate::apps::manager::AppManager::new(
        crate::apps::config::apps_dir().to_owned(),
        config,
    ))
}

fn execute_operation<O>(operation: O, input: O::Input) -> SystemResult<O::Output>
where
    O: Operation + DaemonOperation,
    O::Input: Send,
    CliOperationEventSink: EventSink<O::Event>,
{
    let mut events = CliOperationEventSink::default();
    if crate::daemon::is_privileged() {
        let config = load_ctrl_config()?;
        LocalExecutor::new(&config).execute(operation, input, &mut events)
    } else {
        DaemonClient::new(crate::daemon::load_daemon_settings()?).execute(
            operation,
            input,
            &mut events,
        )
    }
}

fn system_reboot_mode(reboot: &UpdateRebootType) -> SystemRebootMode {
    match reboot {
        UpdateRebootType::Yes => SystemRebootMode::Yes,
        UpdateRebootType::No => SystemRebootMode::No,
        UpdateRebootType::Set => SystemRebootMode::Set,
        UpdateRebootType::Deferred => SystemRebootMode::Deferred,
    }
}

fn resolve_mark_good_group(
    groups: &crate::system::boot_groups::BootGroups,
    active: Option<BootGroupIdx>,
    requested: Option<&str>,
) -> SystemResult<BootGroupIdx> {
    if let Some(requested) = requested {
        return groups
            .find_by_name(requested)
            .map(|(index, _)| index)
            .ok_or_else(|| whatever!("unable to find boot group {requested}"));
    }
    active.ok_or_else(|| whatever!("unable to determine the active boot group"))
}

#[derive(Debug, Clone)]
pub enum ImageHash {
    Sha256(Vec<u8>),
}

pub enum MaybeStreamHasher<R> {
    NoHash {
        reader: R,
    },
    Sha256 {
        hasher: StreamHasher<R, sha2::Sha256>,
        expected: Vec<u8>,
    },
}

impl<R> MaybeStreamHasher<R> {
    pub fn verify(self) -> SystemResult<()> {
        match self {
            MaybeStreamHasher::NoHash { .. } => Ok(()),
            MaybeStreamHasher::Sha256 { hasher, expected } => {
                let found = hasher.finalize();
                if expected.as_slice() != found.as_slice() {
                    return Err(reportify::Report::whatever(indoc::formatdoc! {
                        r#"
                            **Image Hash Mismatch:**
                            Expected: {}
                            Found: {}
                        "#,
                        hex::encode(expected),
                        hex::encode(found)
                    }));
                }
                Ok(())
            }
        }
    }
}

impl<R: Read> Read for MaybeStreamHasher<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            MaybeStreamHasher::NoHash { reader } => reader.read(buf),
            MaybeStreamHasher::Sha256 { hasher, .. } => hasher.read(buf),
        }
    }
}

pub struct UpdateState {
    bytes_read: u64,
    bytes_total: u64,
}

pub struct UpdateStatus {
    state: Mutex<UpdateState>,
}

impl StatusSegment for UpdateStatus {
    fn draw(&self, ctx: &mut rugix_cli::DrawCtx) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.bytes_total > 0 {
            ProgressBar::new(state.bytes_read, state.bytes_total).draw(ctx);
        } else {
            ProgressSpinner::new().draw(ctx);
        }
    }
}

#[derive(Default)]
struct CliOperationEventSink {
    update_status: Option<rugix_cli::StatusSegmentRef<UpdateStatus>>,
    progress_cursors: ProgressCursors,
}

impl CliOperationEventSink {
    fn ensure_update_status(&mut self) -> &rugix_cli::StatusSegmentRef<UpdateStatus> {
        self.update_status.get_or_insert_with(|| {
            rugix_cli::add_status(UpdateStatus {
                state: Mutex::new(UpdateState {
                    bytes_read: 0,
                    bytes_total: 0,
                }),
            })
        })
    }
}

impl EventSink<NoEvent> for CliOperationEventSink {
    fn emit(&mut self, event: NoEvent) {
        match event {}
    }
}

impl EventSink<BundleInstallEvent> for CliOperationEventSink {
    fn emit(&mut self, event: BundleInstallEvent) {
        match &event {
            BundleInstallEvent::Started => {
                self.ensure_update_status();
            }
            BundleInstallEvent::UpdateProgress {
                progress,
                bytes_read,
                bytes_total,
            } => {
                {
                    let update_status = self.ensure_update_status();
                    let mut update_state = update_status
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    update_state.bytes_read = *bytes_read;
                    update_state.bytes_total = *bytes_total;
                }
                if !rugix_cli::stdout_is_piped()
                    || !self.progress_cursors.should_emit_json(*progress)
                {
                    return;
                }
                self.progress_cursors.mark_json_emitted(*progress);
            }
            BundleInstallEvent::CompatibilityCheckSkipped { .. } => {
                if !rugix_cli::stdout_is_piped() {
                    return;
                }
            }
            BundleInstallEvent::CompatibilityCheckFailed { report } => {
                if let Err(error) = rugix_cli::json::print_json(report, false) {
                    warn!(%error, "unable to write component compatibility report");
                }
                return;
            }
        }

        let Some(event) = operation_event_as_cli_event(&event) else {
            return;
        };
        let result = serde_json::to_vec(&event)
            .map_err(io::Error::other)
            .and_then(|mut bytes| {
                bytes.push(b'\n');
                std::io::stdout().write_all(&bytes)
            });
        if let Err(error) = result {
            warn!(%error, "unable to emit operation event");
        }
    }
}

impl EventSink<AppLifecycleEvent> for CliOperationEventSink {
    fn emit(&mut self, event: AppLifecycleEvent) {
        match event {
            AppLifecycleEvent::ActivationCompleted {
                app,
                generation,
                outcome,
            } => {
                if !rugix_cli::stdout_is_piped() {
                    return;
                }
                let event = Event::AppActivationResult(AppActivationResultEvent {
                    app,
                    generation,
                    outcome,
                });
                let result = serde_json::to_vec(&event)
                    .map_err(io::Error::other)
                    .and_then(|mut bytes| {
                        bytes.push(b'\n');
                        std::io::stdout().write_all(&bytes)
                    });
                if let Err(error) = result {
                    warn!(%error, "unable to emit app activation JSON event");
                }
            }
            AppLifecycleEvent::CompatibilityCheckFailed { report } => {
                if let Err(error) = rugix_cli::json::print_json(&report, false) {
                    warn!(%error, "unable to write component compatibility report");
                }
            }
        }
    }
}

fn operation_event_as_cli_event(event: &BundleInstallEvent) -> Option<Event> {
    match event {
        BundleInstallEvent::Started => None,
        BundleInstallEvent::UpdateProgress { progress, .. } => {
            Some(Event::UpdateProgress(UpdateProgressEvent {
                progress: *progress,
            }))
        }
        BundleInstallEvent::CompatibilityCheckSkipped { scope, reason } => Some(
            Event::CompatibilityCheckSkipped(CompatibilityCheckSkippedEvent {
                scope: scope.clone(),
                reason: reason.clone(),
            }),
        ),
        BundleInstallEvent::CompatibilityCheckFailed { .. } => None,
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Boolean {
    True,
    False,
}

#[derive(Debug, Parser)]
#[clap(author, version = rugix_version::RUGIX_GIT_VERSION, about)]
pub struct Args {
    /// The command.
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Parser)]
pub enum Command {
    /// Run or inspect the privileged operation daemon.
    Daemon {
        /// Optional daemon inspection command.
        #[clap(subcommand)]
        command: Option<DaemonCommand>,
    },
    /// Manage the persistent state of the system.
    #[clap(subcommand)]
    State(StateCommand),
    /// Install and inspect over-the-air updates.
    #[clap(subcommand)]
    Update(UpdateCommand),
    /// Manage the system.
    #[clap(subcommand)]
    System(SystemCommand),
    /// Inspect compatibility components and constraints (experimental).
    #[clap(subcommand)]
    Components(ComponentsCommand),
    /// Manage the update slots of the system.
    #[clap(subcommand)]
    Slots(SlotsCommand),
    /// Control the boot flow of the system.
    #[clap(subcommand)]
    Boot(BootCommand),
    /// Utility commands useful for scripting.
    #[clap(subcommand)]
    Utils(UtilsCommand),
    /// Manage applications.
    #[clap(subcommand)]
    Apps(AppsCommand),
    /// Manage the data partition.
    #[clap(subcommand)]
    Data(DataCommand),
    /// Unstable experimental commands.
    #[clap(subcommand)]
    Unstable(UnstableCommand),
}

#[derive(Debug, Parser)]
pub enum DaemonCommand {
    /// Query the running daemon's effective policy.
    Info {
        /// Format the output as JSON.
        #[clap(long)]
        json: bool,
    },
}

#[derive(Debug, Parser)]
pub enum DataCommand {
    /// Cryptographically wipe the data partition.
    ///
    /// Renders existing contents unrecoverable (LUKS drivers destroy the
    /// master key; the plaintext driver discards and reformats) and reboots.
    /// **Destructive:** all state profiles, app data, and metadata are lost.
    Wipe {
        /// Skip the interactive confirmation. Required when not on a TTY.
        #[clap(long)]
        yes: bool,
        /// Do not reboot after writing the wipe marker.
        #[clap(long)]
        no_reboot: bool,
    },
}

#[derive(Debug, Parser)]
pub enum StateCommand {
    /// Perform a factory reset of the system.
    Reset {
        /// Backup the old state by creating a new state profile.
        #[clap(long)]
        backup: bool,
        /// Name of the backup state profile.
        #[clap(long)]
        backup_name: Option<String>,
    },
    /// Configure the root filesystem overlay.
    #[clap(subcommand)]
    Overlay(OverlayCommand),
}

#[derive(Debug, Parser)]
pub enum SlotsCommand {
    /// Verify the integrity of a slot.
    Verify { slot: String },
    /// Query the state of a slot.
    Inspect { slot: String },
    /// Add an index to a slot.
    CreateIndex {
        slot: String,
        chunker: ChunkerAlgorithm,
        hash_algorithm: HashAlgorithm,
    },
}

#[derive(Debug, Parser)]
pub enum OverlayCommand {
    /// Set the persistency of the overlay.
    ForcePersist { persist: Boolean },
}

#[derive(Debug, Parser)]
pub enum UpdateCommand {
    /// Install an update.
    Install {
        /// Path to the update bundle to install.
        bundle: String,
        /// Skip bundle verification (insecure, do not use in production).
        ///
        /// By default, either a valid signature is required or a bundle hash has to be
        /// specified with `--bundle-hash`. This flag allows the installation of update
        /// bundles without either of those.
        #[clap(long)]
        insecure_skip_bundle_verification: bool,
        /// Allow payloads without a block index (insecure, do not use in production).
        ///
        /// By default, payloads without a block index are rejected during installation.
        /// This flag allows installing update payloads that lack a block index.
        #[clap(long)]
        insecure_allow_missing_block_index: bool,
        /// Skip component compatibility checks.
        #[clap(long)]
        skip_compatibility_check: bool,
        /// Root certificate to use for signature verification.
        ///
        /// This overrides the configured default certificate.
        #[clap(long)]
        root_cert: Option<PathBuf>,
        /// Expected bundle hash.
        #[clap(long)]
        bundle_hash: Option<HashDigest>,
        /// Control how to reboot the system.
        #[clap(long)]
        reboot: Option<UpdateRebootType>,
        /// Do not delete the overlay of the target slot (if any).
        ///
        /// Only effective when using Rugix's state management mechanism.
        #[clap(long)]
        keep_overlay: bool,
        /// Boot group to install the update to.
        #[clap(long)]
        boot_group: Option<String>,
        /// Disable the use of range queries for HTTP sources.
        #[clap(long)]
        disable_range_queries: bool,
        /// Maximum number of retry attempts for transient HTTP errors.
        #[clap(long, default_value_t = 5)]
        http_max_retries: u32,
        /// Initial HTTP retry backoff duration in seconds.
        #[clap(long, default_value_t = 1)]
        http_retry_initial_backoff: u64,
        /// Maximum HTTP retry backoff duration in seconds.
        #[clap(long, default_value_t = 30)]
        http_retry_max_backoff: u64,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum UpdateRebootType {
    /// Durably select the new system and reboot after synchronizing all payload data.
    Yes,
    /// Leave boot selection unchanged after synchronizing all payload data.
    No,
    /// Durably select the new system without rebooting.
    ///
    /// This will tell the bootloader integration to boot into the new system next without
    /// actually triggering a reboot.
    Set,
    /// Durably record the selected new system without changing boot selection yet.
    ///
    /// Rugix will itself remember that an update has been installed. On the next boot,
    /// it will select the recorded group, remove the marker, and reboot into the new
    /// system. The marker remains in place if boot selection fails, so initialization
    /// can retry. This allows the system
    /// to be shutoff after installing the update. On the next boot, Rugix will then try
    /// to boot into the new version.
    Deferred,
}

#[derive(Debug, Parser)]
pub enum SystemCommand {
    /// Print information about the system.
    Info {
        /// Output compact JSON instead of pretty-printed JSON.
        #[clap(long)]
        json: bool,
    },
    /// Make the active system the default.
    Commit,
    /// Reboot the system.
    Reboot {
        /// Reboot into the spare system.
        #[clap(long)]
        spare: bool,
    },
}

#[derive(Debug, Parser)]
pub enum ComponentsCommand {
    /// List installed compatibility components.
    List,
    /// Show installed compatibility components with a specific component ID.
    Info {
        /// Component ID.
        component: String,
    },
    /// Check installed compatibility components for internal consistency.
    Check,
}

#[derive(Debug, Parser)]
pub enum UnstableCommand {
    /// Set deferred spare reboot flag.
    SetDeferredSpareReboot {
        value: Boolean,
    },
    PrintSystemInfo,
}

#[derive(Debug, Parser)]
pub enum BootCommand {
    /// Mark a boot group as good.
    MarkGood { group: Option<String> },
    /// Mark a boot group as bad.
    MarkBad { group: String },
}

#[derive(Debug, Parser)]
pub enum UtilsCommand {
    /// Determine the block device behind a path.
    FindBlockDevice { path: PathBuf },
    /// Check whether a path is a mount point.
    IsMountPoint { path: PathBuf },
    /// Resolve a partition relative to the main disk or some other block device.
    ResolvePartition {
        #[clap(long)]
        disk: Option<PathBuf>,
        partition: u32,
    },
}

#[derive(Debug, Parser)]
pub enum AppsCommand {
    /// Install apps from a bundle.
    Install {
        /// Path of the app bundle, `-` to read from stdin, or an HTTP(S) URL.
        bundle: String,
        /// Skip bundle verification (insecure, do not use in production).
        ///
        /// By default, either a valid signature is required or a bundle hash has to be
        /// specified with `--bundle-hash`. This flag allows the installation of app
        /// bundles without either of those.
        #[clap(long)]
        insecure_skip_bundle_verification: bool,
        /// Allow payloads without a block index (insecure, do not use in production).
        ///
        /// By default, payloads without a block index are rejected during installation.
        /// This flag allows installing app payloads that lack a block index.
        #[clap(long)]
        insecure_allow_missing_block_index: bool,
        /// Skip component compatibility checks.
        #[clap(long)]
        skip_compatibility_check: bool,
        /// Root certificate to use for signature verification.
        ///
        /// This overrides the configured default certificate.
        #[clap(long)]
        root_cert: Option<PathBuf>,
        /// Expected bundle hash.
        #[clap(long)]
        bundle_hash: Option<HashDigest>,
        /// Maximum number of retry attempts for transient HTTP errors.
        #[clap(long, default_value_t = 5)]
        http_max_retries: u32,
        /// Initial HTTP retry backoff duration in seconds.
        #[clap(long, default_value_t = 1)]
        http_retry_initial_backoff: u64,
        /// Maximum HTTP retry backoff duration in seconds.
        #[clap(long, default_value_t = 30)]
        http_retry_max_backoff: u64,
    },
    /// List all installed apps.
    List,
    /// Show app info and status.
    Info {
        /// App name.
        app: String,
    },
    /// Activate a generation. If no generation is specified, activates the
    /// most recently activated generation (useful for re-activating after deactivation).
    Activate {
        /// App name.
        app: String,
        /// Generation number (defaults to the most recently activated generation).
        generation: Option<u64>,
        /// Skip component compatibility checks.
        #[clap(long)]
        skip_compatibility_check: bool,
    },
    /// Deactivate the current generation of an app.
    Deactivate {
        /// App name.
        app: String,
        /// Skip component compatibility checks.
        #[clap(long)]
        skip_compatibility_check: bool,
    },
    /// Start the workload of an active app.
    Start {
        /// App name.
        app: String,
    },
    /// Stop the workload of an active app without deactivating it.
    Stop {
        /// App name.
        app: String,
    },
    /// Rollback an app to the previous generation.
    Rollback {
        /// App name.
        app: String,
        /// Skip component compatibility checks.
        #[clap(long)]
        skip_compatibility_check: bool,
    },
    /// Remove an app entirely.
    Remove {
        /// App name.
        app: String,
        /// Skip component compatibility checks.
        #[clap(long)]
        skip_compatibility_check: bool,
    },
    /// List generations for an app.
    Generations {
        /// App name.
        app: String,
    },
    /// Garbage collect old generations. If no app is specified, runs for all apps.
    Gc {
        /// App name (if omitted, runs for all apps).
        app: Option<String>,
        /// Number of previously activated generations to keep (in addition to the
        /// currently active generation, which is always kept).
        #[clap(long, default_value_t = 1)]
        keep: usize,
    },
    /// Recover any interrupted app transitions.
    Recover,
    /// Create block indices for app-file payloads in a generation.
    ///
    /// If no path is specified, creates indices for all payload files
    /// recorded in the generation's payloads.json.
    CreateIndex {
        /// App name.
        app: String,
        /// Chunker algorithm.
        chunker: ChunkerAlgorithm,
        /// Hash algorithm.
        hash_algorithm: HashAlgorithm,
        /// Relative payload path within the generation directory.
        /// If omitted, creates indices for all known payload files.
        #[clap(long)]
        path: Option<String>,
        /// Generation number (defaults to the currently active generation).
        #[clap(long)]
        generation: Option<u64>,
    },
    /// Service manager integration.
    #[clap(subcommand)]
    ServiceManager(AppsServiceManagerCommand),
}

#[derive(Debug, Parser)]
pub enum AppsServiceManagerCommand {
    /// Systemd integration.
    #[clap(subcommand)]
    Systemd(AppsSystemdCommand),
}

#[derive(Debug, Parser)]
pub enum AppsSystemdCommand {
    /// Restore app units into the systemd runtime directory.
    RestoreUnits,
}

/// Wipe the data partition by writing a `wipe-data` marker on the config
/// partition and rebooting. Pre-init runs the actual erase + reformat
/// before mounting; we can't safely do it here because the data
/// partition is currently mounted.
fn run_data_wipe(yes: bool, no_reboot: bool) -> SystemResult<()> {
    let _update_lock = lock_update()?;

    if !yes {
        eprintln!(
            "Refusing to wipe the data partition without `--yes`. \
             This is destructive: all state profiles, app data, and metadata \
             on the data partition will be lost."
        );
        bail!("`--yes` required");
    }

    let system = System::initialize()?;
    let config_partition = system.require_config_partition()?;
    config_partition
        .ensure_writable(|| -> SystemResult<()> {
            let rugix_dir = config_partition.path().join(".rugix");
            fs::create_dir_all(&rugix_dir).whatever("unable to create `.rugix` directory")?;
            fs::write(rugix_dir.join("wipe-data"), "")
                .whatever("unable to write `wipe-data` marker")?;
            Ok(())
        })
        .whatever("unable to make config partition writable for `data wipe`")??;

    if !no_reboot {
        reboot()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use crate::config::system::BootGroupConfig;
    use crate::config::system::FileSlotConfig;
    use crate::config::system::SlotConfig;
    use crate::operations::install::BundleInstallEvent;
    use crate::system::boot_groups::BootGroups;
    use crate::system::slots::SystemSlots;

    use super::operation_event_as_cli_event;
    use super::resolve_mark_good_group;

    fn file_slots(names: &[&str]) -> SystemSlots {
        let config = names
            .iter()
            .map(|name| {
                (
                    (*name).to_owned(),
                    SlotConfig::File(FileSlotConfig {
                        path: format!("/tmp/{name}"),
                        immutable: Some(true),
                    }),
                )
            })
            .collect::<IndexMap<_, _>>();
        SystemSlots::from_config(None, Some(&config)).unwrap()
    }

    #[test]
    fn mark_good_without_a_known_active_group_returns_a_command_error() {
        let slots = file_slots(&["system"]);
        let groups_config = [(
            "a".to_owned(),
            BootGroupConfig {
                slots: IndexMap::new(),
            },
        )]
        .into_iter()
        .collect::<IndexMap<_, _>>();
        let groups = BootGroups::from_config(&slots, Some(&groups_config)).unwrap();

        let error = resolve_mark_good_group(&groups, None, None).unwrap_err();
        assert!(format!("{error:?}").contains("unable to determine the active boot group"));
        assert!(resolve_mark_good_group(&groups, None, Some("missing")).is_err());
    }

    #[test]
    fn compatibility_skip_events_preserve_scope_and_reason() {
        let event = operation_event_as_cli_event(&BundleInstallEvent::CompatibilityCheckSkipped {
            scope: "system".to_owned(),
            reason: "explicit bypass".to_owned(),
        })
        .unwrap();
        let json = serde_json::to_value(event).unwrap();
        assert_eq!(json["event"], "CompatibilityCheckSkipped");
        assert_eq!(json["scope"], "system");
        assert_eq!(json["reason"], "explicit bypass");
    }
}
