//! Definition of the command line interface (CLI).

use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fs::File;
use std::fs::{self};
use std::io::Read;
use std::io::Write;
use std::io::{self};
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::sync::Mutex;
use std::time::Duration;

use rugix_bundle::format;
use rugix_bundle::format::decode::decode_slice;
use rugix_bundle::manifest::ChunkerAlgorithm;
use rugix_bundle::reader::block_provider::StoredBlockProvider;
use rugix_bundle::reader::BundleReader;
use rugix_bundle::reader::DecodedPayloadInfo;
use rugix_bundle::reader::PayloadTarget;
use rugix_bundle::source::BundleSource;
use rugix_bundle::source::ReaderSource;
use rugix_bundle::source::SkipRead;
use rugix_bundle::source::SkipSeek;
use rugix_bundle::xdelta::xdelta_decompress;
use rugix_cli::widgets::ProgressBar;
use rugix_cli::widgets::ProgressSpinner;
use rugix_cli::widgets::Widget;
use rugix_cli::StatusSegment;
use rugix_common::disk::blkdev::find_block_device;
use rugix_common::disk::blkdev::BlockDevice;
use rugix_common::mount::is_mount_point;
use rugix_common::path::ensure_no_symlink_components;
use rugix_common::path::ValidatedRelativePath;
use rugix_common::pipe::buffered_pipe;
use rugix_common::pipe::PipeWriter;
use rugix_common::slots::SlotState;
use rugix_hooks::HooksLoader;
use rugix_hooks::RunOptions;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;
use si_crypto_hashes::Hasher;
use tracing::debug;
use tracing::info;
use tracing::trace;
use tracing::warn;

use crate::config::config::Config;
use crate::config::events::Event;
use crate::config::events::UpdateProgressEvent;
use crate::config::load_ctrl_config;
use crate::system::boot_groups::BootGroup;
use crate::system::boot_groups::BootGroupIdx;
use crate::system::slots::SlotIdx;
use crate::system::slots::SlotKind;
use crate::system::slots::SystemSlots;
use crate::system::System;
use crate::system::SystemResult;
use clap::Parser;
use clap::ValueEnum;
use reportify::bail;
use reportify::whatever;
use reportify::ErrorExt;
use reportify::ResultExt;
use rugix_common::stream_hasher::StreamHasher;
use xscript::vars;
use xscript::Vars;

use crate::config::output::BlockDeviceInfo;
use crate::config::output::ComponentsCheckOutput;
use crate::http_source::HttpSource;
use crate::http_source::RetryConfig;
use crate::overlay::overlay_dir;
use crate::payload_db::BlockProvider;
use crate::payload_db::{self};
use crate::system_state;
use crate::utils::clear_flag;
use crate::utils::reboot;
use crate::utils::set_flag;
use crate::utils::DEFERRED_SPARE_REBOOT_FLAG;

fn create_rugix_state_directory() -> SystemResult<()> {
    fs::create_dir_all("/run/rugix/state/.rugix")
        .whatever("unable to create `/run/rugix/state/.rugix`")
}

/// Acquire an exclusive lock for system update operations.
///
/// Prevents concurrent `update install` invocations from corrupting partition state and
/// boot flow configuration.
fn lock_update() -> SystemResult<nix::fcntl::Flock<File>> {
    fs::create_dir_all("/run/rugix").whatever("unable to create `/run/rugix`")?;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open("/run/rugix/update-lock")
        .whatever("unable to open update lock file")?;
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_file, errno)| errno)
        .whatever("another update is already in progress")
}

fn set_rugix_state_flag(name: &str, value: Option<&str>) -> SystemResult<()> {
    fs::write(
        Path::new("/run/rugix/state/.rugix").join(name),
        value.unwrap_or_default(),
    )
    .whatever("unable to write state flag")
    .field("name", name.to_owned())
}

fn clear_rugix_state_flag(name: &str) -> SystemResult<()> {
    let path = Path::new("/run/rugix/state/.rugix").join(name);
    fs::remove_file(&path).or_else(|error| match error.kind() {
        io::ErrorKind::NotFound => Ok(()),
        _ => Err(error
            .whatever("unable to clear state flag")
            .field("name", name.to_owned())),
    })?;
    if path.exists() {
        return Err(whatever!("unable to clear state flag").field("name", name.to_owned()));
    }
    Ok(())
}

pub fn main() -> SystemResult<()> {
    rugix_cli::CliBuilder::new().init();

    let args = Args::parse();
    let config = load_ctrl_config()?;

    match &args.command {
        Command::State(state_cmd) => match state_cmd {
            StateCommand::Reset {
                backup,
                backup_name,
            } => {
                if backup_name.is_some() && !*backup {
                    warn!("ignoring `--backup-name` option because `--backup` is not set");
                }

                let reset_hooks = HooksLoader::default()
                    .load_hooks("state-reset")
                    .whatever("unable to load `state-reset` hooks")?;
                reset_hooks
                    .run_hooks("prepare", Vars::new(), &Default::default())
                    .whatever("unable to run `state-reset/prepare` hooks")?;
                create_rugix_state_directory()?;
                if *backup {
                    let backup_name = backup_name.clone().unwrap_or_else(|| {
                        jiff::Timestamp::now()
                            .strftime("default.%Y%m%d%H%M%S")
                            .to_string()
                    });
                    let validated_backup_name = ValidatedRelativePath::new(backup_name)
                        .whatever("invalid state backup name")?;
                    if !validated_backup_name.is_single_component() {
                        bail!("state backup name must contain exactly one path component");
                    }
                    set_rugix_state_flag("reset-state", Some(validated_backup_name.as_str()))?;
                } else {
                    set_rugix_state_flag("reset-state", None)?;
                };
                reboot()?;
            }
            StateCommand::Overlay(overlay_cmd) => match overlay_cmd {
                OverlayCommand::ForcePersist { persist } => match persist {
                    Boolean::True => {
                        create_rugix_state_directory()?;
                        set_rugix_state_flag("force-persist-overlay", None)?;
                    }
                    Boolean::False => {
                        clear_rugix_state_flag("force-persist-overlay")?;
                    }
                },
            },
        },
        Command::Update(update_cmd) => {
            match update_cmd {
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
                    let _update_lock = lock_update()?;
                    let system = System::initialize()?;

                    if system.needs_commit()? {
                        bail!("system needs to be committed before installing an update");
                    }

                    // Find the entry where we are going to install the update to.
                    let boot_group = match boot_group {
                        Some(entry_name) => {
                            let Some(entry) = system.boot_entries().find_by_name(entry_name) else {
                                bail!("unable to find boot group {entry_name}")
                            };
                            Some(entry)
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

                    let retry_config = RetryConfig {
                        max_retries: *http_max_retries,
                        initial_backoff: Duration::from_secs(*http_retry_initial_backoff),
                        max_backoff: Duration::from_secs(*http_retry_max_backoff),
                    };
                    let bundle_options = BundleInstallOptions {
                        bundle_hash,
                        root_cert: root_cert.as_deref(),
                        insecure_skip_bundle_verification: *insecure_skip_bundle_verification,
                        insecure_allow_missing_block_index: *insecure_allow_missing_block_index,
                        skip_compatibility_check: *skip_compatibility_check,
                    };
                    let should_reboot = install_update_stream(
                        &system,
                        &config,
                        bundle,
                        boot_group.as_ref(),
                        bundle_options,
                        *keep_overlay,
                        *disable_range_queries,
                        retry_config,
                    )?;

                    let reboot_type = reboot_type.clone().unwrap_or(should_reboot);

                    match reboot_type {
                        UpdateRebootType::Yes => {
                            let (entry_idx, boot_group) = boot_group.unwrap();
                            info!(
                                "instructing boot flow to try booting into {:?}",
                                boot_group.name()
                            );
                            system
                                .boot_flow()
                                .set_try_next(&system, entry_idx)
                                .whatever("unable to set next boot group")?;
                            info!("rebooting");
                            system.reboot()?;
                        }
                        UpdateRebootType::No => { /* nothing to do */ }
                        UpdateRebootType::Set => {
                            let (entry_idx, boot_group) = boot_group.unwrap();
                            info!(
                                "instructing boot flow to try booting into {:?}",
                                boot_group.name()
                            );
                            system
                                .boot_flow()
                                .set_try_next(&system, entry_idx)
                                .whatever("unable to set next boot group")?;
                        }
                        UpdateRebootType::Deferred => {
                            set_flag(DEFERRED_SPARE_REBOOT_FLAG)?;
                        }
                    }
                }
            }
        }
        Command::System(sys_cmd) => match sys_cmd {
            SystemCommand::Info { json } => {
                let system = System::initialize()?;
                let output = system_state::state_from_system(&system)?;
                rugix_cli::json::print_json(&output, *json)
                    .whatever("unable to write system info to stdout")?;
            }
            SystemCommand::Commit => {
                let system = System::initialize()?;

                if system.needs_commit()? {
                    let hooks = HooksLoader::default()
                        .load_hooks("system-commit")
                        .whatever("unable to load `system-commit` hooks")?;
                    hooks
                        .run_hooks("pre-commit", Vars::new(), &Default::default())
                        .whatever("unable to run `pre-commit` hooks")?;
                    system.commit()?;
                    hooks
                        .run_hooks("post-commit", Vars::new(), &Default::default())
                        .whatever("unable to run `post-commit` hooks")?;
                } else {
                    info!("active boot group is already the default");
                }
            }
            SystemCommand::Reboot { spare } => {
                let system = System::initialize()?;
                if *spare {
                    if let Some((spare, _)) = system.spare_entry()? {
                        system
                            .boot_flow()
                            .set_try_next(&system, spare)
                            .whatever("unable to set next boot group")?;
                    }
                }
                system.reboot()?;
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
            ComponentsCommand::Check => match run_components_check() {
                Ok(true) => {}
                Ok(false) => std::process::exit(1),
                Err(report) => {
                    eprintln!("{report:?}");
                    std::process::exit(2);
                }
            },
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
                let boot_group = match group {
                    Some(entry_name) => {
                        let Some((group, _)) = system.boot_entries().find_by_name(entry_name)
                        else {
                            bail!("unable to find boot group {entry_name}")
                        };
                        group
                    }
                    None => system.require_active_boot_entry()?,
                };
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
                    system.root().as_ref().unwrap().device.clone()
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
        Command::Apps(cmd) => {
            warn!("edge application orchestration is experimental");
            let apps_config =
                crate::apps::config::load_apps_config().whatever("unable to load apps config")?;
            let apps_dir = crate::apps::config::apps_dir().to_owned();
            let manager = crate::apps::manager::AppManager::new(apps_dir, apps_config);
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
                    let bundle_options = BundleInstallOptions {
                        bundle_hash,
                        root_cert: root_cert.as_deref(),
                        insecure_skip_bundle_verification: *insecure_skip_bundle_verification,
                        insecure_allow_missing_block_index: *insecure_allow_missing_block_index,
                        skip_compatibility_check: *skip_compatibility_check,
                    };
                    if bundle.starts_with("http") {
                        let retry_config = RetryConfig {
                            max_retries: *http_max_retries,
                            initial_backoff: Duration::from_secs(*http_retry_initial_backoff),
                            max_backoff: Duration::from_secs(*http_retry_max_backoff),
                        };
                        let source = HttpSource::new(bundle, false, retry_config)
                            .whatever("unable to create HTTP source")?;
                        install_app_bundle(&config, &manager, source, bundle_options)?;
                    } else if bundle == "-" {
                        let source = ReaderSource::<_, SkipRead>::from_unbuffered(std::io::stdin());
                        install_app_bundle(&config, &manager, source, bundle_options)?;
                    } else {
                        let file = File::open(bundle).whatever("unable to open app bundle")?;
                        let source = ReaderSource::<_, SkipSeek>::from_unbuffered(file);
                        install_app_bundle(&config, &manager, source, bundle_options)?;
                    }
                }
                AppsCommand::List => {
                    use crate::config::output::AppListEntryOutput;
                    let apps = manager.list_apps().whatever("unable to list apps")?;
                    let entries: indexmap::IndexMap<String, AppListEntryOutput> = apps
                        .iter()
                        .map(|app| {
                            let status = resolve_app_status(manager.app_status(app).ok());
                            let generation = match manager.current_generation(app) {
                                Ok(gen) => gen,
                                Err(err) => {
                                    tracing::error!(app, error = ?err, "unable to read app state");
                                    None
                                }
                            };
                            let metadata = generation.and_then(|gen| {
                                manager.generation_dir(app, gen).ok().and_then(|gen_dir| {
                                    crate::apps::manager::AppManager::read_metadata(&gen_dir)
                                })
                            });
                            (
                                app.clone(),
                                AppListEntryOutput::new(status)
                                    .with_generation(generation)
                                    .with_metadata(metadata),
                            )
                        })
                        .collect();
                    rugix_cli::json::print_json(&entries, false)
                        .whatever("unable to write apps list to stdout")?;
                }
                AppsCommand::Info { app } => {
                    use crate::config::output::AppInfoOutput;
                    use crate::config::output::GenerationInfoOutput;
                    let status = resolve_app_status(manager.app_status(app).ok());
                    let generations = manager
                        .list_generations(app)
                        .whatever("unable to list generations")?;
                    let current = manager
                        .current_generation(app)
                        .whatever("unable to read app state")?;
                    let state = manager
                        .read_state(app)
                        .whatever("unable to read app state")?;
                    let gen_entries: Vec<_> = generations
                        .iter()
                        .map(|gen| {
                            let metadata = manager
                                .generation_dir(app, gen.meta.number)
                                .ok()
                                .and_then(|gen_dir| {
                                    crate::apps::manager::AppManager::read_metadata(&gen_dir)
                                });
                            GenerationInfoOutput::new(
                                gen.meta.number,
                                gen.meta.created_at.clone(),
                                gen.complete,
                                Some(gen.meta.number) == current,
                            )
                            .with_last_activated(gen.meta.last_activated.clone())
                            .with_metadata(metadata)
                        })
                        .collect();
                    let output = AppInfoOutput::new(app.clone(), status, state, gen_entries);
                    rugix_cli::json::print_json(&output, false)
                        .whatever("unable to write app info to stdout")?;
                }
                AppsCommand::Activate {
                    app,
                    generation,
                    skip_compatibility_check,
                } => {
                    let lock = manager.lock_app(app).whatever("unable to lock app")?;
                    let gen = match generation {
                        Some(n) => *n,
                        None => {
                            let Some(n) = manager
                                .last_activated_generation(app)
                                .whatever("unable to find last activated generation")?
                            else {
                                bail!("no previously activated generation found for {app}");
                            };
                            n
                        }
                    };
                    if !*skip_compatibility_check {
                        check_app_generation_compatibility(&manager, app, gen)?;
                    } else {
                        warn!("skipping app compatibility check");
                    }
                    manager
                        .activate_generation(&lock, app, gen)
                        .whatever("unable to activate generation")?;
                }
                AppsCommand::Deactivate {
                    app,
                    skip_compatibility_check,
                } => {
                    let lock = manager.lock_app(app).whatever("unable to lock app")?;
                    if !*skip_compatibility_check {
                        check_app_removal_compatibility(&manager, app)?;
                    } else {
                        warn!("skipping app compatibility check");
                    }
                    manager
                        .deactivate(&lock, app)
                        .whatever("unable to deactivate app")?;
                }
                AppsCommand::Start { app } => {
                    let lock = manager.lock_app(app).whatever("unable to lock app")?;
                    manager
                        .start_app(&lock, app)
                        .whatever("unable to start app workload")?;
                }
                AppsCommand::Stop { app } => {
                    let lock = manager.lock_app(app).whatever("unable to lock app")?;
                    manager
                        .stop_app(&lock, app)
                        .whatever("unable to stop app workload")?;
                }
                AppsCommand::Rollback {
                    app,
                    skip_compatibility_check,
                } => {
                    let lock = manager.lock_app(app).whatever("unable to lock app")?;
                    if !*skip_compatibility_check {
                        let generation = manager
                            .rollback_target_generation(app)
                            .whatever("unable to determine rollback target generation")?;
                        check_app_generation_compatibility(&manager, app, generation)?;
                    } else {
                        warn!("skipping app compatibility check");
                    }
                    manager
                        .rollback(&lock, app)
                        .whatever("unable to rollback app")?;
                }
                AppsCommand::Remove {
                    app,
                    skip_compatibility_check,
                } => {
                    let lock = manager.lock_app(app).whatever("unable to lock app")?;
                    if !*skip_compatibility_check {
                        check_app_removal_compatibility(&manager, app)?;
                    } else {
                        warn!("skipping app compatibility check");
                    }
                    manager
                        .remove_app(&lock, app)
                        .whatever("unable to remove app")?;
                }
                AppsCommand::Generations { app } => {
                    use crate::config::output::GenerationInfoOutput;
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
                    use crate::config::output::AppGcAppOutput;
                    let app_names = match app {
                        Some(name) => vec![name.clone()],
                        None => manager.list_apps().whatever("unable to list apps")?,
                    };
                    let mut results = indexmap::IndexMap::new();
                    for name in &app_names {
                        let lock = manager.lock_app(name).whatever("unable to lock app")?;
                        let removed = manager
                            .gc(&lock, name, *keep)
                            .whatever("unable to garbage collect")?;
                        results.insert(name.clone(), AppGcAppOutput::new(removed));
                    }
                    rugix_cli::json::print_json(&results, false)
                        .whatever("unable to write gc output to stdout")?;
                }
                AppsCommand::Recover => {
                    manager.recover_all().whatever("recovery failed")?;
                }
                AppsCommand::CreateIndex {
                    app,
                    chunker,
                    hash_algorithm,
                    path,
                    generation,
                } => {
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
                AppsCommand::ServiceManager(sm_cmd) => match sm_cmd {
                    AppsServiceManagerCommand::Systemd(systemd_cmd) => match systemd_cmd {
                        AppsSystemdCommand::RestoreUnits => {
                            crate::apps::systemd::restore::restore_units(&manager)
                                .whatever("failed to restore app units")?;
                        }
                    },
                },
            }
        }
    }
    Ok(())
}

fn run_components_check() -> SystemResult<bool> {
    let components = crate::components::InstalledComponents::load()?;
    let output = components.check_output();
    let consistent = output.consistent;
    rugix_cli::json::print_json(&output, false)
        .whatever("unable to write component check report to stdout")?;
    Ok(consistent)
}

/// Resolve an optional [`AppStatus`], defaulting to `Unknown`.
fn resolve_app_status(
    status: Option<crate::apps::orchestrators::AppStatus>,
) -> crate::apps::orchestrators::AppStatus {
    status.unwrap_or(crate::apps::orchestrators::AppStatus::Unknown)
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

#[derive(Debug, Clone, Copy)]
struct BundleInstallOptions<'a> {
    bundle_hash: &'a Option<HashDigest>,
    root_cert: Option<&'a Path>,
    insecure_skip_bundle_verification: bool,
    insecure_allow_missing_block_index: bool,
    skip_compatibility_check: bool,
}

fn install_app_bundle<S: BundleSource>(
    config: &Config,
    app_manager: &crate::apps::manager::AppManager,
    bundle_source: S,
    options: BundleInstallOptions<'_>,
) -> SystemResult<()> {
    let mut bundle_reader =
        rugix_bundle::reader::BundleReader::start(bundle_source, options.bundle_hash.clone())
            .whatever("unable to read app bundle")?;

    let root_cert = options.root_cert.or_else(|| {
        config.signatures.as_ref().and_then(|c| {
            if c.roots.len() > 1 {
                warn!("multiple root certificates in config, using only the first")
            };
            c.roots.first().map(Path::new)
        })
    });

    // If a bundle hash has been specified, then the bundle will be verified against that hash
    // by the reader. Otherwise, try signature verification.
    let bundle_verified =
        options.bundle_hash.is_some() || verify_bundle_signature(root_cert, &bundle_reader)?;
    if !bundle_verified && !options.insecure_skip_bundle_verification {
        bail!("bundle verification failed, refusing to install app bundle");
    }

    validate_app_bundle_header(bundle_reader.header())?;

    let bundle_components = bundle_reader.header().components.clone();
    if let Some(components) = &bundle_components {
        crate::components::validate_bundle_components(components)?;
    }
    let touched_apps = touched_apps(bundle_reader.header());
    let bundle_components_app = if bundle_components.is_some() {
        Some(app_bundle_components_owner(bundle_reader.header())?)
    } else {
        None
    };

    // Advisory locks held for the duration of the install, one per app.
    let mut app_locks: std::collections::HashMap<String, crate::apps::manager::AppLock> =
        std::collections::HashMap::new();
    for app in &touched_apps {
        let lock = app_manager.lock_app(app).whatever("unable to lock app")?;
        app_locks.insert(app.clone(), lock);
    }

    if !options.skip_compatibility_check {
        check_app_bundle_compatibility(&bundle_reader, &touched_apps)?;
    } else {
        warn!("skipping app bundle compatibility check");
    }

    let mut app_generations: std::collections::HashMap<String, (u64, PathBuf)> =
        std::collections::HashMap::new();
    // Accumulated payload hashes per app, keyed by (app_name, path).
    let mut payload_states: std::collections::HashMap<
        String,
        std::collections::HashMap<String, payload_db::PayloadState>,
    > = std::collections::HashMap::new();

    let mut progress = |_source: &_| {};

    // Phase 1: extract all app payloads into generation directories.
    while let Some(payload) = bundle_reader
        .next_payload()
        .whatever("unable to read payload")?
    {
        let payload_entry = payload.entry();
        if let Some(type_app_file) = &payload_entry.type_app_file {
            let app_name = type_app_file.app.clone();
            let payload_path = ValidatedRelativePath::new(type_app_file.path.clone())
                .whatever("invalid app-file path")?;
            let file_mode = type_app_file.mode;
            let delta_encoding = payload_entry.delta_encoding.clone();
            if !app_generations.contains_key(&app_name) {
                let lock = app_locks
                    .get(&app_name)
                    .expect("app payload must be listed in bundle header");
                let gen = app_manager
                    .create_generation(lock, &app_name)
                    .whatever("unable to create app generation")?;
                app_generations.insert(app_name.clone(), gen);
            }
            let (_, gen_dir) = &app_generations[&app_name];
            let gen_dir = gen_dir.clone();
            ensure_no_symlink_components(&gen_dir, &payload_path)
                .whatever("app-file path contains a symbolic link")?;
            let file_path = gen_dir.join(&payload_path);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).whatever("unable to create parent directory")?;
            }

            // Set up block provider for block-encoded payloads.
            let block_provider = if !options.insecure_allow_missing_block_index {
                let block_encoding = payload.header().block_encoding.as_ref().ok_or_else(|| {
                    whatever!(
                        "payload {} does not have a block index, refusing to install",
                        payload.idx()
                    )
                })?;
                let mut provider = BlockProvider::new(
                    block_encoding.chunker.clone(),
                    block_encoding.hash_algorithm,
                );
                // Add block indices from existing generations of the same app.
                for gen in app_manager.list_generations(&app_name).unwrap_or_default() {
                    if !gen.complete {
                        continue;
                    }
                    let old_gen_dir = app_manager
                        .generation_dir(&app_name, gen.meta.number)
                        .whatever("invalid app name")?;
                    let indices =
                        payload_db::get_app_file_indices(&old_gen_dir, payload_path.as_str())
                            .unwrap_or_default();
                    if !indices.is_empty() {
                        let data_file = old_gen_dir.join(&payload_path);
                        if data_file.exists() {
                            if let Err(e) = provider.add_indices(&indices, data_file) {
                                warn!("failed to load app-file block indices: {e:?}");
                            }
                        }
                    }
                }
                Some(provider)
            } else {
                None
            };

            let decoded_payload_info = if let Some(delta_encoding) = delta_encoding {
                info!(
                    app = app_name,
                    path = %payload_path,
                    "installing delta app file payload {}",
                    payload.idx()
                );
                if delta_encoding.inputs.len() != 1 {
                    bail!("unsupported number of delta encoding inputs");
                }
                let input = &delta_encoding.inputs[0];
                // Find the delta source in existing generations.
                let mut source_path = None;
                'generations: for gen in app_manager.list_generations(&app_name).unwrap_or_default()
                {
                    if !gen.complete {
                        continue;
                    }
                    let old_gen_dir = app_manager
                        .generation_dir(&app_name, gen.meta.number)
                        .whatever("invalid app name")?;
                    let old_states =
                        crate::apps::manager::AppManager::load_payload_states(&old_gen_dir);
                    let Some(old_state) = old_states.get(payload_path.as_str()) else {
                        continue;
                    };
                    for input_hash in &input.hashes {
                        if let Some(stored_hash) = old_state.hashes.get(&input_hash.algorithm()) {
                            if stored_hash == input_hash {
                                let candidate = old_gen_dir.join(&payload_path);
                                if candidate.exists() {
                                    source_path = Some(candidate);
                                    break 'generations;
                                }
                            }
                        }
                    }
                }
                let Some(source_path) = source_path else {
                    bail!("no suitable delta source found for app-file {payload_path}");
                };
                match delta_encoding.format {
                    rugix_bundle::manifest::DeltaEncodingFormat::Xdelta => { /* ok */ }
                }
                let target = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .read(true)
                    .write(true)
                    .open(&file_path)
                    .whatever("unable to open app file target")?;
                let mut target_writer =
                    HashWriter::new(delta_encoding.original_hash.algorithm(), target);
                let (mut patch_reader, patch_writer) = buffered_pipe(8192);
                let (decode_result, xdelta_result) = std::thread::scope(|scope| {
                    let target_writer = &mut target_writer;
                    let handle = scope.spawn(move || {
                        xdelta_decompress(&source_path, &mut patch_reader, target_writer)
                    });
                    let decode_result = payload.decode_into(
                        BufferedPipeTarget {
                            writer: patch_writer,
                        },
                        block_provider
                            .as_ref()
                            .map(|p| p as &dyn StoredBlockProvider),
                        &mut progress,
                    );
                    (decode_result, handle.join().unwrap())
                });
                decode_result.whatever("unable to decode delta app payload")?;
                xdelta_result.whatever("unable to decompress delta app payload")?;
                let (target_hash, target_size) = target_writer
                    .finalize_synced()
                    .whatever("unable to synchronize delta app payload")?;
                if target_hash != delta_encoding.original_hash {
                    bail!("decoded app file data does not match hash");
                }
                DecodedPayloadInfo {
                    hash: target_hash,
                    size: target_size.into(),
                }
            } else {
                info!(
                    app = app_name,
                    path = %payload_path,
                    "extracting app file payload {}",
                    payload.idx()
                );
                let target = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .read(true)
                    .write(true)
                    .open(&file_path)
                    .whatever("unable to open app file target")?;
                payload
                    .decode_into(
                        target,
                        block_provider
                            .as_ref()
                            .map(|p| p as &dyn StoredBlockProvider),
                        &mut progress,
                    )
                    .whatever("unable to decode app payload")?
            };

            // Apply file mode if specified in the payload metadata.
            #[cfg(unix)]
            if let Some(mode) = file_mode {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&file_path, fs::Permissions::from_mode(mode))
                    .whatever("unable to set app file permissions")?;
            }

            // Save payload hash for this app-file.
            payload_states.entry(app_name.clone()).or_default().insert(
                payload_path.as_str().to_owned(),
                payload_db::PayloadState {
                    hashes: [(
                        decoded_payload_info.hash.algorithm(),
                        decoded_payload_info.hash,
                    )]
                    .into_iter()
                    .collect(),
                    size: Some(decoded_payload_info.size),
                    updated_at: Some(jiff::Timestamp::now()),
                },
            );

            continue;
        }
        if let Some(type_app_archive) = &payload_entry.type_app_archive {
            if !app_generations.contains_key(&type_app_archive.app) {
                let lock = app_locks
                    .get(&type_app_archive.app)
                    .expect("app payload must be listed in bundle header");
                let gen = app_manager
                    .create_generation(lock, &type_app_archive.app)
                    .whatever("unable to create app generation")?;
                app_generations.insert(type_app_archive.app.clone(), gen);
            }
            let (_, gen_dir) = &app_generations[&type_app_archive.app];
            info!(
                app = type_app_archive.app,
                "extracting app archive payload {}",
                payload.idx()
            );
            let tmp_tar = tempfile::NamedTempFile::new()
                .whatever("unable to create temporary file for archive")?;
            let tmp_file = tmp_tar
                .as_file()
                .try_clone()
                .whatever("unable to clone temp file handle")?;
            let block_provider = if !options.insecure_allow_missing_block_index {
                let block_encoding = payload.header().block_encoding.as_ref().ok_or_else(|| {
                    whatever!(
                        "payload {} does not have a block index, refusing to install",
                        payload.idx()
                    )
                })?;
                let provider = BlockProvider::new(
                    block_encoding.chunker.clone(),
                    block_encoding.hash_algorithm,
                );
                Some(provider)
            } else {
                None
            };
            payload
                .decode_into(
                    tmp_file,
                    block_provider
                        .as_ref()
                        .map(|p| p as &dyn StoredBlockProvider),
                    &mut progress,
                )
                .whatever("unable to decode app archive payload")?;
            // Extract the tar archive into the generation directory.
            let tar_file = std::fs::File::open(tmp_tar.path())
                .whatever("unable to reopen archive for extraction")?;
            validate_app_archive(tar_file)?;
            let tar_file = std::fs::File::open(tmp_tar.path())
                .whatever("unable to reopen validated archive for extraction")?;
            let mut archive = tar::Archive::new(tar_file);
            archive
                .unpack(gen_dir)
                .whatever("unable to extract app archive")?;
            continue;
        }
        payload.skip().whatever("unable to skip payload")?;
    }

    if app_generations.is_empty() {
        warn!("bundle contained no app payloads");
        return Ok(());
    }

    // Phase 2: save payload states, finalize, and activate.
    for (app_name, (gen_number, gen_dir)) in &app_generations {
        // Persist payload hashes for this generation.
        if let Some(states) = payload_states.get(app_name) {
            crate::apps::manager::AppManager::save_payload_states(gen_dir, states)
                .whatever("unable to save app payload states")?;
        }
        info!(app = %app_name, generation = gen_number, "finalizing app generation");
        if bundle_components_app.as_ref() == Some(app_name) {
            let bundle_components = bundle_components
                .as_ref()
                .expect("bundle components owner requires bundle components");
            crate::components::write_bundle_components(
                bundle_components,
                &gen_dir.join(".rugix/components"),
            )
            .whatever("unable to install app component metadata")?;
        }
        app_manager
            .write_generation_metadata(
                gen_dir,
                &crate::config::apps::AppGeneration::new(
                    *gen_number,
                    jiff::Timestamp::now().to_string(),
                ),
            )
            .whatever("unable to write generation metadata")?;
        rugix_common::fsutils::sync_tree(gen_dir)
            .whatever("unable to synchronize app generation")?;
        crate::apps::manager::AppManager::mark_complete(gen_dir)
            .whatever("unable to mark generation as complete")?;
        let lock = &app_locks[app_name];
        app_manager
            .activate_generation(lock, app_name, *gen_number)
            .whatever("unable to activate app generation")?;
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct AppPayloadDelivery<'a> {
    app_file: Option<(&'a str, &'a str)>,
    app_archive: Option<&'a str>,
    slot: bool,
    execute: bool,
}

fn validate_app_bundle_header(header: &format::BundleHeader) -> SystemResult<()> {
    let deliveries = header
        .payload_index
        .iter()
        .map(|entry| AppPayloadDelivery {
            app_file: entry
                .type_app_file
                .as_ref()
                .map(|delivery| (delivery.app.as_str(), delivery.path.as_str())),
            app_archive: entry
                .type_app_archive
                .as_ref()
                .map(|delivery| delivery.app.as_str()),
            slot: entry.type_slot.is_some(),
            execute: entry.type_execute.is_some(),
        })
        .collect::<Vec<_>>();
    validate_app_deliveries(&deliveries)
}

fn validate_app_deliveries(deliveries: &[AppPayloadDelivery<'_>]) -> SystemResult<()> {
    if deliveries.is_empty() {
        bail!("app bundle does not contain any payloads");
    }
    for (payload_idx, delivery) in deliveries.iter().enumerate() {
        let delivery_count = [
            delivery.app_file.is_some(),
            delivery.app_archive.is_some(),
            delivery.slot,
            delivery.execute,
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if delivery_count != 1 {
            bail!(
                "app bundle payload {payload_idx} must declare exactly one delivery type, found {delivery_count}"
            );
        }
        if delivery.slot || delivery.execute {
            bail!("app bundle payload {payload_idx} is not an app payload");
        }
        let (app, path) = match (delivery.app_file, delivery.app_archive) {
            (Some((app, path)), None) => (app, Some(path)),
            (None, Some(app)) => (app, None),
            _ => unreachable!("delivery count validated above"),
        };
        rugix_bundle::manifest::validate_app_name(app)
            .whatever("invalid app name in bundle payload")?;
        if let Some(path) = path {
            ValidatedRelativePath::new(path).whatever("invalid app-file path in bundle payload")?;
        }
    }
    Ok(())
}

fn validate_app_archive(file: File) -> SystemResult<()> {
    let mut archive = tar::Archive::new(file);
    let mut paths = Vec::new();
    let mut link_paths = HashSet::new();
    let mut unique_paths = HashSet::new();
    for entry in archive
        .entries()
        .whatever("unable to read app archive entries")?
    {
        let entry = entry.whatever("unable to read app archive entry")?;
        let path = entry.path().whatever("unable to read app archive path")?;
        let path = path
            .to_str()
            .ok_or_else(|| whatever!("app archive path is not UTF-8"))?;
        let path = ValidatedRelativePath::new(path).whatever("invalid path in app archive")?;
        if !unique_paths.insert(path.as_str().to_owned()) {
            bail!("duplicate path in app archive: {path}");
        }
        if entry.header().entry_type().is_symlink() || entry.header().entry_type().is_hard_link() {
            let target = entry
                .link_name()
                .whatever("unable to read app archive link target")?
                .ok_or_else(|| whatever!("app archive link has no target"))?;
            let target = target
                .to_str()
                .ok_or_else(|| whatever!("app archive link target is not UTF-8"))?;
            ValidatedRelativePath::new(target).whatever("invalid link target in app archive")?;
            link_paths.insert(path.as_str().to_owned());
        }
        paths.push(path);
    }

    for path in &paths {
        if link_paths.iter().any(|link| {
            path.as_str() != link
                && path
                    .as_str()
                    .strip_prefix(link)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) {
            bail!("app archive contains a path beneath a symbolic or hard link: {path}");
        }
    }
    Ok(())
}

#[expect(clippy::too_many_arguments)]
fn install_update_stream(
    system: &System,
    config: &Config,
    bundle: &String,
    boot_group: Option<&(BootGroupIdx, &BootGroup)>,
    options: BundleInstallOptions<'_>,
    keep_overlay: bool,
    disable_range_queries: bool,
    retry_config: RetryConfig,
) -> SystemResult<UpdateRebootType> {
    if bundle.starts_with("http") {
        let mut has_indices = false;
        for (_, slot) in system.slots().iter() {
            has_indices |= payload_db::get_stored_indices(slot.name())
                .map(|indices| !indices.is_empty())
                .unwrap_or_default();
            if has_indices {
                break;
            }
        }

        let mut bundle_source =
            HttpSource::new(bundle, !disable_range_queries && has_indices, retry_config)?;
        let should_reboot = install_update_bundle(
            system,
            config,
            &mut bundle_source,
            boot_group,
            options,
            keep_overlay,
        )?;
        let stats = bundle_source.get_download_stats();
        info!(
            "downloaded {:.1}% ({}/{}) of the full bundle",
            stats.download_ratio() * 100.0,
            stats.bytes_read,
            stats.total_bytes(),
        );
        return Ok(should_reboot);
    }
    if bundle == "-" {
        let bundle_source = ReaderSource::<_, SkipRead>::from_unbuffered(io::stdin());
        install_update_bundle(
            system,
            config,
            bundle_source,
            boot_group,
            options,
            keep_overlay,
        )
    } else {
        let file = File::open(bundle).whatever("error opening image")?;
        let bundle_source = ReaderSource::<_, SkipSeek>::from_unbuffered(file);
        install_update_bundle(
            system,
            config,
            bundle_source,
            boot_group,
            options,
            keep_overlay,
        )
    }
}

pub struct UpdateState {
    bytes_read: u64,
    bytes_total: u64,
}

pub struct UpdateStatus {
    state: Mutex<UpdateState>,
}

#[derive(Debug, Default)]
struct ProgressCursors {
    hook: f64,
    json: f64,
}

impl ProgressCursors {
    fn should_emit_hook(&self, progress: f64) -> bool {
        (progress >= 100.0 && self.hook < 100.0) || progress - self.hook > 0.9
    }

    fn should_emit_json(&self, progress: f64) -> bool {
        (progress >= 100.0 && self.json < 100.0) || progress - self.json > 0.4
    }

    fn mark_hook_emitted(&mut self, progress: f64) {
        self.hook = progress;
    }

    fn mark_json_emitted(&mut self, progress: f64) {
        self.json = progress;
    }
}

impl StatusSegment for UpdateStatus {
    fn draw(&self, ctx: &mut rugix_cli::DrawCtx) {
        let state = self.state.lock().unwrap();
        if state.bytes_total > 0 {
            ProgressBar::new(state.bytes_read, state.bytes_total).draw(ctx);
        } else {
            ProgressSpinner::new().draw(ctx);
        }
    }
}

fn verify_bundle_signature<S: BundleSource>(
    root_cert: Option<&Path>,
    bundle_reader: &BundleReader<S>,
) -> SystemResult<bool> {
    let Some(root_cert) = root_cert else {
        return Ok(false);
    };
    let Some(signatures) = bundle_reader.signatures() else {
        warn!("root certificate configured but no signatures found");
        return Ok(false);
    };
    let cert_pem = std::fs::read(root_cert).whatever("unable to read root certificate")?;
    let verifier =
        rugix_pki::CmsVerifier::new(&cert_pem).whatever("unable to create CMS verifier")?;
    info!("checking bundle signatures");
    for signature in signatures.cms_signatures.iter() {
        let result = match verifier.verify(&signature.raw) {
            Ok(result) => result,
            Err(error) => {
                info!("signature verification failed: {error}");
                continue;
            }
        };
        let signed_metadata = decode_slice::<format::SignedMetadata>(&result.content)
            .whatever("unable to decode signed metadata")?;
        if signed_metadata.header_hash
            == bundle_reader.header_hash(signed_metadata.header_hash.algorithm())
        {
            info!("found valid signature");
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_system_update_compatibility<S: BundleSource>(
    bundle_reader: &BundleReader<S>,
) -> SystemResult<()> {
    let Some(bundle_components) = bundle_reader.header().components.as_ref() else {
        warn!("update bundle does not declare components, skipping compatibility check");
        return Ok(());
    };
    let installed = crate::components::InstalledComponents::load()
        .whatever("unable to load installed components")?;
    let output = if bundle_reader.header().is_incremental {
        installed
            .check_incremental_update(bundle_components)
            .whatever("unable to check incremental update compatibility")?
    } else {
        installed
            .check_system_update(bundle_components)
            .whatever("unable to check system update compatibility")?
    };
    require_compatible_components(output)
}

fn check_app_bundle_compatibility<S: BundleSource>(
    bundle_reader: &BundleReader<S>,
    touched_apps: &[String],
) -> SystemResult<()> {
    let bundle_components = bundle_reader.header().components.as_ref();
    if touched_apps.is_empty() {
        warn!("app bundle does not contain app payloads, skipping compatibility check");
        return Ok(());
    }
    if bundle_components.is_none() {
        warn!("app bundle does not declare components, checking removal of touched app components");
    }
    let installed = crate::components::InstalledComponents::load()
        .whatever("unable to load installed components")?;
    let output = installed
        .check_app_update(touched_apps, bundle_components)
        .whatever("unable to check app bundle compatibility")?;
    require_compatible_components(output)
}

fn check_app_generation_compatibility(
    app_manager: &crate::apps::manager::AppManager,
    app: &str,
    generation: u64,
) -> SystemResult<()> {
    let installed = crate::components::InstalledComponents::load()
        .whatever("unable to load installed components")?;
    let component_root = app_manager
        .generation_dir(app, generation)
        .whatever("invalid app name")?
        .join(".rugix/components");
    let output = installed
        .check_app_generation(app, generation, component_root)
        .whatever("unable to check app generation compatibility")?;
    require_compatible_components(output)
}

fn check_app_removal_compatibility(
    app_manager: &crate::apps::manager::AppManager,
    app: &str,
) -> SystemResult<()> {
    if app_manager
        .current_generation(app)
        .whatever("unable to read app state")?
        .is_none()
    {
        return Ok(());
    }
    let installed = crate::components::InstalledComponents::load()
        .whatever("unable to load installed components")?;
    let output = installed.check_app_removal(app);
    require_compatible_components(output)
}

fn require_compatible_components(output: ComponentsCheckOutput) -> SystemResult<()> {
    if output.consistent {
        return Ok(());
    }
    rugix_cli::json::print_json(&output, false)
        .whatever("unable to write component compatibility report to stdout")?;
    bail!("component compatibility check failed");
}

fn touched_apps(header: &format::BundleHeader) -> Vec<String> {
    header
        .payload_index
        .iter()
        .filter_map(|entry| {
            entry
                .type_app_file
                .as_ref()
                .map(|app_file| app_file.app.as_str())
                .or_else(|| {
                    entry
                        .type_app_archive
                        .as_ref()
                        .map(|app_archive| app_archive.app.as_str())
                })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn app_bundle_components_owner(header: &format::BundleHeader) -> SystemResult<String> {
    let touched_apps = touched_apps(header);
    match touched_apps.as_slice() {
        [] => bail!("app bundle declares components but does not contain app payloads"),
        [app] => Ok(app.clone()),
        _ => bail!(
            "app bundle declares components for multiple apps, which is not supported yet: {:?}",
            touched_apps
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemPayloadDestination {
    Slot(SlotIdx),
    Execute,
}

#[derive(Debug, Clone, Copy)]
struct PayloadDelivery<'a> {
    slot: Option<&'a str>,
    execute: bool,
    app_file: bool,
    app_archive: bool,
}

fn preflight_system_payloads(
    header: &format::BundleHeader,
    slots: &SystemSlots,
    boot_group: Option<&BootGroup>,
) -> SystemResult<Vec<SystemPayloadDestination>> {
    let deliveries = header
        .payload_index
        .iter()
        .map(|entry| PayloadDelivery {
            slot: entry
                .type_slot
                .as_ref()
                .map(|delivery| delivery.slot.as_str()),
            execute: entry.type_execute.is_some(),
            app_file: entry.type_app_file.is_some(),
            app_archive: entry.type_app_archive.is_some(),
        })
        .collect::<Vec<_>>();
    preflight_system_deliveries(header.is_incremental, &deliveries, slots, boot_group)
}

fn preflight_system_deliveries(
    is_incremental: bool,
    deliveries: &[PayloadDelivery<'_>],
    slots: &SystemSlots,
    boot_group: Option<&BootGroup>,
) -> SystemResult<Vec<SystemPayloadDestination>> {
    if !is_incremental && boot_group.is_none() {
        bail!("full system updates require the specification of a boot group");
    }

    let mut destinations = Vec::with_capacity(deliveries.len());
    let mut targeted_slots = HashSet::new();
    let mut system_payloads = 0usize;

    for (payload_idx, delivery) in deliveries.iter().enumerate() {
        let delivery_type_count = [
            delivery.slot.is_some(),
            delivery.execute,
            delivery.app_file,
            delivery.app_archive,
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if delivery_type_count != 1 {
            bail!(
                "bundle payload {payload_idx} must declare exactly one delivery type, found {delivery_type_count}"
            );
        }

        if delivery.app_file || delivery.app_archive {
            bail!(
                "bundle payload {payload_idx} is an app payload and cannot be installed as a system update"
            );
        }

        if let Some(slot_name) = delivery.slot {
            let slot_idx = boot_group
                .and_then(|group| group.get_slot(slot_name))
                .or_else(|| slots.find_by_name(slot_name).map(|(idx, _)| idx))
                .ok_or_else(|| {
                    whatever!(
                        "unknown destination slot {:?} for bundle payload {payload_idx}",
                        slot_name
                    )
                })?;
            let slot = &slots[slot_idx];
            if !slot.is_available() {
                bail!(
                    "destination slot {:?} for bundle payload {payload_idx} is unavailable",
                    slot.name()
                );
            }
            if slot.active() {
                bail!(
                    "refusing to install bundle payload {payload_idx} to active slot {:?}",
                    slot.name()
                );
            }
            if !targeted_slots.insert(slot_idx) {
                bail!(
                    "multiple bundle payloads resolve to destination slot {:?}",
                    slot.name()
                );
            }
            system_payloads += 1;
            destinations.push(SystemPayloadDestination::Slot(slot_idx));
        } else if delivery.execute {
            destinations.push(SystemPayloadDestination::Execute);
        } else {
            unreachable!("delivery type was validated above");
        }
    }

    if destinations.is_empty() {
        bail!("bundle does not contain any payloads applicable to a system update");
    }
    if !is_incremental && system_payloads == 0 {
        bail!("full system update does not contain a system-slot payload");
    }
    Ok(destinations)
}

fn clear_target_overlay(path: &Path) -> SystemResult<()> {
    clear_target_overlay_with(path, |path| fs::remove_dir_all(path))
}

fn clear_target_overlay_with<F>(path: &Path, remove: F) -> SystemResult<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    match remove(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error
            .whatever("unable to clear target boot-group overlay")
            .field("path", path.display().to_string())),
    }
}

fn install_update_bundle<R: BundleSource>(
    system: &System,
    config: &Config,
    bundle_source: R,
    boot_group: Option<&(BootGroupIdx, &BootGroup)>,
    options: BundleInstallOptions<'_>,
    keep_overlay: bool,
) -> SystemResult<UpdateRebootType> {
    let mut bundle_reader =
        rugix_bundle::reader::BundleReader::start(bundle_source, options.bundle_hash.clone())
            .whatever("unable to read bundle")?;

    let root_cert = options.root_cert.or_else(|| {
        config.signatures.as_ref().and_then(|c| {
            if c.roots.len() > 1 {
                warn!("multiple root certificates in config, using only the first")
            };
            c.roots.first().map(Path::new)
        })
    });

    // If a bundle hash has been specified, then the bundle will be verified against that hash
    // by the reader.
    let bundle_verified =
        options.bundle_hash.is_some() || verify_bundle_signature(root_cert, &bundle_reader)?;

    if !bundle_verified && !options.insecure_skip_bundle_verification {
        bail!("bundle verification failed, refusing to install update");
    }

    if !options.skip_compatibility_check {
        check_system_update_compatibility(&bundle_reader)?;
    } else {
        warn!("skipping system update compatibility check");
    }

    let payload_destinations = preflight_system_payloads(
        bundle_reader.header(),
        system.slots(),
        boot_group.map(|(_, group)| *group),
    )?;

    let update_hooks = HooksLoader::default()
        .load_hooks("update-install")
        .whatever("unable to load `update-install` hooks")?;
    let hook_vars = vars! {
        RUGIX_BOOT_GROUP = boot_group.map(|g| g.1.name()).unwrap_or(""),
    };
    update_hooks
        .run_hooks("pre-update", hook_vars.clone(), &Default::default())
        .whatever("error running `pre-update` hooks")?;

    if !keep_overlay {
        if let Some(boot_group) = &boot_group {
            let spare_overlay_dir = overlay_dir(boot_group.1);
            clear_target_overlay(&spare_overlay_dir)?;
        }
    }

    if !bundle_reader.header().is_incremental {
        let (entry_idx, _) = boot_group.expect("boot group validated during preflight");
        system
            .boot_flow()
            .pre_install(system, *entry_idx)
            .whatever("error executing pre-install step")?;
    }

    let update_status = rugix_cli::add_status(UpdateStatus {
        state: Mutex::new(UpdateState {
            bytes_read: 0,
            bytes_total: 0,
        }),
    });

    let mut progress_cursors = ProgressCursors::default();
    let hooks = HooksLoader::default()
        .load_hooks("update-install")
        .whatever("unable to load `update-install` hooks")?;
    let mut emit_progress = |current_progress: f64| {
        if progress_cursors.should_emit_hook(current_progress) {
            let hook_vars = vars! {
                RUGIX_UPDATE_PROGRESS = format!("{current_progress:.2}")
            };
            match hooks.run_hooks(
                "progress",
                hook_vars,
                RunOptions::default().with_silent(true),
            ) {
                Ok(()) => progress_cursors.mark_hook_emitted(current_progress),
                Err(error) => {
                    warn!("error running 'update-install/progress' hooks: {error:?}");
                }
            }
        }
        if rugix_cli::stdout_is_piped() && progress_cursors.should_emit_json(current_progress) {
            let event = Event::UpdateProgress(UpdateProgressEvent {
                progress: current_progress,
            });
            let result = serde_json::to_vec(&event)
                .map_err(io::Error::other)
                .and_then(|mut bytes| {
                    bytes.push(b'\n');
                    std::io::stdout().write_all(&bytes)
                });
            match result {
                Ok(()) => progress_cursors.mark_json_emitted(current_progress),
                Err(error) => warn!("unable to emit JSON update progress: {error}"),
            }
        }
    };
    let mut progress = {
        |source: &R| {
            let Some(bytes_total) = source.bytes_total() else {
                return;
            };
            if bytes_total.raw == 0 {
                return;
            }
            let Some(bytes_read) = source.bytes_read() else {
                return;
            };
            let current_progress =
                ((bytes_read.raw as f64) / (bytes_total.raw as f64) * 100.0).min(100.0);
            {
                let mut update_state = update_status.state.lock().unwrap();
                update_state.bytes_read = bytes_read.raw;
                update_state.bytes_total = bytes_total.raw;
            }
            emit_progress(current_progress);
        }
    };

    while let Some(payload) = bundle_reader
        .next_payload()
        .whatever("unable to read payload")?
    {
        let payload_entry = payload.entry();
        let destination = payload_destinations
            .get(payload.idx())
            .copied()
            .ok_or_else(|| {
                whatever!("payload {} is missing from the bundle index", payload.idx())
            })?;
        if let SystemPayloadDestination::Slot(slot) = destination {
            let slot = &system.slots()[slot];
            info!(
                "installing bundle payload {} to slot {}",
                payload.idx(),
                slot.name()
            );
            payload_db::erase(slot.name())?;
            let block_provider = if !options.insecure_allow_missing_block_index {
                let block_encoding = payload.header().block_encoding.as_ref().ok_or_else(|| {
                    whatever!(
                        "payload {} does not have a block index, refusing to install",
                        payload.idx()
                    )
                })?;
                let mut provider = BlockProvider::new(
                    block_encoding.chunker.clone(),
                    block_encoding.hash_algorithm,
                );
                // Since we erased all the indices of the target slot, it
                // is fine to also add the target slot here.
                for (_, slot) in system.slots().iter() {
                    match slot.kind() {
                        SlotKind::Block(block_slot) => {
                            let Some(device) = block_slot.device() else {
                                continue;
                            };
                            provider.add_slot(slot.name(), device.path().to_path_buf())?;
                        }
                        SlotKind::File { path } => {
                            provider.add_slot(slot.name(), path.to_path_buf())?;
                        }
                        SlotKind::Custom { .. } => { /* nothing to do */ }
                    }
                }
                Some(provider)
            } else {
                None
            };
            // If the target is a file on the config partition, ensure
            // it is writable for the duration of the payload write.
            let _write_guard = if let SlotKind::File { path } = slot.kind() {
                system
                    .config_partition()
                    .filter(|cp| path.starts_with(cp.path()))
                    .map(|cp| cp.acquire_write_guard())
                    .transpose()
                    .whatever("unable to make config partition writable")?
            } else {
                None
            };
            let decoded_payload_info = if let Some(delta_encoding) = &payload_entry.delta_encoding {
                let delta_encoding = delta_encoding.clone();
                if delta_encoding.inputs.len() != 1 {
                    bail!("unsupported number of delta encoding inputs");
                }
                let input = &delta_encoding.inputs[0];
                let mut source = None;
                'slots: for (_, delta_slot) in system.slots().iter() {
                    let Ok(Some(slot_state)) = payload_db::get_stored_state(delta_slot.name())
                    else {
                        continue;
                    };
                    for input_hash in &input.hashes {
                        let Some(slot_hash) = slot_state.hashes.get(&input_hash.algorithm()) else {
                            trace!(slot_name = delta_slot.name(), algorithm = ?input_hash.algorithm(), "no hash found");
                            continue;
                        };
                        if slot_hash == input_hash {
                            // We found the slot to use as a source.
                            source = Some(delta_slot);
                            trace!(slot_name = delta_slot.name(), "delta source found");
                            break 'slots;
                        } else {
                            trace!(slot_name = delta_slot.name(), %slot_hash, %input_hash, "hash does not match");
                        }
                    }
                }
                let Some(source) = source else {
                    bail!("no slot suitable delta source found");
                };
                // This is here so that we get an error when introducing additional formats.
                match delta_encoding.format {
                    rugix_bundle::manifest::DeltaEncodingFormat::Xdelta => { /* do nothing */ }
                }
                let source = match source.kind() {
                    SlotKind::Block(_) => source.require_available_block()?.path().to_owned(),
                    SlotKind::File { path } => path.to_owned(),
                    SlotKind::Custom { .. } => {
                        bail!("source slot must not be a custom slot");
                    }
                };
                let target = match slot.kind() {
                    SlotKind::Block(_) => {
                        let device = slot.require_available_block()?;
                        std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(device)
                            .whatever("unable to open payload target")?
                    }
                    SlotKind::File { path } => std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(path)
                        .whatever("unable to open payload target")?,
                    SlotKind::Custom { .. } => {
                        bail!("custom slots do not support delta updates yet")
                    }
                };
                let mut target_writer =
                    HashWriter::new(delta_encoding.original_hash.algorithm(), target);
                let (mut patch_reader, patch_writer) = buffered_pipe(8192);

                let (decode_result, xdelta_result) = std::thread::scope(|scope| {
                    let target_writer = &mut target_writer;
                    // We must move the `patch_reader` here as we need it to be dropped when
                    // the decompression fails. Otherwise, we get a deadlock when waiting for
                    // the payload decoding in the following.
                    let handle = scope.spawn(move || {
                        trace!("starting xdelta");
                        let result = xdelta_decompress(&source, &mut patch_reader, target_writer);
                        trace!(?result, "xdelta terminated");
                        result
                    });
                    let decode_result = payload.decode_into(
                        BufferedPipeTarget {
                            writer: patch_writer,
                        },
                        block_provider
                            .as_ref()
                            .map(|p| p as &dyn StoredBlockProvider),
                        &mut progress,
                    );
                    trace!("finished decoding payload into pipe");
                    (decode_result, handle.join().unwrap())
                });
                decode_result.whatever("unable to decode payload")?;
                xdelta_result.whatever("unable to decode delta update")?;
                let (target_hash, target_size) = target_writer
                    .finalize_synced()
                    .whatever("unable to synchronize delta payload target")?;
                if target_hash != delta_encoding.original_hash {
                    bail!("decoded slot data does not match hash");
                }
                DecodedPayloadInfo {
                    hash: target_hash,
                    size: target_size.into(),
                }
            } else {
                match slot.kind() {
                    SlotKind::Block(_) => {
                        let device = slot.require_available_block()?;
                        let target = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(device)
                            .whatever("unable to open payload target")?;
                        payload
                            .decode_into(
                                target,
                                block_provider
                                    .as_ref()
                                    .map(|p| p as &dyn StoredBlockProvider),
                                &mut progress,
                            )
                            .whatever("unable to decode payload")?
                    }
                    SlotKind::File { path } => {
                        let target = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create(true)
                            .truncate(true)
                            .open(path)
                            .whatever("unable to open payload target")?;
                        payload
                            .decode_into(
                                target,
                                block_provider
                                    .as_ref()
                                    .map(|p| p as &dyn StoredBlockProvider),
                                &mut progress,
                            )
                            .whatever("unable to decode payload")?
                    }
                    SlotKind::Custom { handler } => {
                        let target = CustomTarget::new(handler.iter().map(|arg| arg.as_str()))?;
                        payload
                            .decode_into(
                                target,
                                block_provider
                                    .as_ref()
                                    .map(|p| p as &dyn StoredBlockProvider),
                                &mut progress,
                            )
                            .whatever("unable to decode payload")?
                    }
                }
            };
            payload_db::save_slot_state(
                slot.name(),
                // Only save the hashes and size if the slot is immutable.
                &SlotState {
                    hashes: if slot.is_immutable() {
                        [(
                            decoded_payload_info.hash.algorithm(),
                            decoded_payload_info.hash,
                        )]
                        .into_iter()
                        .collect()
                    } else {
                        Default::default()
                    },
                    size: if slot.is_immutable() {
                        Some(decoded_payload_info.size)
                    } else {
                        None
                    },
                    updated_at: Some(jiff::Timestamp::now()),
                },
            )
            .whatever("unable to save slot state")?;
            continue;
        } else if let SystemPayloadDestination::Execute = destination {
            let type_execute = payload_entry
                .type_execute
                .as_ref()
                .expect("execute delivery validated during preflight");
            eprintln!("executing update payload {}", payload.idx(),);
            let target = CustomTarget::new(type_execute.handler.iter().map(|arg| arg.as_str()))?;
            payload
                .decode_into(target, None, &mut progress)
                .whatever("unable to decode payload")?;
            continue;
        }
    }
    drop(progress);
    emit_progress(100.0);

    let reboot_type = if !bundle_reader.header().is_incremental {
        system
            .boot_flow()
            .post_install(system, boot_group.unwrap().0)
            .whatever("error executing post-install step")?;
        UpdateRebootType::Yes
    } else {
        UpdateRebootType::No
    };
    update_hooks
        .run_hooks("post-update", hook_vars, &Default::default())
        .whatever("error running `post-update` hooks")?;
    Ok(reboot_type)
}

#[derive(Debug)]
pub struct HashWriter<W> {
    writer: W,
    hasher: Hasher,
    size: u64,
}

impl<W> HashWriter<W> {
    pub fn new(algorithm: HashAlgorithm, writer: W) -> Self {
        Self {
            writer,
            hasher: algorithm.hasher(),
            size: 0,
        }
    }

    pub fn finalize(self) -> (HashDigest, u64) {
        (self.hasher.finalize(), self.size)
    }
}

impl HashWriter<File> {
    pub fn finalize_synced(mut self) -> io::Result<(HashDigest, u64)> {
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
pub struct BufferedPipeTarget {
    writer: PipeWriter,
}

impl PayloadTarget for BufferedPipeTarget {
    fn write(&mut self, bytes: &[u8]) -> rugix_bundle::BundleResult<()> {
        self.writer.write_all(bytes).whatever("write failed")
    }

    fn finalize(mut self) -> rugix_bundle::BundleResult<()> {
        self.writer.flush().whatever("flush failed")
    }
}

#[derive(Debug)]
pub struct CustomTarget {
    child: Child,
}

impl CustomTarget {
    pub fn new<'arg>(mut command: impl Iterator<Item = &'arg str>) -> SystemResult<Self> {
        let Some(prog) = command.next() else {
            bail!("custom update handler cannot be an empty sequence");
        };
        let child = std::process::Command::new(prog)
            .args(command)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .whatever("unable to spawn custom update handler")?;
        Ok(Self { child })
    }
}

impl PayloadTarget for CustomTarget {
    fn write(&mut self, bytes: &[u8]) -> rugix_bundle::BundleResult<()> {
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(bytes)
            .whatever("unable to write payload to custom handler")
    }

    fn finalize(mut self) -> rugix_bundle::BundleResult<()> {
        info!("waiting on custom update handler to finalize");
        // Flush all bytes and close stdin.
        drop(self.child.stdin.take().unwrap());
        let status = self
            .child
            .wait()
            .whatever("error waiting for update handler")?;
        if !status.success() {
            bail!(
                "error running custom update handler, code {:?}",
                status.code()
            )
        }
        Ok(())
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
    /// Manage the persistent state of the system.
    #[clap(subcommand)]
    State(StateCommand),
    /// Install and inspect over-the-air updates.
    #[clap(subcommand)]
    Update(UpdateCommand),
    /// Manage the system.
    #[clap(subcommand)]
    System(SystemCommand),
    /// Inspect compatibility components and constraints.
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
    /// Reboot into the newly installed system.
    Yes,
    /// Do nothing.
    No,
    /// Just set the flags without rebooting.
    ///
    /// This will tell the bootloader integration to boot into the new system next without
    /// actually triggering a reboot.
    Set,
    /// Set the deferred spare reboot marker.
    ///
    /// Rugix will itself remember that an update has been installed. On the next boot,
    /// it will remove the marker and reboot into the new system. This allows the system
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

    use crate::config::system::BlockSlotConfig;
    use crate::config::system::BootGroupConfig;
    use crate::config::system::FileSlotConfig;
    use crate::config::system::SlotConfig;
    use crate::system::boot_groups::BootGroups;
    use crate::system::slots::SystemSlots;

    use super::clear_target_overlay_with;
    use super::preflight_system_deliveries;
    use super::validate_app_archive;
    use super::validate_app_deliveries;
    use super::AppPayloadDelivery;
    use super::HashWriter;
    use super::PayloadDelivery;
    use super::ProgressCursors;
    use super::SystemPayloadDestination;

    fn no_delivery() -> PayloadDelivery<'static> {
        PayloadDelivery {
            slot: None,
            execute: false,
            app_file: false,
            app_archive: false,
        }
    }

    fn slot_delivery(slot: &'static str) -> PayloadDelivery<'static> {
        PayloadDelivery {
            slot: Some(slot),
            ..no_delivery()
        }
    }

    fn execute_delivery() -> PayloadDelivery<'static> {
        PayloadDelivery {
            execute: true,
            ..no_delivery()
        }
    }

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
    fn preflight_resolves_group_aliases_before_installation() {
        let slots = file_slots(&["system-a", "system-b"]);
        let mut aliases = IndexMap::new();
        aliases.insert("system".to_owned(), "system-b".to_owned());
        let groups_config = [("b".to_owned(), BootGroupConfig { slots: aliases })]
            .into_iter()
            .collect::<IndexMap<_, _>>();
        let groups = BootGroups::from_config(&slots, Some(&groups_config)).unwrap();
        let (_, group) = groups.iter().next().unwrap();
        let target_idx = slots.find_by_name("system-b").unwrap().0;

        assert_eq!(
            preflight_system_deliveries(false, &[slot_delivery("system")], &slots, Some(group))
                .unwrap(),
            vec![SystemPayloadDestination::Slot(target_idx)]
        );
    }

    #[test]
    fn preflight_rejects_unknown_active_and_duplicate_destinations() {
        let slots = file_slots(&["target"]);
        assert!(
            preflight_system_deliveries(true, &[slot_delivery("missing")], &slots, None).is_err()
        );

        let (_, active) = slots.find_by_name("target").unwrap();
        active.mark_active();
        assert!(
            preflight_system_deliveries(true, &[slot_delivery("target")], &slots, None).is_err()
        );

        let slots = file_slots(&["target"]);
        assert!(preflight_system_deliveries(
            true,
            &[slot_delivery("target"), slot_delivery("target")],
            &slots,
            None
        )
        .is_err());
    }

    #[test]
    fn preflight_requires_one_supported_delivery_type() {
        let slots = file_slots(&["target"]);
        assert!(preflight_system_deliveries(true, &[no_delivery()], &slots, None).is_err());

        let mut ambiguous = slot_delivery("target");
        ambiguous.execute = true;
        assert!(preflight_system_deliveries(true, &[ambiguous], &slots, None).is_err());
    }

    #[test]
    fn preflight_rejects_unavailable_optional_block_slots() {
        let config = [(
            "optional".to_owned(),
            SlotConfig::Block(BlockSlotConfig {
                device: Some("/dev/rugix-test-device-does-not-exist".to_owned()),
                partition: None,
                immutable: Some(true),
                optional: Some(true),
            }),
        )]
        .into_iter()
        .collect::<IndexMap<_, _>>();
        let slots = SystemSlots::from_config(None, Some(&config)).unwrap();

        assert!(
            preflight_system_deliveries(true, &[slot_delivery("optional")], &slots, None).is_err()
        );
    }

    #[test]
    fn preflight_rejects_app_only_empty_and_inapplicable_full_bundles() {
        let slots = file_slots(&["target"]);
        let app_delivery = PayloadDelivery {
            app_archive: true,
            ..no_delivery()
        };
        assert!(preflight_system_deliveries(true, &[app_delivery], &slots, None).is_err());
        assert!(preflight_system_deliveries(true, &[], &slots, None).is_err());

        let groups_config = [(
            "target".to_owned(),
            BootGroupConfig {
                slots: IndexMap::new(),
            },
        )]
        .into_iter()
        .collect::<IndexMap<_, _>>();
        let groups = BootGroups::from_config(&slots, Some(&groups_config)).unwrap();
        let (_, group) = groups.iter().next().unwrap();
        assert!(
            preflight_system_deliveries(false, &[execute_delivery()], &slots, Some(group)).is_err()
        );
    }

    #[test]
    fn overlay_cleanup_ignores_only_missing_directories() {
        let path = std::path::Path::new("/test/overlay");
        assert!(clear_target_overlay_with(path, |_| {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        })
        .is_ok());
        assert!(clear_target_overlay_with(path, |_| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })
        .is_err());
    }

    #[test]
    fn hash_writer_accounts_only_for_bytes_actually_written() {
        struct ShortWriter;

        impl std::io::Write for ShortWriter {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                Ok(buffer.len().min(2))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = HashWriter::new(si_crypto_hashes::HashAlgorithm::Sha256, ShortWriter);
        assert_eq!(std::io::Write::write(&mut writer, b"four").unwrap(), 2);
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
    fn app_bundle_paths_are_validated_before_installation() {
        let valid = [
            AppPayloadDelivery {
                app_file: Some(("example_app", "config/settings.json")),
                app_archive: None,
                slot: false,
                execute: false,
            },
            AppPayloadDelivery {
                app_file: None,
                app_archive: Some("other-app"),
                slot: false,
                execute: false,
            },
        ];
        assert!(validate_app_deliveries(&valid).is_ok());

        for (app, path) in [
            ("../escape", "file"),
            ("example", "/absolute"),
            ("example", "../escape"),
            ("example", "directory/./file"),
            ("example", ""),
        ] {
            let delivery = [AppPayloadDelivery {
                app_file: Some((app, path)),
                app_archive: None,
                slot: false,
                execute: false,
            }];
            assert!(
                validate_app_deliveries(&delivery).is_err(),
                "{app:?} {path:?}"
            );
        }

        let system_delivery = [AppPayloadDelivery {
            app_file: None,
            app_archive: None,
            slot: true,
            execute: false,
        }];
        assert!(validate_app_deliveries(&system_delivery).is_err());
    }

    #[test]
    fn app_archive_validation_rejects_escaping_and_redirected_paths() {
        fn archive_with<F>(build: F) -> tempfile::NamedTempFile
        where
            F: FnOnce(&mut tar::Builder<std::fs::File>),
        {
            let file = tempfile::NamedTempFile::new().unwrap();
            let mut builder = tar::Builder::new(file.as_file().try_clone().unwrap());
            build(&mut builder);
            builder.finish().unwrap();
            drop(builder);
            file
        }

        let safe = archive_with(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_size(4);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "directory/file", b"safe".as_slice())
                .unwrap();
        });
        assert!(validate_app_archive(std::fs::File::open(safe.path()).unwrap()).is_ok());

        let escaping_link = archive_with(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            builder
                .append_link(&mut header, "redirect", "../outside")
                .unwrap();
        });
        assert!(validate_app_archive(std::fs::File::open(escaping_link.path()).unwrap()).is_err());

        let redirected_write = archive_with(|builder| {
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            link.set_mode(0o777);
            link.set_cksum();
            builder
                .append_link(&mut link, "redirect", "directory")
                .unwrap();

            let mut file = tar::Header::new_gnu();
            file.set_size(4);
            file.set_mode(0o644);
            file.set_cksum();
            builder
                .append_data(&mut file, "redirect/file", b"data".as_slice())
                .unwrap();
        });
        assert!(
            validate_app_archive(std::fs::File::open(redirected_write.path()).unwrap()).is_err()
        );
    }
}
