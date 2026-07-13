use std::ffi::CString;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use byte_calc::NumBytes;
use nix::mount::MntFlags;
use reportify::bail;
use reportify::ensure;
use reportify::ErrorExt;
use reportify::ResultExt;
use rugix_common::disk::blkdev::BlockDevice;

use rugix_common::mount::is_mount_point;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::config::bootstrapping::BootstrappingConfig;
use crate::config::bootstrapping::DefaultLayoutConfig;
use crate::config::bootstrapping::SystemLayoutConfig;
use crate::config::state::OverlayConfig;
use crate::config::state::OverlayFallbackConfig;
use crate::config::state::PersistConfig;
use crate::config::state::PersistDirectoryConfig;
use crate::config::state::PersistFileConfig;
use crate::config::state::StateConfig;
use crate::config::system::SystemConfig;
use crate::state::load_state_config;
use crate::system::boot_flows::BootFlowCapabilities;
use crate::system::config::load_system_config;
use crate::system::data_partition::resolve_driver;
use crate::system::data_partition::DriverContext;
use crate::system::partitions::resolve_data_partition;
use crate::system::paths::MOUNT_POINT_CONFIG;
use crate::system::paths::MOUNT_POINT_DATA;
use crate::system::paths::MOUNT_POINT_SYSTEM;
use crate::system::root::find_system_device;
use crate::system::root::SystemRoot;
use crate::system::System;
use crate::system::SystemError;
use crate::system::SystemResult;
use rugix_common::disk::blkpg::update_kernel_partitions;
use rugix_common::disk::repart::generic_efi_partition_schema;
use rugix_common::disk::repart::generic_mbr_partition_schema;
use rugix_common::disk::repart::repart;
use rugix_common::disk::repart::PartitionSchema;
use rugix_common::disk::repart::SchemaPartition;
use rugix_common::disk::PartitionTable;
use rugix_common::partitions::mkfs_ext4;
use rugix_hooks::HooksLoader;
use xscript::run;
use xscript::vars;
use xscript::Run;
use xscript::Vars;

use crate::utils::clear_flag;
use crate::utils::is_flag_set;
use crate::utils::is_init_process;
use crate::utils::DEFERRED_SPARE_REBOOT_FLAG;

mod error_shell;

pub fn main() -> SystemResult<()> {
    ensure!(is_init_process(), "process must be the init process");
    let result = init();
    match &result {
        Ok(_) => {
            error!("initialization procedure terminated unexpectedly");
            error_shell::prompt_on_init_error();
        }
        Err(error) => {
            error!(error = ?error, "error during initialization");
            error_shell::prompt_on_init_error();
        }
    }
    eprintln!("waiting for 30 seconds...");
    thread::sleep(Duration::from_secs(30));
    Ok(())
}

const STATE_PROFILES_DIR: &str = "/run/rugix/mounts/data/state/";

const DEFAULT_STATE_DIR: &str = "/run/rugix/mounts/data/state/default";

fn init() -> SystemResult<()> {
    println!(include_str!("../assets/BANNER.txt"));

    rugix_cli::CliBuilder::new().init();

    const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    if let Ok(path) = std::env::var("PATH") {
        let mut paths = path.split(':').collect::<Vec<_>>();
        for default_path in DEFAULT_PATH.split(':').rev() {
            if !paths.contains(&default_path) {
                println!("adding '{}' to PATH", default_path);
                paths.insert(0, default_path);
            }
        }
        let new_path = paths.join(":");
        std::env::set_var("PATH", &new_path);
        println!("PATH='{}'", new_path);
    } else {
        std::env::set_var("PATH", DEFAULT_PATH);
        println!("PATH='{}'", DEFAULT_PATH);
    }

    // Mount essential filesystems.
    mount_essential_filesystems()?;

    let boot_hooks = HooksLoader::default()
        .load_hooks("boot")
        .whatever("unable to load `boot` hooks")?;

    if let Err(error) = boot_hooks.run_hooks("pre-init", Default::default(), &Default::default()) {
        error!(error = ?error, "error running `boot/pre-init` hooks");
    }

    let system_config = load_system_config()?;
    let Some(system_device) = find_system_device() else {
        bail!("unable to determine system device")
    };
    let Some(root) = SystemRoot::from_system_device(&system_device) else {
        bail!("unable to determine system root");
    };

    let Some(config_partition) = (match system_config.config_partition.as_ref() {
        Some(partition) => {
            if let Some(partition) = partition.partition {
                root.resolve_partition(partition)
            } else if let Some(device) = partition.device.as_deref() {
                Some(BlockDevice::new(device).whatever("unable to find config partition device")?)
            } else {
                None
            }
        }
        None => root.resolve_partition(1),
    }) else {
        bail!("bootstrapping requires a config partition");
    };

    log_ignored_error(
        fs::create_dir_all(MOUNT_POINT_CONFIG),
        "unable to create config mount point",
    );
    run!([
        "/usr/bin/env",
        "mount",
        "-o",
        "ro",
        config_partition.path(),
        MOUNT_POINT_CONFIG
    ])
    .whatever("unable to mount config partition")?;

    let dotted_marker = Path::new(MOUNT_POINT_CONFIG).join(".rugix/bootstrap");
    let plain_marker = Path::new(MOUNT_POINT_CONFIG).join("rugix/bootstrap");
    let bootstrap_marker = if dotted_marker.exists() {
        Some(dotted_marker)
    } else if plain_marker.exists() {
        Some(plain_marker)
    } else {
        None
    };
    let wipe_data_marker = Path::new(MOUNT_POINT_CONFIG).join(".rugix/wipe-data");
    let wipe_pending = wipe_data_marker.exists();

    if bootstrap_marker.is_some() || wipe_pending {
        run!([
            "/usr/bin/env",
            "mount",
            "-o",
            "remount,rw",
            MOUNT_POINT_CONFIG
        ])
        .whatever("unable to mount config partition as read-write")?;

        if let Some(marker) = bootstrap_marker {
            bootstrap(&root, &system_config)?;
            std::fs::remove_file(&marker).whatever("unable to remove bootstrap marker")?;
            info!("Done bootstrapping");
        }

        if wipe_pending {
            info!("processing deferred data wipe");
            run_deferred_data_wipe(&root, &system_config)?;
            std::fs::remove_file(&wipe_data_marker)
                .whatever("unable to clear `wipe-data` marker")?;
        }

        run!([
            "/usr/bin/env",
            "mount",
            "-o",
            "remount,ro",
            MOUNT_POINT_CONFIG
        ])
        .whatever("unable to mount config partition as readonly")?;
    }

    let system = System::initialize()?;

    let default_boot_entry = log_ignored_error(
        system.boot_flow().get_default(&system),
        "unable to determine default boot entry",
    );
    let requires_commit = default_boot_entry != system.active_boot_entry();
    let current_system_is_committed =
        default_boot_entry.is_some() && default_boot_entry == system.active_boot_entry();

    if let Err(error) = setup_state_and_exec_init(
        &root,
        &system_device,
        &system_config,
        &system,
        requires_commit,
    ) {
        maybe_exec_underlying_init(&system, current_system_is_committed, &error);
        return Err(error);
    }

    Ok(())
}

fn setup_state_and_exec_init(
    root: &SystemRoot,
    system_device: &BlockDevice,
    system_config: &SystemConfig,
    system: &System,
    requires_commit: bool,
) -> SystemResult<()> {
    log_ignored_error(
        fs::create_dir_all(MOUNT_POINT_DATA),
        "unable to create data mount point",
    );
    let data_partition_config = system_config.data_partition.clone().unwrap_or_default();
    let data_partition = resolve_data_partition(Some(root), &data_partition_config);
    let Some(data_partition) = data_partition else {
        bail!("Rugix pre-init requires a data partition");
    };
    let data_driver = resolve_driver(&data_partition_config);
    let driver_ctx = DriverContext::new(
        data_partition.path().to_path_buf(),
        Path::new(MOUNT_POINT_DATA).to_path_buf(),
    );
    // Mount failures are non-fatal here: pre-init falls through with an
    // empty data tmpfs (the system comes up looking like a factory reset).
    // Encrypting drivers wanting a hard halt can return success only
    // after verifying the partition is actually usable.
    if let Err(error) = data_driver.mount(&driver_ctx) {
        warn!(error = ?error, "mounting of the data partition failed");
        log_ignored_error(
            fs::create_dir_all(Path::new(MOUNT_POINT_DATA).join(".rugix")),
            "unable to create data error log directory",
        );
        log_ignored_error(
            fs::write(
                Path::new(MOUNT_POINT_DATA).join(".rugix/data-mount-error.log"),
                format!("{error:?}"),
            ),
            "unable to write data mount error log",
        );
    }

    let state_config = load_state_config()?;

    if !matches!(state_config.overlay, Some(OverlayConfig::Disabled)) {
        // 4️⃣ Setup remaining mount points in `/run/rugix/mounts`.
        log_ignored_error(
            fs::create_dir_all(MOUNT_POINT_SYSTEM),
            "unable to create system mount point",
        );
        run!([
            "/usr/bin/env",
            "mount",
            "-o",
            "ro",
            system_device.path(),
            MOUNT_POINT_SYSTEM
        ])
        .whatever("unable to mount system partition")?;
    }

    if let Err(error) = check_deferred_spare_reboot(system) {
        warn!(error = ?error, "error executing deferred reboot");
    }

    // 6️⃣ Setup state in `/run/rugix/state`.
    let state_profile = Path::new(DEFAULT_STATE_DIR);
    let reset_flag = state_profile.join(".rugix/reset-state");
    if reset_flag.exists() {
        let backup_name = log_ignored_error(
            std::fs::read(&reset_flag),
            "unable to read reset-state flag",
        )
        .and_then(|d| log_ignored_error(String::from_utf8(d), "reset-state flag is not UTF-8"))
        .unwrap_or_default();
        let reset_hooks = HooksLoader::default()
            .load_hooks("state-reset")
            .whatever("unable to load `state-reset` hooks")?;

        reset_hooks
            .run_hooks("pre-reset", Vars::new(), &Default::default())
            .whatever("unable to run `pre-reset` hooks")?;
        // The existence of the file indicates that the state shall be reset.
        if backup_name.trim().is_empty() {
            log_ignored_error(
                fs::remove_dir_all(state_profile),
                "unable to remove state profile",
            );
        } else {
            let backup_profile = Path::new(STATE_PROFILES_DIR).join(backup_name);
            log_ignored_error(
                fs::rename(state_profile, &backup_profile),
                "unable to move state profile backup",
            );
            log_ignored_error(
                fs::remove_file(backup_profile.join(".rugix/reset-state")),
                "unable to remove reset-state flag from backup profile",
            );
        }
        reset_hooks
            .run_hooks("post-reset", Vars::new(), &Default::default())
            .whatever("unable to run `post-reset` hooks")?;
    }
    log_ignored_error(
        fs::create_dir_all(state_profile),
        "unable to create state profile",
    );
    log_ignored_error(fs::create_dir_all(STATE_DIR), "unable to create state dir");
    run!(["/usr/bin/env", "mount", "--bind", &state_profile, STATE_DIR])
        .whatever("unable to bind mount state profile")?;

    // 7️⃣ Setup the root filesystem overlay.
    let root_dir = setup_root_overlay(system, &state_config, state_profile)?;

    // 8️⃣ Setup the bind mounts for the persistent state.
    setup_persistent_state(&root_dir, state_profile, &state_config)?;

    // 9️⃣ Restore the machine id and hand off to Systemd.
    exec_chroot_init(&root_dir, requires_commit)?;

    Ok(())
}

fn maybe_exec_underlying_init(
    system: &System,
    current_system_is_committed: bool,
    error: &impl std::fmt::Debug,
) {
    let capabilities = system.boot_flow().capabilities();
    if !should_exec_underlying_init_after_error(current_system_is_committed, capabilities) {
        return;
    }
    warn!(
        error = ?error,
        boot_flow = system.boot_flow().name(),
        "Rugix init failed on committed system without userspace failure recovery; starting underlying init"
    );
    if let Err(error) = exec_system_init() {
        error!(error = ?error, "unable to start underlying init after Rugix init failure");
    }
}

fn should_exec_underlying_init_after_error(
    current_system_is_committed: bool,
    capabilities: BootFlowCapabilities,
) -> bool {
    current_system_is_committed && !capabilities.userspace_failure_recovery.unwrap_or(false)
}

const STATE_DIR: &str = "/run/rugix/state";
const OVERLAY_FALLBACK_ERROR_LOG: &str = ".rugix/overlay-fallback-error.log";

pub fn state_dir() -> &'static Path {
    Path::new(STATE_DIR)
}

const BOOTSTRAP_CONFIG_PATH: &str = "/etc/rugix/bootstrapping.toml";

fn load_bootstrap_config() -> SystemResult<BootstrappingConfig> {
    Ok(if Path::new(BOOTSTRAP_CONFIG_PATH).exists() {
        toml::from_str(
            &fs::read_to_string(BOOTSTRAP_CONFIG_PATH)
                .whatever("unable to read system configuration file")?,
        )
        .whatever("unable to parse system configuration file")?
    } else {
        BootstrappingConfig::default()
    })
}

fn bootstrap(root: &SystemRoot, system_config: &SystemConfig) -> SystemResult<()> {
    let bootstrap_hooks = HooksLoader::default()
        .load_hooks("bootstrap")
        .whatever("unable to load bootstrap hooks")?;

    bootstrap_hooks
        .run_hooks("prepare", Vars::new(), &Default::default())
        .whatever("unable to run `bootstrap/prepare` hooks")?;

    let bootstrap_config = load_bootstrap_config()?;

    if bootstrap_config.disabled.unwrap_or(false) {
        warn!("Found bootstrapping marker but bootstrapping is disabled. Skip bootstrapping");
        return Ok(());
    }

    info!("Found bootstrapping marker. Begin bootstrapping");
    let layout = bootstrap_config.layout.unwrap_or_else(|| {
        SystemLayoutConfig::Default(DefaultLayoutConfig::new(NumBytes::gibibytes(4)))
    });

    let ty = root.table.as_ref().unwrap().ty();

    let schema = match &layout {
        SystemLayoutConfig::Mbr(partition_layout_config)
        | SystemLayoutConfig::Gpt(partition_layout_config) => Some(PartitionSchema {
            ty,
            partitions: partition_layout_config
                .partitions
                .iter()
                .map(|part| SchemaPartition {
                    number: None,
                    name: part.name.clone(),
                    size: part.size.map(|s| s.raw.into()),
                    ty: part.ty,
                })
                .collect(),
        }),
        SystemLayoutConfig::Default(default_layout_config) => match ty {
            rugix_common::disk::PartitionTableType::Gpt => Some(generic_efi_partition_schema(
                default_layout_config.system_size.raw.into(),
            )),
            rugix_common::disk::PartitionTableType::Mbr => Some(generic_mbr_partition_schema(
                default_layout_config.system_size.raw.into(),
            )),
        },
        SystemLayoutConfig::None => None,
    };

    let data_partition_config = system_config.data_partition.clone().unwrap_or_default();
    let default_data_idx = if ty.is_mbr() { 7u32 } else { 6u32 };
    let data_partition_idx = data_partition_config.partition.unwrap_or(default_data_idx);
    let data_partition_has_driver = data_partition_config.driver.is_some();

    if let Some(schema) = schema {
        bootstrap_hooks
            .run_hooks("pre-layout", Vars::new(), &Default::default())
            .whatever("unable to run `bootstrap/pre-layout` hooks")?;
        if let Some((old_table, _)) = bootstrap_partitions(&schema, root)? {
            // Partition is new, let's see whether we need to create a filesystem.
            match &layout {
                SystemLayoutConfig::Mbr(partition_layout_config)
                | SystemLayoutConfig::Gpt(partition_layout_config) => {
                    for (idx, config) in partition_layout_config.partitions.iter().enumerate() {
                        let part_num = (idx + 1) as u32;
                        if idx < old_table.partitions.len() {
                            if config.filesystem.is_some() {
                                warn!(
                                    "refuse to create filesystems on already existing partition {}",
                                    part_num
                                );
                            }
                            continue;
                        }
                        let block_device = root.resolve_partition(part_num).unwrap();
                        // When a driver is configured, it owns format
                        // end-to-end; the layout's filesystem entry is
                        // ignored to avoid double-formatting an
                        // encrypted volume.
                        if part_num == data_partition_idx && data_partition_has_driver {
                            let driver = resolve_driver(&data_partition_config);
                            let ctx = DriverContext::new(
                                block_device.path().to_path_buf(),
                                Path::new(MOUNT_POINT_DATA).to_path_buf(),
                            );
                            driver.format(&ctx).whatever(
                                "unable to format data partition via configured driver",
                            )?;
                            continue;
                        }
                        let Some(filesystem) = &config.filesystem else {
                            continue;
                        };
                        match filesystem {
                            crate::config::bootstrapping::Filesystem::Ext4(ext4_filesystem) => {
                                mkfs_ext4(
                                    block_device,
                                    ext4_filesystem.label.as_deref().unwrap_or(""),
                                    ext4_filesystem
                                        .additional_options
                                        .as_deref()
                                        .unwrap_or_default(),
                                )
                                .whatever("unable to create filesystem on partition")?;
                            }
                        }
                    }
                }
                SystemLayoutConfig::Default(_) => {
                    format_data_partition_if_new(&old_table, data_partition_idx, || {
                        let block_device = root.resolve_partition(data_partition_idx).unwrap();
                        let driver = resolve_driver(&data_partition_config);
                        let ctx = DriverContext::new(
                            block_device.path().to_path_buf(),
                            Path::new(MOUNT_POINT_DATA).to_path_buf(),
                        );
                        driver.format(&ctx)
                    })
                    .whatever("unable to format data partition")?;
                }
                SystemLayoutConfig::None => unreachable!(),
            }
        }
        bootstrap_hooks
            .run_hooks("post-layout", Vars::new(), &Default::default())
            .whatever("unable to run `bootstrap/post-layout` hooks")?;
    }

    Ok(())
}

/// Returns whether the configured data partition was added during repartitioning.
///
/// Partition numbers are one-based and are not required to be contiguous, so the number
/// of entries in the old table cannot be used to determine whether a particular partition
/// existed.
fn data_partition_is_new(old_table: &PartitionTable, data_partition_idx: u32) -> bool {
    old_table
        .partitions
        .iter()
        .all(|partition| u32::from(partition.number) != data_partition_idx)
}

fn format_data_partition_if_new<F>(
    old_table: &PartitionTable,
    data_partition_idx: u32,
    format: F,
) -> SystemResult<()>
where
    F: FnOnce() -> SystemResult<()>,
{
    if data_partition_is_new(old_table, data_partition_idx) {
        format()?;
    }
    Ok(())
}

/// Run a deferred `rugix-ctrl data wipe`. The driver's `wipe` is
/// responsible for leaving the partition in a fresh, mountable state.
///
/// Any error here propagates so the caller leaves the `wipe-data` marker
/// in place — the next boot retries until the wipe actually succeeds.
fn run_deferred_data_wipe(root: &SystemRoot, system_config: &SystemConfig) -> SystemResult<()> {
    let data_partition_config = system_config.data_partition.clone().unwrap_or_default();
    let Some(data_partition) = resolve_data_partition(Some(root), &data_partition_config) else {
        bail!("deferred data wipe: data partition not resolvable");
    };
    let driver = resolve_driver(&data_partition_config);
    let ctx = DriverContext::new(
        data_partition.path().to_path_buf(),
        Path::new(MOUNT_POINT_DATA).to_path_buf(),
    );
    driver.wipe(&ctx).whatever("data partition wipe failed")
}

/// Mounts the essential filesystems `/proc`, `/sys`, and `/run`.
fn mount_essential_filesystems() -> SystemResult<()> {
    if !is_mount_point("/proc") {
        if let Err(error) = run!(["/usr/bin/env", "mount", "-t", "proc", "proc", "/proc"]) {
            let error = error.whatever::<SystemError>("error mounting /proc");
            warn!(error = ?error, "error mounting /proc");
        }
    } else {
        debug!("skip mounting of `/proc`: already mounted")
    }
    if !is_mount_point("/sys") {
        if let Err(error) = run!(["/usr/bin/env", "mount", "-t", "sysfs", "sys", "/sys"]) {
            warn!(error = ?error, "error mounting /sys");
        }
    } else {
        debug!("skip mounting of `/sys`: already mounted")
    }
    if !is_mount_point("/run") {
        if let Err(error) = run!(["/usr/bin/env", "mount", "-t", "tmpfs", "tmp", "/run"]) {
            let error = error.whatever::<SystemError>("error mounting /run");
            warn!(error = ?error, "error mounting /run");
        }
    } else {
        debug!("skip mounting of `/run`: already mounted")
    }
    Ok(())
}

/// Initializes the partitions and expands the partition table during the first boot.
fn bootstrap_partitions(
    schema: &PartitionSchema,
    root: &SystemRoot,
) -> SystemResult<Option<(PartitionTable, PartitionTable)>> {
    let old_table =
        PartitionTable::read(root.device.path()).whatever("unable to read partition table")?;
    if let Some(new_table) =
        repart(&old_table, schema).whatever("unable to compute new partition table")?
    {
        // Write new partition table to disk.
        new_table
            .write(root.device.path())
            .whatever("unable to write new partition table")?;
        run!(["/usr/bin/env", "sync"]).whatever("unable to synchronize file systems")?;
        // Inform the kernel about new partitions.
        update_kernel_partitions(root.device.path(), &old_table, &new_table)
            .whatever("unable to update partitions in the kernel")?;
        Ok(Some((old_table, new_table)))
    } else {
        Ok(None)
    }
}

/// Sets up the overlay.
fn setup_root_overlay(
    system: &System,
    config: &StateConfig,
    state_profile: &Path,
) -> SystemResult<PathBuf> {
    let overlay_config = config.overlay.clone().unwrap_or(OverlayConfig::Discard);
    let result = setup_root_overlay_once(system, state_profile, overlay_config.clone());
    match result {
        Ok(root_dir) => {
            clear_overlay_fallback_error(state_profile);
            Ok(root_dir)
        }
        Err(error) => match &config.overlay_fallback {
            Some(OverlayFallbackConfig::InMemory)
                if !matches!(
                    overlay_config,
                    OverlayConfig::Disabled | OverlayConfig::InMemory
                ) =>
            {
                warn!(
                    error = ?error,
                    "error setting up configured overlay; falling back to in-memory overlay"
                );
                write_overlay_fallback_error(state_profile, &error);
                setup_root_overlay_once(system, state_profile, OverlayConfig::InMemory).map_err(
                    |fallback_error| {
                        reportify::whatever!(
                            "unable to setup system overlay mounts with in-memory fallback"
                        )
                        .field_debug("configured overlay error", &error)
                        .field_debug("fallback overlay error", &fallback_error)
                    },
                )
            }
            _ => Err(error),
        },
    }
}

fn setup_root_overlay_once(
    system: &System,
    state_profile: &Path,
    overlay_config: OverlayConfig,
) -> SystemResult<PathBuf> {
    let overlay_state = state_profile.join("overlay");
    let force_persist = state_profile.join(".rugix/force-persist-overlay").exists();

    if matches!(overlay_config, OverlayConfig::Discard) && !force_persist {
        remove_dir_all_if_exists(&overlay_state).whatever("unable to remove overlay state")?;
    }

    let (overlay_dir, overlay_root_dir, overlay_work_dir, upper) = match overlay_config {
        OverlayConfig::Persist | OverlayConfig::Discard => {
            let hot_overlay_state = match system.active_boot_entry() {
                Some(idx) => overlay_state.join(system.boot_entries()[idx].name()),
                None => {
                    warn!("active boot group unknown; using shared overlay state under '_unknown'");
                    overlay_state.join("_unknown")
                }
            };
            const OVERLAY_DIR: &str = "/run/rugix/mounts/data/overlay";
            const OVERLAY_ROOT_DIR: &str = "/run/rugix/mounts/data/overlay/root";
            const OVERLAY_WORK_DIR: &str = "/run/rugix/mounts/data/overlay/work";
            (
                OVERLAY_DIR,
                OVERLAY_ROOT_DIR,
                OVERLAY_WORK_DIR,
                hot_overlay_state,
            )
        }
        OverlayConfig::InMemory => {
            const TEMP_OVERLAY_DIR: &str = "/run/rugix/overlay";
            const TEMP_OVERLAY_ROOT_DIR: &str = "/run/rugix/overlay/root";
            const TEMP_OVERLAY_WORK_DIR: &str = "/run/rugix/overlay/work";
            (
                TEMP_OVERLAY_DIR,
                TEMP_OVERLAY_ROOT_DIR,
                TEMP_OVERLAY_WORK_DIR,
                PathBuf::from("/run/rugix/overlay/upper"),
            )
        }
        OverlayConfig::Disabled => return Ok(PathBuf::from("/")),
    };

    // Reinitialize `work` and `root` directories.
    remove_dir_all_if_exists(overlay_dir).whatever("unable to remove overlay directory")?;
    fs::create_dir_all(overlay_work_dir).whatever("unable to create overlay work directory")?;
    fs::create_dir_all(overlay_root_dir).whatever("unable to create overlay root directory")?;
    fs::create_dir_all(&upper).whatever("unable to create overlay upper directory")?;

    let upper = upper.to_string_lossy();
    run!([
        "/usr/bin/env",
        "mount",
        "-t",
        "overlay",
        "overlay",
        "-o",
        "noatime,lowerdir={MOUNT_POINT_SYSTEM},upperdir={upper},workdir={overlay_work_dir}",
        overlay_root_dir
    ])
    .whatever("unable to setup system overlay mounts")?;
    let overlay_root_dir = Path::new(overlay_root_dir);
    run!([
        "/usr/bin/env",
        "mount",
        "--rbind",
        "/run",
        overlay_root_dir.join("run")
    ])
    .whatever("unable to rbind /run")?;
    Ok(overlay_root_dir.to_path_buf())
}

fn write_overlay_fallback_error<E>(state_profile: &Path, error: &E)
where
    E: std::fmt::Debug,
{
    let path = state_profile.join(OVERLAY_FALLBACK_ERROR_LOG);
    log_ignored_error(
        create_parent_dir(&path),
        "unable to create overlay fallback error log directory",
    );
    log_ignored_error(
        fs::write(path, format!("{error:?}")),
        "unable to write overlay fallback error log",
    );
}

fn clear_overlay_fallback_error(state_profile: &Path) {
    log_ignored_error(
        remove_file_if_exists(state_profile.join(OVERLAY_FALLBACK_ERROR_LOG)),
        "unable to clear overlay fallback error log",
    );
}

/// Sets up the bind mounts required for the persistent state.
fn setup_persistent_state(
    root_dir: &Path,
    state_profile: &Path,
    state_config: &StateConfig,
) -> SystemResult<()> {
    let persist_dir = state_profile.join("persist");
    log_ignored_error(
        fs::create_dir_all(state_profile),
        "unable to create state profile",
    );

    let Some(persist) = &state_config.persist else {
        return Ok(());
    };

    for persist in persist {
        match persist {
            PersistConfig::Directory(PersistDirectoryConfig { directory }) => {
                let directory = path_strip_root(directory.as_ref());
                eprintln!(
                    "Setting up bind mounts for directory `{}`...",
                    directory.to_string_lossy()
                );
                let system_path = root_dir.join(directory);
                let state_path = persist_dir.join(directory);
                if system_path.exists() && !system_path.is_dir() {
                    bail!(
                        "Error persisting `{}`, not a directory!",
                        directory.to_string_lossy()
                    );
                }
                if !state_path.is_dir() {
                    log_ignored_error(
                        fs::remove_dir_all(&state_path),
                        "unable to remove persistent directory state path",
                    );
                    log_ignored_error(
                        create_parent_dir(&state_path),
                        "unable to create parent directory of persistent directory",
                    );
                    if system_path.is_dir() {
                        run!(["/usr/bin/env", "cp", "-a", &system_path, &state_path])
                            .whatever("unable to copy system files from root partition to state")?;
                    } else {
                        log_ignored_error(
                            fs::create_dir_all(&state_path),
                            "unable to create persistent directory state path",
                        );
                    }
                }
                if !system_path.is_dir() {
                    fs::create_dir_all(&system_path)
                        .whatever("unable to create system directory")?;
                }
                run!(["/usr/bin/env", "mount", "--bind", &state_path, &system_path])
                    .whatever("unable to bind-mount persistent directory")?;
            }
            PersistConfig::File(PersistFileConfig { file, default }) => {
                let file = path_strip_root(file.as_ref());
                eprintln!(
                    "Setting up bind mounts for file `{}`...",
                    file.to_string_lossy()
                );
                let system_path = root_dir.join(file);
                let state_path = persist_dir.join(file);
                if system_path.exists() && !system_path.is_file() {
                    bail!("Error persisting `{}`, not a file!", file.to_string_lossy());
                }
                if !state_path.is_file() {
                    log_ignored_error(
                        fs::remove_dir_all(&state_path),
                        "unable to remove persistent file state path",
                    );
                    create_parent_dir(&state_path)
                        .whatever("unable to create parent directory of persistent file")?;
                    if system_path.is_file() {
                        run!(["/usr/bin/env", "cp", "-a", &system_path, &state_path])
                            .whatever("unable to copy persistent file from system")?;
                    } else {
                        fs::write(&state_path, default.as_deref().unwrap_or_default())
                            .whatever("unable to write default")?;
                    }
                }
                if !system_path.is_file() {
                    create_parent_dir(&system_path)
                        .whatever("unable to create system parent directory")?;
                    fs::write(&system_path, "").whatever("unable to initialize file")?;
                }
                run!(["/usr/bin/env", "mount", "--bind", &state_path, &system_path])
                    .whatever("unable to bind mount file")?;
            }
        }
    }

    Ok(())
}

/// Strips the root `/` from a path.
fn path_strip_root(path: &Path) -> &Path {
    if let Ok(stripped) = path.strip_prefix("/") {
        stripped
    } else {
        path
    }
}

/// Creates the parent directories of a path.
fn create_parent_dir(path: impl AsRef<Path>) -> io::Result<()> {
    fn _create_parent_dir(path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
        } else {
            Err(io::Error::other(format!("path `{path:?}` has no parent")))
        }
    }
    _create_parent_dir(path.as_ref())
}

fn remove_dir_all_if_exists(path: impl AsRef<Path>) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_file_if_exists(path: impl AsRef<Path>) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Makes sure `/etc/machine-id` has been restored/initialized.
fn restore_machine_id(root_dir: &Path) -> SystemResult<()> {
    let state_machine_id = state_dir().join("machine-id");
    let system_machine_id = root_dir.join("etc/machine-id");
    if !state_machine_id.exists() {
        let machine_id = format!("{}", uuid::Uuid::new_v4().simple());
        fs::write(&system_machine_id, machine_id.as_bytes())
            .whatever("unable to write machine-id")?;
        fs::copy(system_machine_id, state_machine_id)
            .whatever("unable to copy machine id into state")?;
    } else {
        fs::copy(state_machine_id, system_machine_id)
            .whatever("unable to copy machine id into /etc/machine-id")?;
    }
    Ok(())
}

/// Changes the root directory and hands off to the system init process.
///
/// We follow the example from the manpage of the `pivot_root` system call here.
///
/// We are not using `chroot` as this lead to problems with Docker.
fn exec_chroot_init(root_dir: &Path, requires_commit: bool) -> SystemResult<()> {
    if root_dir != Path::new("/") {
        restore_machine_id(root_dir)?;
        println!("Changing current working directory to overlay root directory.");
        nix::unistd::chdir(root_dir).whatever("unable to switch to overlay directory")?;
        println!("Pivoting root mount point to current working directory.");
        nix::unistd::pivot_root(".", ".").whatever("unable to pivot root directory")?;
        println!("Unmounting the previous root filesystem.");
        nix::mount::umount2(".", MntFlags::MNT_DETACH)
            .whatever("unable to unmount old root directory")?;
        println!("Changing current working directory to `/`.");
        nix::unistd::chdir("/").whatever("unable to switch to current working directory")?;
    }
    let boot_hooks = HooksLoader::default()
        .load_hooks("boot")
        .whatever("unable to load `boot` hooks")?;
    if let Err(error) = boot_hooks.run_hooks(
        "post-init",
        vars! {
            RUGIX_REQUIRES_COMMIT = if requires_commit { "true" } else { "false" }
        },
        &Default::default(),
    ) {
        error!(error = ?error, "error running `boot/post-init` hooks");
    }
    exec_system_init()?;
    Ok(())
}

fn exec_system_init() -> SystemResult<()> {
    println!("Starting system init process.");
    let systemd_init = &CString::new("/sbin/init").unwrap();
    nix::unistd::execv(systemd_init, &[systemd_init]).whatever("unable to run system init")?;
    Ok(())
}

/// Reboot the system to the spare partitions if the deferred spare reboot flag is set.
fn check_deferred_spare_reboot(system: &System) -> SystemResult<()> {
    if is_flag_set(DEFERRED_SPARE_REBOOT_FLAG) {
        println!("Executing deferred reboot to spare partitions.");
        // Remove file and make sure that changes are synced to disk.
        clear_flag(DEFERRED_SPARE_REBOOT_FLAG)?;
        nix::unistd::sync();
        if !system.needs_commit()? {
            // Reboot to the spare partitions.
            if let Some((spare, _)) = system.spare_entry()? {
                system
                    .boot_flow()
                    .set_try_next(system, spare)
                    .whatever("unable to set next boot group")?;
                system.reboot()?;
            }
        }
    }
    Ok(())
}

fn log_ignored_error<T, E>(result: Result<T, E>, context: &'static str) -> Option<T>
where
    E: std::fmt::Debug,
{
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            warn!(error = ?error, "{}", context);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::PathBuf;

    use rugix_common::disk::gpt::gpt_types;
    use rugix_common::disk::mbr::mbr_types;
    use rugix_common::disk::mbr::MbrId;
    use rugix_common::disk::DiskId;
    use rugix_common::disk::NumBlocks;
    use rugix_common::disk::Partition;
    use rugix_common::disk::PartitionTable;

    use crate::system::data_partition::DataPartitionDriver;
    use crate::system::data_partition::DriverContext;
    use crate::system::SystemResult;

    use super::data_partition_is_new;
    use super::format_data_partition_if_new;

    #[derive(Default)]
    struct RecordingDriver {
        formats: Cell<usize>,
    }

    impl DataPartitionDriver for RecordingDriver {
        fn format(&self, _ctx: &DriverContext) -> SystemResult<()> {
            self.formats.set(self.formats.get() + 1);
            Ok(())
        }

        fn mount(&self, _ctx: &DriverContext) -> SystemResult<()> {
            unreachable!("mount is not used by bootstrap format tests")
        }

        fn wipe(&self, _ctx: &DriverContext) -> SystemResult<()> {
            unreachable!("wipe is not used by bootstrap format tests")
        }
    }

    fn driver_context() -> DriverContext {
        DriverContext::new(PathBuf::from("/dev/test-data"), PathBuf::from("/mnt/data"))
    }

    fn partition(number: u8, ty: rugix_common::disk::PartitionType) -> Partition {
        Partition {
            number,
            start: NumBlocks::from_raw(u64::from(number) * 2048),
            size: NumBlocks::from_raw(1024),
            ty,
            name: None,
            gpt_id: None,
            gpt_attrs: None,
            bootable: false,
        }
    }

    #[test]
    fn new_default_gpt_data_partition_is_detected() {
        let mut table = PartitionTable::new(DiskId::random_gpt(), NumBlocks::from_raw(1_000_000));
        table.partitions = (1..=5)
            .map(|number| partition(number, gpt_types::LINUX))
            .collect();

        let driver = RecordingDriver::default();
        let ctx = driver_context();
        format_data_partition_if_new(&table, 6, || driver.format(&ctx)).unwrap();

        assert!(data_partition_is_new(&table, 6));
        assert_eq!(driver.formats.get(), 1);
    }

    #[test]
    fn existing_default_gpt_data_partition_is_not_new() {
        let mut table = PartitionTable::new(DiskId::random_gpt(), NumBlocks::from_raw(1_000_000));
        table.partitions = (1..=6)
            .map(|number| partition(number, gpt_types::LINUX))
            .collect();

        let driver = RecordingDriver::default();
        let ctx = driver_context();
        format_data_partition_if_new(&table, 6, || driver.format(&ctx)).unwrap();

        assert!(!data_partition_is_new(&table, 6));
        assert_eq!(driver.formats.get(), 0);
    }

    #[test]
    fn configured_data_partition_is_found_by_number_across_gaps() {
        let mut table = PartitionTable::new(DiskId::random_gpt(), NumBlocks::from_raw(1_000_000));
        table.partitions = [1, 2, 4, 8]
            .map(|number| partition(number, gpt_types::LINUX))
            .into();

        assert!(!data_partition_is_new(&table, 8));
        assert!(data_partition_is_new(&table, 6));
    }

    #[test]
    fn default_mbr_data_partition_is_detected_by_number() {
        let mut table = PartitionTable::new(
            DiskId::Mbr(MbrId::new(0x12345678)),
            NumBlocks::from_raw(1_000_000),
        );
        table.partitions = (1..=7)
            .map(|number| partition(number, mbr_types::LINUX))
            .collect();

        let driver = RecordingDriver::default();
        let ctx = driver_context();
        format_data_partition_if_new(&table, 7, || driver.format(&ctx)).unwrap();
        assert!(!data_partition_is_new(&table, 7));
        assert_eq!(driver.formats.get(), 0);

        table.partitions.retain(|partition| partition.number != 7);
        format_data_partition_if_new(&table, 7, || driver.format(&ctx)).unwrap();
        assert!(data_partition_is_new(&table, 7));
        assert_eq!(driver.formats.get(), 1);
    }
}
