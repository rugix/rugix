//! Plan and resume first-boot partition creation and filesystem initialization.
//!
//! `run_bootstrap` persists the original initialization plan before changing the table.
//! Each filesystem is synchronized before its completion checkpoint is saved.

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use byte_calc::NumBytes;
use reportify::bail;
use reportify::ensure;
use reportify::ResultExt;
use rugix_common::disk::blkpg::update_kernel_partitions;
use rugix_common::disk::repart::generic_efi_partition_schema;
use rugix_common::disk::repart::generic_mbr_partition_schema;
use rugix_common::disk::repart::repart;
use rugix_common::disk::repart::PartitionSchema;
use rugix_common::disk::repart::SchemaPartition;
use rugix_common::disk::PartitionTable;
use rugix_common::disk::PartitionTableType;
use rugix_common::partitions::mkfs_ext4;
use rugix_hooks::HooksLoader;
use rugix_hooks::RunOptions;
use sha2::Digest;
use tracing::info;
use tracing::warn;
use xscript::run;
use xscript::Run;
use xscript::Vars;

use crate::config::bootstrapping::BootstrappingConfig;
use crate::config::bootstrapping::DefaultLayoutConfig;
use crate::config::bootstrapping::Filesystem;
use crate::config::bootstrapping::SystemLayoutConfig;
use crate::config::system::PartitionConfig;
use crate::config::system::SystemConfig;
use crate::system::config::SYSTEM_CONFIG_PATH;
use crate::system::data_partition::resolve_driver;
use crate::system::data_partition::DriverContext;
use crate::system::paths::MOUNT_POINT_CONFIG;
use crate::system::paths::MOUNT_POINT_DATA;
use crate::system::root::SystemRoot;
use crate::system::SystemResult;
use crate::utils::clear_flag;

use journal::Journal;

mod journal;

const CONFIG_PATH: &str = "/etc/rugix/bootstrapping.toml";

pub fn journal_path() -> PathBuf {
    Path::new(MOUNT_POINT_CONFIG).join(".rugix/bootstrap-journal.json")
}

pub fn run_bootstrap(
    root: &SystemRoot,
    system_config: &SystemConfig,
    hook_options: &RunOptions,
) -> SystemResult<()> {
    let path = journal_path();
    let mut journal = Journal::load(&path)?;
    let system_bytes = read_optional(Path::new(SYSTEM_CONFIG_PATH))?;
    let hooks = HooksLoader::default()
        .load_hooks("bootstrap")
        .whatever("unable to load bootstrap hooks")?;
    hooks
        .run_hooks("prepare", Vars::new(), hook_options)
        .whatever("unable to run `bootstrap/prepare` hooks")?;

    // SystemConfig was loaded before prepare; do not pair stale settings with new bytes.
    ensure!(
        system_bytes == read_optional(Path::new(SYSTEM_CONFIG_PATH))?,
        "system configuration changed during bootstrap preparation"
    );
    let config_bytes = read_optional(Path::new(CONFIG_PATH))?;
    let configuration = configuration_digest(config_bytes.as_deref(), system_bytes.as_deref());
    let config = match config_bytes.as_deref() {
        Some(bytes) => toml::from_str::<BootstrappingConfig>(
            std::str::from_utf8(bytes).whatever("bootstrap configuration is not UTF-8")?,
        )
        .whatever("unable to parse bootstrap configuration")?,
        None => BootstrappingConfig::default(),
    };
    let table =
        PartitionTable::read(&root.device).whatever("unable to read bootstrap partition table")?;
    if let Some(journal) = &journal {
        journal.validate_binding(&table, &configuration)?;
    }
    if config.disabled.unwrap_or(false) {
        ensure!(
            journal.is_none(),
            "bootstrapping disabled while a journal is pending"
        );
        warn!("Found bootstrapping marker but bootstrapping is disabled. Skip bootstrapping");
        return Ok(());
    }
    let layout = config.layout.unwrap_or_else(|| {
        SystemLayoutConfig::Default(DefaultLayoutConfig::new(NumBytes::gibibytes(4).into()))
    });
    let Some(schema) = partition_schema(&layout, table.ty()) else {
        ensure!(
            journal.is_none(),
            "pending bootstrap journal requires a partition layout"
        );
        return Ok(());
    };
    let data_config = system_config.data_partition.clone().unwrap_or_default();
    let data_number = data_config
        .partition
        .unwrap_or(if table.is_mbr() { 7 } else { 6 });

    info!("Begin bootstrapping");
    hooks
        .run_hooks("pre-layout", Vars::new(), hook_options)
        .whatever("unable to run `bootstrap/pre-layout` hooks")?;
    ensure!(
        configuration
            == configuration_digest(
                read_optional(Path::new(CONFIG_PATH))?.as_deref(),
                read_optional(Path::new(SYSTEM_CONFIG_PATH))?.as_deref(),
            ),
        "configuration changed during bootstrap pre-layout hooks"
    );
    let before =
        PartitionTable::read(&root.device).whatever("unable to read current partition table")?;
    let changes = repart(&before, &schema).whatever("unable to plan bootstrap partitions")?;
    let target = changes.as_ref().unwrap_or(&before);

    let mut journal = match journal.take() {
        Some(journal) => {
            journal.validate_binding(&before, &configuration)?;
            journal.validate_plan(target)?;
            journal
        }
        None => {
            let pending = partitions_to_initialize(
                &before,
                target,
                &layout,
                data_number,
                data_config.driver.is_some(),
            );
            let journal = Journal::new(target, configuration, pending);
            journal.save(&path)?;
            journal
        }
    };

    if let Some(target) = &changes {
        target
            .write(root.device.path())
            .whatever("unable to write bootstrap partition table")?;
        run!(["sync"]).whatever("unable to synchronize partition table")?;
        update_kernel_partitions(root.device.path(), &before, target)
            .whatever("unable to update kernel partitions")?;
    }
    initialize_pending(&mut journal, &path, |number| {
        let device = root
            .resolve_partition(u32::from(number))
            .ok_or_else(|| reportify::whatever!("bootstrap partition {number} is unavailable"))?;
        let expected = target
            .partitions
            .iter()
            .find(|partition| partition.number == number)
            .expect("journal validation checks partition membership");
        ensure!(
            device
                .size()
                .whatever("unable to read bootstrap partition size")?
                == target.blocks_to_bytes(expected.size).into_raw(),
            "kernel geometry for bootstrap partition {number} does not match the plan"
        );
        format_partition(device.path(), number, &layout, &data_config, data_number)
    })?;
    hooks
        .run_hooks("post-layout", Vars::new(), hook_options)
        .whatever("unable to run `bootstrap/post-layout` hooks")?;
    clear_flag(&path).whatever("unable to clear completed bootstrap journal")
}

/// Keep the old checkpoint if formatting or synchronization is interrupted.
fn initialize_pending(
    journal: &mut Journal,
    path: &Path,
    mut format: impl FnMut(u8) -> SystemResult<()>,
) -> SystemResult<()> {
    while let Some(&number) = journal.pending.first() {
        format(number)?;
        run!(["sync"]).whatever("unable to synchronize initialized partition")?;
        journal.pending.remove(0);
        journal.save(path)?;
    }
    Ok(())
}

fn partitions_to_initialize(
    before: &PartitionTable,
    target: &PartitionTable,
    layout: &SystemLayoutConfig,
    data_number: u32,
    has_data_driver: bool,
) -> Vec<u8> {
    target
        .partitions
        .iter()
        .filter(|partition| {
            let number = u32::from(partition.number);
            if before
                .partitions
                .iter()
                .any(|old| old.number == partition.number)
            {
                return false;
            }
            match layout {
                SystemLayoutConfig::Default(_) => number == data_number,
                SystemLayoutConfig::Gpt(layout) | SystemLayoutConfig::Mbr(layout) => layout
                    .partitions
                    .get(number.saturating_sub(1) as usize)
                    .is_some_and(|entry| {
                        entry.filesystem.is_some() || (number == data_number && has_data_driver)
                    }),
                SystemLayoutConfig::None => false,
            }
        })
        .map(|partition| partition.number)
        .collect()
}

fn format_partition(
    device: &Path,
    number: u8,
    layout: &SystemLayoutConfig,
    data_config: &PartitionConfig,
    data_number: u32,
) -> SystemResult<()> {
    if u32::from(number) == data_number
        && (data_config.driver.is_some() || matches!(layout, SystemLayoutConfig::Default(_)))
    {
        return resolve_driver(data_config).format(&DriverContext::new(
            device.to_path_buf(),
            PathBuf::from(MOUNT_POINT_DATA),
        ));
    }
    let filesystem = match layout {
        SystemLayoutConfig::Gpt(layout) | SystemLayoutConfig::Mbr(layout) => layout
            .partitions
            .get(usize::from(number) - 1)
            .and_then(|entry| entry.filesystem.as_ref()),
        _ => None,
    };
    let Some(Filesystem::Ext4(filesystem)) = filesystem else {
        bail!("bootstrap partition {number} has no filesystem configuration");
    };
    mkfs_ext4(
        device,
        filesystem.label.as_deref().unwrap_or(""),
        filesystem.additional_options.as_deref().unwrap_or_default(),
    )
    .whatever("unable to create bootstrap filesystem")
}

fn partition_schema(
    layout: &SystemLayoutConfig,
    ty: PartitionTableType,
) -> Option<PartitionSchema> {
    match layout {
        SystemLayoutConfig::Mbr(layout) | SystemLayoutConfig::Gpt(layout) => {
            Some(PartitionSchema {
                ty,
                partitions: layout
                    .partitions
                    .iter()
                    .map(|partition| SchemaPartition {
                        number: None,
                        name: partition.name.clone().map(Into::into),
                        size: partition.size.map(|size| size.raw.into()),
                        ty: partition.ty.map(|value| value.0),
                    })
                    .collect(),
            })
        }
        SystemLayoutConfig::Default(layout) => Some(match ty {
            PartitionTableType::Gpt => generic_efi_partition_schema(layout.system_size.raw.into()),
            PartitionTableType::Mbr => generic_mbr_partition_schema(layout.system_size.raw.into()),
        }),
        SystemLayoutConfig::None => None,
    }
}

/// Distinguish an absent file from an empty file and hash exactly the supplied bytes.
fn configuration_digest(bootstrap: Option<&[u8]>, system: Option<&[u8]>) -> String {
    let mut hash = sha2::Sha256::new();
    for bytes in [bootstrap, system] {
        hash.update([u8::from(bytes.is_some())]);
        if let Some(bytes) = bytes {
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
    }
    format!("{:x}", hash.finalize())
}

fn read_optional(path: &Path) -> SystemResult<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).whatever("unable to read bootstrap configuration input"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rugix_common::disk::DiskId;
    use rugix_common::disk::NumBlocks;

    const CUSTOM_LAYOUT: &str = r#"
[layout]
type = "gpt"
[[layout.partitions]]
name = "boot"
size = "4M"
[[layout.partitions]]
name = "root-a"
size = "4M"
[[layout.partitions]]
name = "root-b"
size = "4M"
[[layout.partitions]]
name = "cache"
size = "8M"
filesystem = { type = "ext4", label = "cache" }
[[layout.partitions]]
name = "data"
filesystem = { type = "ext4", label = "data" }
"#;

    fn custom_plan() -> (PartitionTable, SystemLayoutConfig) {
        let layout = toml::from_str::<BootstrappingConfig>(CUSTOM_LAYOUT)
            .unwrap()
            .layout
            .unwrap();
        let disk = PartitionTable::new(DiskId::random_gpt(), NumBlocks::from_raw(262_144));
        let target = repart(&disk, &partition_schema(&layout, disk.ty()).unwrap())
            .unwrap()
            .unwrap();
        (target, layout)
    }

    /// An interruption after table creation retains provenance and each successful
    /// checkpoint.
    #[test]
    fn resume_formats_only_unfinished_new_filesystems() {
        let (target, layout) = custom_plan();
        let mut before = target.clone();
        before.partitions.retain(|partition| partition.number <= 2);
        let pending = partitions_to_initialize(&before, &target, &layout, 5, false);
        assert_eq!(pending, [4, 5]);
        let configuration = configuration_digest(Some(CUSTOM_LAYOUT.as_bytes()), None);
        let mut journal = Journal::new(&target, configuration.clone(), pending);
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("journal");
        journal.save(&path).unwrap();
        let recomputed = repart(&before, &partition_schema(&layout, before.ty()).unwrap())
            .unwrap()
            .unwrap();
        Journal::load(&path)
            .unwrap()
            .unwrap()
            .validate_plan(&recomputed)
            .unwrap();

        // The updated table alone would lose the information that cache/data were new.
        assert!(partitions_to_initialize(&target, &target, &layout, 5, false).is_empty());
        let result = initialize_pending(&mut journal, &path, |number| {
            if number == 5 {
                bail!("simulated interruption during data format");
            }
            fs::write(work.path().join("cache"), b"prepared filesystem")
                .whatever("unable to create cache fixture")
        });
        assert!(result.is_err());

        let mut resumed = Journal::load(&path).unwrap().unwrap();
        resumed.validate_binding(&target, &configuration).unwrap();
        resumed.validate_plan(&target).unwrap();
        assert_eq!(resumed.pending, [5]);
        initialize_pending(&mut resumed, &path, |number| {
            assert_eq!(number, 5);
            fs::write(work.path().join("data"), b"initialized")
                .whatever("unable to create data fixture")
        })
        .unwrap();
        assert_eq!(
            fs::read(work.path().join("cache")).unwrap(),
            b"prepared filesystem"
        );

        let mut complete = Journal::load(&path).unwrap().unwrap();
        initialize_pending(&mut complete, &path, |_| {
            panic!("completed partitions must not be formatted")
        })
        .unwrap();
        assert!(complete.pending.is_empty());
    }

    /// Fallback disks/configurations and changed target geometry are rejected before
    /// formatting.
    #[test]
    fn replay_rejects_configuration_disk_and_geometry_changes() {
        let (target, _) = custom_plan();
        let original = configuration_digest(
            Some(CUSTOM_LAYOUT.as_bytes()),
            Some(b"[data-partition]\npartition = 5\n"),
        );
        let journal = Journal::new(&target, original.clone(), vec![4, 5]);
        let mut other_disk = target.clone();
        other_disk.disk_id = DiskId::random_gpt();
        assert!(journal.validate_binding(&other_disk, &original).is_err());
        let same_settings = format!("# same settings, different bytes\n{CUSTOM_LAYOUT}");
        for (bootstrap, system) in [
            (
                Some(CUSTOM_LAYOUT.as_bytes()),
                Some(b"[data-partition]\npartition = 4\n".as_slice()),
            ),
            (Some(CUSTOM_LAYOUT.as_bytes()), None),
            (None, Some(b"[data-partition]\npartition = 5\n".as_slice())),
            (
                Some(same_settings.as_bytes()),
                Some(b"[data-partition]\npartition = 5\n".as_slice()),
            ),
        ] {
            assert!(journal
                .validate_binding(&target, &configuration_digest(bootstrap, system))
                .is_err());
        }
        let mut moved = target.clone();
        moved.partitions[4].start += NumBlocks::ONE;
        assert!(journal.validate_plan(&moved).is_err());
        let mut resized = target.clone();
        resized.partitions[4].size = resized.partitions[4].size - NumBlocks::ONE;
        assert!(journal.validate_plan(&resized).is_err());
        let mut sector_size = target.clone();
        sector_size.block_size = rugix_common::utils::units::NumBytes::from_raw(4096);
        assert!(journal.validate_plan(&sector_size).is_err());
        assert!(Journal::new(&target, original, vec![4, 4])
            .validate_plan(&target)
            .is_err());
    }

    /// Default GPT/MBR layouts format new data only, using partition numbers across gaps.
    #[test]
    fn default_plans_preserve_existing_data_and_unformatted_system_slots() {
        let layout =
            SystemLayoutConfig::Default(DefaultLayoutConfig::new(NumBytes::mebibytes(64).into()));
        for (id, data_number) in [(DiskId::random_gpt(), 6), (DiskId::random_mbr(), 7)] {
            let disk = PartitionTable::new(id, NumBlocks::from_raw(4_194_304));
            let target = repart(&disk, &partition_schema(&layout, disk.ty()).unwrap())
                .unwrap()
                .unwrap();
            let mut before = target.clone();
            before
                .partitions
                .retain(|partition| u32::from(partition.number) != data_number);
            assert_eq!(
                partitions_to_initialize(&before, &target, &layout, data_number, false),
                [data_number as u8]
            );
            before.partitions = target.partitions.clone();
            before.partitions.retain(|partition| partition.number != 2);
            assert!(
                partitions_to_initialize(&before, &target, &layout, data_number, false).is_empty()
            );
        }
    }

    /// A configured data driver requests formatting even without a layout filesystem
    /// entry.
    #[test]
    fn custom_layout_selects_non_data_filesystems_and_data_driver() {
        let (target, _) = custom_plan();
        let config =
            CUSTOM_LAYOUT.replace("filesystem = { type = \"ext4\", label = \"data\" }", "");
        let layout = toml::from_str::<BootstrappingConfig>(&config)
            .unwrap()
            .layout
            .unwrap();
        let mut before = target.clone();
        before.partitions.retain(|partition| partition.number <= 2);
        assert_eq!(
            partitions_to_initialize(&before, &target, &layout, 5, false),
            [4]
        );
        assert_eq!(
            partitions_to_initialize(&before, &target, &layout, 5, true),
            [4, 5]
        );
    }
}
