//! Boot flows for atomic system updates.

use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::Write;

use custom::CustomBootFlow;
use reportify::bail;
use reportify::Report;
use reportify::ResultExt;
use rugix_common::disk::PartitionTable;
use serde::Deserialize;
use serde::Serialize;
use tempfile::tempdir;

use super::boot_groups::BootGroupIdx;
use super::boot_groups::BootGroups;
use super::slots::SlotIdx;
use super::ConfigPartition;
use super::System;
use crate::boot::fwenv::load_vars;
use crate::boot::fwenv::set_vars;
pub use crate::config::system::BootFlowCapabilities;
use crate::config::system::BootFlowConfig;
use crate::system::boot_flows::mender::MenderGrub;
use crate::system::boot_flows::mender::MenderUboot;
use crate::system::boot_flows::rauc::RaucGrub;
use crate::system::boot_flows::rauc::RaucUboot;
use crate::system::slots::SlotKind;
use rugix_common::boot::grub::load_grub_env;
use rugix_common::boot::grub::write_with_hash;
use rugix_common::boot::grub::RUGIX_BOOTPART;
use rugix_common::boot::tryboot::AutobootSection;
use rugix_common::boot::tryboot::AUTOBOOT_A;
use rugix_common::boot::tryboot::AUTOBOOT_B;
use rugix_common::boot::tryboot::{self};
use rugix_common::boot::uboot::UBootEnv;
use rugix_common::grub_patch_env;
use rugix_common::mount::Mounted;
use rugix_common::partitions::get_disk_id;
use rugix_common::rpi_patch_boot;
use rugix_common::utils::ascii_numbers;

pub mod custom;
pub mod mender;
pub mod rauc;
pub mod systemd_boot;

reportify::new_whatever_type! {
    pub BootFlowError
}

pub type BootFlowResult<T> = Result<T, Report<BootFlowError>>;

/// Implementation of a boot flow.
pub trait BootFlow: Debug {
    /// Whether a boot flow is configured for the system.
    fn is_configured(&self) -> bool {
        true
    }

    /// Name of the boot flow.
    fn name(&self) -> &str;

    /// Capabilities supported by the boot flow.
    fn capabilities(&self) -> BootFlowCapabilities {
        BootFlowCapabilities::default()
    }

    /// Set the boot group to try on the next boot.
    ///
    /// If booting fails, the bootloader should fallback to the previous default.
    ///
    /// Note that this function may change the default boot group.
    fn set_try_next(&self, system: &System, group: BootGroupIdx) -> BootFlowResult<()>;

    /// Get the default boot group.
    fn get_default(&self, system: &System) -> BootFlowResult<BootGroupIdx>;

    /// Make the active boot group the default.
    fn commit(&self, system: &System) -> BootFlowResult<()>;

    /// Called prior to installing an update to the given boot group.
    #[allow(unused_variables)]
    fn pre_install(&self, system: &System, group: BootGroupIdx) -> BootFlowResult<()> {
        Ok(())
    }

    /// Called after installing an update to the given boot group.
    #[allow(unused_variables)]
    fn post_install(&self, system: &System, group: BootGroupIdx) -> BootFlowResult<()> {
        Ok(())
    }

    /// Called to mark the given boot group as *good*.
    #[allow(unused_variables)]
    fn mark_good(&self, system: &System, group: BootGroupIdx) -> BootFlowResult<()> {
        Ok(())
    }

    /// Called to mark the given boot group as *bad*.
    #[allow(unused_variables)]
    fn mark_bad(&self, system: &System, group: BootGroupIdx) -> BootFlowResult<()> {
        Ok(())
    }

    /// Determine which boot group is currently running.
    ///
    /// Unlike [`get_default`](Self::get_default) (which reflects what will boot *next
    /// time* and can change at runtime), this reflects what actually booted *this time*.
    ///
    /// Returns `None` to fall back to block device matching.
    #[allow(unused_variables)]
    fn get_active(&self, boot_entries: &BootGroups) -> BootFlowResult<Option<BootGroupIdx>> {
        Ok(None)
    }

    /// Reboot the system.
    ///
    /// The default implementation performs a software-level Linux reboot.
    #[allow(unused_variables)]
    fn reboot(&self, system: &System) -> BootFlowResult<()> {
        crate::utils::reboot().whatever("unable to reboot system")
    }
}

/// Placeholder used on systems without atomic system updates.
#[derive(Debug)]
struct NoBootFlow;

impl BootFlow for NoBootFlow {
    fn is_configured(&self) -> bool {
        false
    }

    fn name(&self) -> &str {
        "none"
    }

    fn set_try_next(&self, _system: &System, _group: BootGroupIdx) -> BootFlowResult<()> {
        bail!("no boot flow is configured")
    }

    fn get_default(&self, _system: &System) -> BootFlowResult<BootGroupIdx> {
        bail!("no boot flow is configured")
    }

    fn commit(&self, _system: &System) -> BootFlowResult<()> {
        bail!("no boot flow is configured")
    }
}

/// Boot group status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum BootGroupStatus {
    /// Status is unknown.
    #[default]
    Unknown,
    /// Boot group is known to be good (bootable and working).
    Good,
    /// Boot group is known to be bad (should not be booted).
    Bad,
}

pub fn from_config(
    config: Option<&BootFlowConfig>,
    config_partition: Option<&ConfigPartition>,
    boot_entries: &BootGroups,
) -> BootFlowResult<Box<dyn BootFlow>> {
    if let Some(config) = config {
        return Ok(match config {
            BootFlowConfig::RpiTryboot => Box::new(RpiTryboot {
                inner: rugix_boot_flow(boot_entries)?,
            }),
            BootFlowConfig::RpiUboot => Box::new(RpiUboot {
                inner: rugix_boot_flow(boot_entries)?,
            }),
            BootFlowConfig::Uboot => Box::new(Uboot {
                inner: rugix_boot_flow(boot_entries)?,
            }),
            BootFlowConfig::Grub => Box::new(GrubEfi {
                inner: rugix_boot_flow(boot_entries)?,
            }),
            BootFlowConfig::SystemdBoot(config) => Box::new(systemd_boot::SystemdBootFlow::new(
                boot_entries,
                &config.entries,
            )?),
            BootFlowConfig::Custom(custom_boot_flow_config) => Box::new(CustomBootFlow {
                controller: custom_boot_flow_config.controller.clone().into(),
            }),
            BootFlowConfig::MenderGrub(config) => Box::new(MenderGrub::new(boot_entries, config)?),
            BootFlowConfig::MenderUboot(config) => {
                Box::new(MenderUboot::new(boot_entries, config)?)
            }
            BootFlowConfig::RaucUboot(config) => Box::new(RaucUboot::new(boot_entries, config)?),
            BootFlowConfig::RaucGrub(config) => Box::new(RaucGrub::new(boot_entries, config)?),
        });
    }
    let Some(config_partition) = config_partition else {
        return Ok(Box::new(NoBootFlow));
    };
    if config_partition.path().join("autoboot.txt").exists() {
        Ok(Box::new(RpiTryboot {
            inner: rugix_boot_flow(boot_entries)?,
        }))
    } else if config_partition
        .path()
        .join("bootpart.default.env")
        .exists()
    {
        Ok(Box::new(RpiUboot {
            inner: rugix_boot_flow(boot_entries)?,
        }))
    } else if config_partition
        .path()
        .join("rugpi/primary.grubenv")
        .exists()
        && config_partition.path().join("EFI").is_dir()
    {
        Ok(Box::new(GrubEfi {
            inner: rugix_boot_flow(boot_entries)?,
        }))
    } else {
        Ok(Box::new(NoBootFlow))
    }
}

fn rugix_boot_flow(boot_entries: &BootGroups) -> BootFlowResult<RugixBootFlow> {
    let mut entries = boot_entries.iter();
    let Some((entry_a_idx, entry_a)) = entries.next() else {
        bail!("invalid number of entries");
    };
    let Some((entry_b_idx, entry_b)) = entries.next() else {
        bail!("invalid number of entries");
    };
    if entries.next().is_some() {
        bail!("Rugix boot flows require exactly two boot groups");
    }
    let boot_a = entry_a.get_slot("boot");
    let boot_b = entry_b.get_slot("boot");
    let Some(system_a) = entry_a.get_slot("system") else {
        bail!("unable to get A system slot");
    };
    let Some(system_b) = entry_b.get_slot("system") else {
        bail!("unable to get B system slot");
    };
    Ok(RugixBootFlow {
        entry_a: entry_a_idx,
        entry_b: entry_b_idx,
        boot_a,
        boot_b,
        system_a,
        system_b,
    })
}

#[derive(Debug)]
struct RugixBootFlow {
    entry_a: BootGroupIdx,
    entry_b: BootGroupIdx,
    boot_a: Option<SlotIdx>,
    boot_b: Option<SlotIdx>,
    system_a: SlotIdx,
    system_b: SlotIdx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RugixGroup {
    A,
    B,
}

fn rugix_group(inner: &RugixBootFlow, entry: BootGroupIdx) -> BootFlowResult<RugixGroup> {
    if entry == inner.entry_a {
        Ok(RugixGroup::A)
    } else if entry == inner.entry_b {
        Ok(RugixGroup::B)
    } else {
        bail!("boot group does not belong to the Rugix boot flow")
    }
}

fn rugix_group_from_boot_partition(
    inner: &RugixBootFlow,
    boot_partition: &str,
) -> BootFlowResult<BootGroupIdx> {
    match boot_partition {
        "2" => Ok(inner.entry_a),
        "3" => Ok(inner.entry_b),
        _ => bail!("invalid default boot partition {boot_partition:?}"),
    }
}

fn rugix_boot_partition(
    inner: &RugixBootFlow,
    entry: BootGroupIdx,
) -> BootFlowResult<&'static str> {
    match rugix_group(inner, entry)? {
        RugixGroup::A => Ok("2"),
        RugixGroup::B => Ok("3"),
    }
}

fn rugix_should_set_spare(
    inner: &RugixBootFlow,
    default: BootGroupIdx,
    requested: BootGroupIdx,
) -> BootFlowResult<bool> {
    let _ = rugix_group(inner, default)?;
    let _ = rugix_group(inner, requested)?;
    Ok(requested != default)
}

fn require_gpt_partition_uuid(
    table: &PartitionTable,
    partition_index: usize,
) -> BootFlowResult<String> {
    let partition = table.partitions.get(partition_index).ok_or_else(|| {
        Report::whatever(format!(
            "partition table does not contain partition index {partition_index}"
        ))
    })?;
    let partition_id = partition.gpt_id.ok_or_else(|| {
        Report::whatever(format!(
            "partition {} does not have a GPT identifier",
            partition.number
        ))
    })?;
    Ok(partition_id
        .to_hex_str(ascii_numbers::Case::Lower)
        .to_string())
}

#[derive(Debug)]
struct RpiTryboot {
    inner: RugixBootFlow,
}

impl BootFlow for RpiTryboot {
    fn set_try_next(&self, system: &System, entry: BootGroupIdx) -> BootFlowResult<()> {
        if rugix_should_set_spare(&self.inner, self.get_default(system)?, entry)? {
            tryboot::set_spare_flag().whatever("unable to set tryboot flag")?;
        } else {
            tryboot::clear_spare_flag().whatever("unable to clear tryboot flag")?;
        }
        Ok(())
    }

    fn commit(&self, system: &System) -> BootFlowResult<()> {
        let active = system
            .require_active_boot_entry()
            .whatever("unable to commit Raspberry Pi tryboot flow")?;
        let config_partition = system
            .require_config_partition()
            .whatever("unable to get config partition")?;
        config_partition
            .ensure_writable(|| {
                let autoboot_new_path = config_partition.path().join("autoboot.txt.new");
                let mut autoboot_new = File::create(&autoboot_new_path)
                    .whatever("unable to create new autoboot file")?;
                autoboot_new
                    .write_all(
                        match rugix_group(&self.inner, active)? {
                            RugixGroup::A => AUTOBOOT_A,
                            RugixGroup::B => AUTOBOOT_B,
                        }
                        .as_bytes(),
                    )
                    .whatever("unable to write autoboot file")?;
                autoboot_new
                    .flush()
                    .whatever("unable to flush autoboot file")?;
                autoboot_new
                    .sync_all()
                    .whatever("unable to synchronize autoboot file")?;
                drop(autoboot_new);
                std::fs::rename(
                    autoboot_new_path,
                    config_partition.path().join("autoboot.txt"),
                )
                .whatever("unable to rename autoboot file")?;
                Ok(())
            })
            .whatever("unable to make config partition mountable")?
    }

    fn get_default(&self, system: &System) -> BootFlowResult<BootGroupIdx> {
        let autoboot_txt = std::fs::read_to_string(
            system
                .require_config_partition()
                .whatever("unable to get config partition")?
                .path()
                .join("autoboot.txt"),
        )
        .whatever("unable to read `autoboot.txt` from config partition")?;
        let mut section = AutobootSection::Unknown;
        for line in autoboot_txt.lines() {
            if line.starts_with("[all]") {
                section = AutobootSection::All;
            } else if line.starts_with("[tryboot]") {
                section = AutobootSection::Tryboot;
            } else if line.starts_with('[') {
                section = AutobootSection::Unknown;
            } else if line.starts_with("boot_partition=2") && section == AutobootSection::All {
                return rugix_group_from_boot_partition(&self.inner, "2");
            } else if line.starts_with("boot_partition=3") && section == AutobootSection::All {
                return rugix_group_from_boot_partition(&self.inner, "3");
            }
        }
        bail!("unable to determine partition set from `autoboot.txt`");
    }

    fn post_install(&self, system: &System, entry: BootGroupIdx) -> BootFlowResult<()> {
        tryboot_uboot_post_install(&self.inner, system, entry)
    }

    fn name(&self) -> &str {
        "rpi-tryboot"
    }
}

#[derive(Debug)]
struct RpiUboot {
    inner: RugixBootFlow,
}

impl BootFlow for RpiUboot {
    fn set_try_next(&self, system: &System, entry: BootGroupIdx) -> BootFlowResult<()> {
        if rugix_should_set_spare(&self.inner, self.get_default(system)?, entry)? {
            crate::boot::uboot::set_spare_flag(system)?;
        } else {
            crate::boot::uboot::clear_spare_flag(system)?;
        }
        Ok(())
    }

    fn commit(&self, system: &System) -> BootFlowResult<()> {
        let active = system
            .require_active_boot_entry()
            .whatever("unable to commit Raspberry Pi U-Boot flow")?;
        let config_partition = system
            .require_config_partition()
            .whatever("unable to get config partition")?;
        config_partition
            .ensure_writable(|| {
                let mut bootpart_env = UBootEnv::new();
                bootpart_env.set("bootpart", rugix_boot_partition(&self.inner, active)?);
                let new_path = config_partition.path().join("bootpart.default.env.new");
                bootpart_env
                    .save(&new_path)
                    .whatever("unable to save uboot environment")?;
                File::open(&new_path)
                    .whatever("unable to open uboot environment")?
                    .sync_all()
                    .whatever("unable to synchronize uboot environment")?;
                std::fs::rename(
                    new_path,
                    config_partition.path().join("bootpart.default.env"),
                )
                .whatever("unable to copy over uboot environment")?;
                Ok(())
            })
            .whatever("unable to make config partition writable")?
    }

    fn get_default(&self, system: &System) -> BootFlowResult<BootGroupIdx> {
        let config_partition = system
            .require_config_partition()
            .whatever("unable to get config partition")?;
        let bootpart_env = UBootEnv::load(config_partition.path().join("bootpart.default.env"))
            .whatever("unable to load uboot environment")?;
        let Some(bootpart) = bootpart_env.get("bootpart") else {
            bail!("Invalid bootpart environment.");
        };
        rugix_group_from_boot_partition(&self.inner, bootpart)
    }

    fn post_install(&self, system: &System, entry: BootGroupIdx) -> BootFlowResult<()> {
        tryboot_uboot_post_install(&self.inner, system, entry)
    }

    fn name(&self) -> &str {
        "rpi-uboot"
    }
}

#[derive(Debug)]
struct Uboot {
    inner: RugixBootFlow,
}

impl BootFlow for Uboot {
    fn set_try_next(&self, system: &System, entry: BootGroupIdx) -> BootFlowResult<()> {
        let config_partition = system
            .require_config_partition()
            .whatever("unable to get config partition")?;
        config_partition
            .ensure_writable(|| {
                let mut boot_env = hashbrown::HashMap::new();
                if rugix_should_set_spare(&self.inner, self.get_default(system)?, entry)? {
                    boot_env.insert("rugix_boot_spare".to_owned(), "1".to_owned());
                } else {
                    boot_env.insert("rugix_boot_spare".to_owned(), "0".to_owned());
                }
                set_vars(&boot_env)?;
                Ok(())
            })
            .whatever("unable to make config partition writable")?
    }

    fn commit(&self, system: &System) -> BootFlowResult<()> {
        let active = system
            .require_active_boot_entry()
            .whatever("unable to commit U-Boot flow")?;
        let config_partition = system
            .require_config_partition()
            .whatever("unable to get config partition")?;
        config_partition
            .ensure_writable(|| {
                let mut boot_env = hashbrown::HashMap::new();
                boot_env.insert(
                    "rugix_bootpart".to_owned(),
                    rugix_boot_partition(&self.inner, active)?.to_owned(),
                );
                set_vars(&boot_env)?;
                Ok(())
            })
            .whatever("unable to make config partition writable")?
    }

    fn get_default(&self, _: &System) -> BootFlowResult<BootGroupIdx> {
        let boot_env = load_vars()?;
        let Some(bootpart) = boot_env.get("rugix_bootpart").map(|v| v.trim()) else {
            bail!("Rugix boot partition is not set.");
        };
        rugix_group_from_boot_partition(&self.inner, bootpart)
    }

    fn name(&self) -> &str {
        "uboot"
    }
}

fn tryboot_uboot_post_install(
    inner: &RugixBootFlow,
    system: &System,
    entry: BootGroupIdx,
) -> BootFlowResult<()> {
    let temp_dir_spare = tempdir().whatever("unable to create temporary directory")?;
    let temp_dir_spare = temp_dir_spare.path();
    let group = rugix_group(inner, entry)?;
    let (Some(boot_slot), system_slot) = (match group {
        RugixGroup::A => (inner.boot_a, inner.system_a),
        RugixGroup::B => (inner.boot_b, inner.system_b),
    }) else {
        // Boot slot is not defined; nothing to do.
        return Ok(());
    };
    let boot_slot = &system.slots()[boot_slot];
    let _system_slot = &system.slots()[system_slot];
    let SlotKind::Block(_) = boot_slot.kind() else {
        bail!("boot slot must be of type `block`")
    };
    let boot_device = boot_slot
        .require_available_block()
        .whatever("spare boot slot is not available")?;
    let _mounted_boot =
        Mounted::mount(boot_device, temp_dir_spare).whatever("unable to mount boot device")?;
    let Some(root) = &system.root else {
        bail!("no parent block device");
    };
    let Some(table) = &root.table else {
        bail!("no partition table");
    };
    let root = if table.is_mbr() {
        let disk_id = get_disk_id(&root.device).whatever("unable to get root device disk id")?;
        match group {
            RugixGroup::A => format!("PARTUUID={disk_id}-05"),
            RugixGroup::B => format!("PARTUUID={disk_id}-06"),
        }
    } else {
        let table =
            PartitionTable::read(&root.device).whatever("unable to read partition table")?;
        // Use partitions 4 (index 3) and 5 (index 4).
        let partition_index = match group {
            RugixGroup::A => 3,
            RugixGroup::B => 4,
        };
        let part_uuid = require_gpt_partition_uuid(&table, partition_index)?;
        format!("PARTUUID={}", part_uuid)
    };
    rpi_patch_boot(temp_dir_spare, root).whatever("unable to patch boot partition")?;
    Ok(())
}

#[derive(Debug)]
struct GrubEfi {
    inner: RugixBootFlow,
}

impl BootFlow for GrubEfi {
    fn set_try_next(&self, system: &System, entry: BootGroupIdx) -> BootFlowResult<()> {
        if rugix_should_set_spare(&self.inner, self.get_default(system)?, entry)? {
            crate::boot::grub::set_spare_flag(system).whatever("unable to set spare flag")?;
        } else {
            crate::boot::grub::clear_spare_flag(system).whatever("unable to clear spare flag")?;
        }
        Ok(())
    }

    fn get_default(&self, system: &System) -> BootFlowResult<BootGroupIdx> {
        let config_partition = system
            .require_config_partition()
            .whatever("unable to get config partition")?;
        let bootpart_env = load_grub_env(config_partition.path().join("rugpi/primary.grubenv"))
            .whatever("unable to load Grub environment")?;
        let Some(bootpart) = bootpart_env.get(RUGIX_BOOTPART) else {
            bail!("Invalid bootpart environment.");
        };
        rugix_group_from_boot_partition(&self.inner, bootpart)
    }

    fn commit(&self, system: &System) -> BootFlowResult<()> {
        let active = system
            .require_active_boot_entry()
            .whatever("unable to commit GRUB flow")?;
        let mut envblk = HashMap::new();
        envblk.insert(
            RUGIX_BOOTPART.to_owned(),
            rugix_boot_partition(&self.inner, active)?.to_owned(),
        );
        let config_partition = system
            .require_config_partition()
            .whatever("unable to get config partition")?;
        config_partition
            .ensure_writable(|| {
                write_with_hash(
                    &envblk,
                    &config_partition.path().join("rugpi/secondary.grubenv"),
                    "/rugpi/secondary.grubenv",
                )
                .whatever("unable to write secondary Grub environment")?;
                write_with_hash(
                    &envblk,
                    &config_partition.path().join("rugpi/primary.grubenv"),
                    "/rugpi/primary.grubenv",
                )
                .whatever("unable to write primary Grub environment")?;
                Ok(())
            })
            .whatever("unable to make config partition mountable")?
    }

    fn post_install(&self, system: &System, entry: BootGroupIdx) -> BootFlowResult<()> {
        let temp_dir_spare = tempdir().whatever("unable to create temporary directory")?;
        let temp_dir_spare = temp_dir_spare.path();
        let group = rugix_group(&self.inner, entry)?;
        let (Some(boot_slot), system_slot) = (match group {
            RugixGroup::A => (self.inner.boot_a, self.inner.system_a),
            RugixGroup::B => (self.inner.boot_b, self.inner.system_b),
        }) else {
            // Boot slot is not defined; nothing to do.
            return Ok(());
        };
        let boot_slot = &system.slots()[boot_slot];
        let _system_slot = &system.slots()[system_slot];
        let SlotKind::Block(_) = boot_slot.kind() else {
            bail!("boot slot must be of type `block`")
        };
        let boot_device = boot_slot
            .require_available_block()
            .whatever("spare boot slot is not available")?;
        let _mounted_boot = Mounted::mount(boot_device, temp_dir_spare)
            .whatever("unable to mount boot partition")?;
        let Some(table) = system.root.as_ref().and_then(|root| root.table.as_ref()) else {
            bail!("no partition table");
        };
        let partition_index = match group {
            RugixGroup::A => 3,
            RugixGroup::B => 4,
        };
        let part_uuid = require_gpt_partition_uuid(table, partition_index)?;
        grub_patch_env(temp_dir_spare, part_uuid).whatever("unable to path Grub environment")?;
        Ok(())
    }

    fn name(&self) -> &str {
        "grub"
    }
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;
    use rugix_common::disk::gpt::Guid;
    use rugix_common::disk::DiskId;
    use rugix_common::disk::NumBlocks;
    use rugix_common::disk::Partition;
    use rugix_common::disk::PartitionTable;
    use rugix_common::disk::PartitionType;

    use super::from_config;
    use super::require_gpt_partition_uuid;
    use super::rugix_boot_flow;
    use super::rugix_boot_partition;
    use super::rugix_group_from_boot_partition;
    use super::rugix_should_set_spare;
    use crate::config::system::BootFlowConfig;
    use crate::config::system::BootGroupConfig;
    use crate::config::system::FileSlotConfig;
    use crate::config::system::PartitionConfig;
    use crate::config::system::SlotConfig;
    use crate::system::boot_groups::BootGroups;
    use crate::system::slots::SystemSlots;
    use crate::system::ConfigPartition;

    fn test_groups(count: usize) -> (SystemSlots, BootGroups) {
        let slot_config = (0..count)
            .map(|index| {
                (
                    format!("system-{index}"),
                    SlotConfig::File(FileSlotConfig {
                        path: format!("/tmp/system-{index}"),
                        immutable: Some(true),
                    }),
                )
            })
            .collect::<IndexMap<_, _>>();
        let slots = SystemSlots::from_config(None, Some(&slot_config)).unwrap();
        let group_config = (0..count)
            .map(|index| {
                (
                    format!("group-{index}"),
                    BootGroupConfig {
                        slots: [("system".to_owned(), format!("system-{index}"))]
                            .into_iter()
                            .collect(),
                    },
                )
            })
            .collect::<IndexMap<_, _>>();
        let groups = BootGroups::from_config(&slots, Some(&group_config)).unwrap();
        (slots, groups)
    }

    #[test]
    fn rugix_flows_require_exactly_two_groups() {
        let (_, one) = test_groups(1);
        let (_, two) = test_groups(2);
        let (_, three) = test_groups(3);
        assert!(rugix_boot_flow(&one).is_err());
        assert!(rugix_boot_flow(&two).is_ok());
        assert!(rugix_boot_flow(&three).is_err());
    }

    #[test]
    fn absent_boot_flow_is_not_an_error() {
        let (_, groups) = test_groups(1);
        let flow = from_config(None, None, &groups).unwrap();
        assert!(!flow.is_configured());

        let directory = tempfile::tempdir().unwrap();
        let partition = ConfigPartition::from_config(
            &PartitionConfig::new().with_path(Some(directory.path().display().to_string())),
        )
        .unwrap();
        let flow = from_config(None, Some(&partition), &groups).unwrap();
        assert!(!flow.is_configured());
    }

    #[test]
    fn invalid_explicit_boot_flow_is_still_an_error() {
        let (_, groups) = test_groups(1);
        assert!(from_config(Some(&BootFlowConfig::RpiTryboot), None, &groups).is_err());
    }

    #[test]
    fn rugix_state_mapping_covers_stable_trial_commit_rollback_and_invalid_states() {
        let (_, groups) = test_groups(2);
        let inner = rugix_boot_flow(&groups).unwrap();
        let mut entries = groups.iter();
        let a = entries.next().unwrap().0;
        let b = entries.next().unwrap().0;

        assert!(!rugix_should_set_spare(&inner, a, a).unwrap());
        assert!(rugix_should_set_spare(&inner, a, b).unwrap());
        assert!(!rugix_should_set_spare(&inner, b, b).unwrap());
        assert!(rugix_should_set_spare(&inner, b, a).unwrap());
        assert_eq!(rugix_group_from_boot_partition(&inner, "2").unwrap(), a);
        assert_eq!(rugix_group_from_boot_partition(&inner, "3").unwrap(), b);
        assert_eq!(rugix_boot_partition(&inner, a).unwrap(), "2");
        assert_eq!(rugix_boot_partition(&inner, b).unwrap(), "3");
        assert!(rugix_group_from_boot_partition(&inner, "4").is_err());

        let (_, three_groups) = test_groups(3);
        let invalid = three_groups.iter().nth(2).unwrap().0;
        assert!(rugix_should_set_spare(&inner, a, invalid).is_err());
        assert!(rugix_boot_partition(&inner, invalid).is_err());
    }

    #[test]
    fn missing_gpt_root_partition_metadata_returns_errors() {
        let mut table = PartitionTable::new(
            DiskId::Gpt(Guid::from_bytes([0; 16])),
            NumBlocks::from_raw(1024),
        );
        assert!(require_gpt_partition_uuid(&table, 3).is_err());
        table.partitions.push(Partition {
            number: 1,
            start: NumBlocks::from_raw(1),
            size: NumBlocks::from_raw(1),
            ty: PartitionType::Gpt(Guid::from_bytes([0; 16])),
            name: None,
            gpt_id: None,
            gpt_attrs: None,
            bootable: false,
        });
        assert!(require_gpt_partition_uuid(&table, 0).is_err());
    }
}
