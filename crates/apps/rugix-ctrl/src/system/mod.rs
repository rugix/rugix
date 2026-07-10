use boot_flows::BootFlow;
use boot_groups::BootGroup;
use boot_groups::BootGroupIdx;
use boot_groups::BootGroups;
use config::load_system_config;
use partitions::ConfigPartition;
use reportify::Report;
use reportify::ResultExt;
use root::find_system_device;
use root::SystemRoot;
use slots::SlotKind;
use slots::SystemSlots;
use tracing::error;
use tracing::warn;

use rugix_common::disk::blkdev::BlockDevice;

use crate::config::system::PartitionConfig;
use crate::config::system::SystemConfig;

pub mod boot_flows;
pub mod boot_groups;
pub mod config;
pub mod data_partition;
pub mod partitions;
pub mod paths;
pub mod root;
pub mod slots;

reportify::new_whatever_type! {
    pub SystemError
}

pub type SystemResult<T> = Result<T, Report<SystemError>>;

pub struct System {
    pub config: SystemConfig,
    pub device: Option<BlockDevice>,
    pub root: Option<SystemRoot>,

    slots: SystemSlots,
    boot_entries: BootGroups,
    active_boot_entry: Option<BootGroupIdx>,
    boot_flow: Box<dyn BootFlow>,
    config_partition: Option<ConfigPartition>,
}

impl System {
    pub fn initialize() -> SystemResult<Self> {
        let system_config = load_system_config()?;
        let system_device = find_system_device();
        let system_root = system_device
            .as_ref()
            .and_then(SystemRoot::from_system_device);

        let config_partition = ConfigPartition::from_config(
            system_config
                .config_partition
                .as_ref()
                .unwrap_or(&PartitionConfig::new()),
        );
        let slots = SystemSlots::from_config(system_root.as_ref(), system_config.slots.as_ref())?;
        let boot_entries = BootGroups::from_config(&slots, system_config.boot_groups.as_ref())?;
        // Create boot flow before determining the active group so that the
        // boot flow can provide this information (e.g., via EFI variables).
        let boot_flow = boot_flows::from_config(
            system_config.boot_flow.as_ref(),
            config_partition.as_ref(),
            &boot_entries,
        )
        .whatever("unable to create boot flow from config")?;
        // Determine the active boot group. Check the kernel cmdline first
        // (rugix.boot_group=<name>), then ask the boot flow, then fall back
        // to block device matching.
        let mut active_boot_entry = get_active_from_cmdline(&boot_entries);
        if active_boot_entry.is_none() {
            active_boot_entry = boot_flow
                .get_active(&boot_entries)
                .whatever("unable to determine active boot group from boot flow")?;
        }
        // Fall back to matching block devices against the system device.
        // Absent (optional) slots are skipped — they have no resolved
        // device to compare against, so they can never be "the one we
        // booted from".
        if active_boot_entry.is_none() {
            for (idx, entry) in boot_entries.iter() {
                for (_, slot) in entry.slots() {
                    if let SlotKind::Block(raw) = &slots[slot].kind() {
                        if raw.device().is_some() && raw.device() == system_device.as_ref() {
                            entry.mark_active();
                            break;
                        }
                    }
                }
                if entry.active() {
                    active_boot_entry = Some(idx);
                    break;
                }
            }
        }
        // Mark all slots in the active group as active.
        if let Some(active_idx) = active_boot_entry {
            let entry = &boot_entries[active_idx];
            entry.mark_active();
            for (_, slot) in entry.slots() {
                slots[slot].mark_active();
            }
        }
        if active_boot_entry.is_none() {
            warn!("unable to determine active boot group");
        }
        Ok(Self {
            config: system_config,
            device: system_device,
            root: system_root,
            slots,
            boot_entries,
            active_boot_entry,
            boot_flow,
            config_partition,
        })
    }

    pub fn root(&self) -> &Option<SystemRoot> {
        &self.root
    }

    pub fn config(&self) -> &SystemConfig {
        &self.config
    }

    pub fn slots(&self) -> &SystemSlots {
        &self.slots
    }

    pub fn boot_entries(&self) -> &BootGroups {
        &self.boot_entries
    }

    pub fn active_boot_entry(&self) -> Option<BootGroupIdx> {
        self.active_boot_entry
    }

    /// First entry that is not the default.
    pub fn spare_entry(&self) -> SystemResult<Option<(BootGroupIdx, &BootGroup)>> {
        let default = self
            .boot_flow
            .get_default(self)
            .whatever("unable to determine default boot group")?;
        Ok(self.boot_entries().iter().find(|(idx, _)| *idx != default))
    }

    pub fn needs_commit(&self) -> SystemResult<bool> {
        Ok(self.active_boot_entry
            != Some(
                self.boot_flow
                    .get_default(self)
                    .whatever("unable to determine default boot group")?,
            ))
    }

    pub fn boot_flow(&self) -> &dyn BootFlow {
        &*self.boot_flow
    }

    pub fn config_partition(&self) -> Option<&ConfigPartition> {
        self.config_partition.as_ref()
    }

    pub fn require_config_partition(&self) -> SystemResult<&ConfigPartition> {
        self.config_partition()
            .ok_or_else(|| Report::whatever("config partition is required"))
    }

    pub fn commit(&self) -> SystemResult<()> {
        self.boot_flow
            .commit(self)
            .whatever("unable to commit to active boot group")
    }

    /// Reboot the system via the configured boot flow.
    pub fn reboot(&self) -> SystemResult<()> {
        self.boot_flow
            .reboot(self)
            .whatever("unable to reboot system")
    }
}

/// Read `rugix.boot_group=<name>` from the kernel cmdline and resolve
/// it to a boot group index.
fn get_active_from_cmdline(boot_entries: &BootGroups) -> Option<BootGroupIdx> {
    let cmdline = match std::fs::read_to_string("/proc/cmdline") {
        Ok(cmdline) => cmdline,
        Err(err) => {
            warn!("unable to read /proc/cmdline: {err}");
            return None;
        }
    };
    for param in cmdline.split_whitespace() {
        if let Some(group_name) = param.strip_prefix("rugix.boot_group=") {
            for (idx, entry) in boot_entries.iter() {
                if entry.name() == group_name {
                    return Some(idx);
                }
            }
            error!("rugix.boot_group={group_name} does not match any boot group");
            return None;
        }
    }
    None
}
