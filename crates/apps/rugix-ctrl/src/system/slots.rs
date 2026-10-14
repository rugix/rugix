use std::ops::Index;
use std::path::PathBuf;
use std::sync::Mutex;

use reportify::bail;
use reportify::whatever;
use tracing::warn;

use crate::config::system::BlockSlotConfig;
use crate::config::system::SlotConfig;

use super::root::SystemRoot;
use super::SystemResult;
use rugix_common::disk::blkdev::BlockDevice;

/// Unique index of a slot of a system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotIdx {
    /// Index into the slot vector.
    idx: usize,
}

/// Slots of a system.
pub struct SystemSlots {
    /// Slots of the system.
    slots: Vec<Slot>,
}

impl SystemSlots {
    fn from_iter<'i, I>(root: Option<&SystemRoot>, iter: I) -> SystemResult<Self>
    where
        I: Iterator<Item = (&'i str, &'i SlotConfig)>,
    {
        let mut slots = Vec::new();
        for (name, config) in iter {
            let kind = match config {
                SlotConfig::Block(block_slot_config) => {
                    let optional = block_slot_config.optional.unwrap_or(false);
                    // Human-readable identifier for diagnostics when the slot is absent.
                    let intended = if let Some(device) = &block_slot_config.device {
                        device.to_string()
                    } else if let Some(partition) = &block_slot_config.partition {
                        format!("partition {partition} of the root device")
                    } else {
                        bail!("invalid configuration: no device and partition for {name}");
                    };
                    let resolution = resolve_block_slot(root, block_slot_config);
                    let device = match resolution {
                        Ok(device) => Some(device),
                        Err(reason) if optional => {
                            warn!(
                                "slot {name:?} is marked optional and could not be \
                                 resolved ({intended}): {reason}"
                            );
                            None
                        }
                        Err(reason) => {
                            bail!("unable to resolve slot {name:?} ({intended}): {reason}")
                        }
                    };
                    SlotKind::Block(BlockSlot {
                        device,
                        intended_path: intended,
                    })
                }
                SlotConfig::File(file_slot_config) => SlotKind::File {
                    path: file_slot_config.path.clone().into(),
                },
                SlotConfig::Custom(custom_slot_config) => SlotKind::Custom {
                    handler: custom_slot_config
                        .handler
                        .clone()
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<_>>(),
                },
            };
            slots.push(Slot::new(name.to_owned(), kind, config.clone()));
        }
        Ok(Self { slots })
    }

    pub fn from_config(
        root: Option<&SystemRoot>,
        config: Option<&sidex::types::Map<sidex::types::Str, SlotConfig>>,
    ) -> SystemResult<Self> {
        match config {
            Some(config) => Self::from_iter(
                root,
                config.iter().map(|(name, config)| (name.as_str(), config)),
            ),
            None => {
                let Some(root) = root else {
                    bail!("no system root")
                };
                let Some(table) = &root.table else {
                    bail!("unable to determine slots: no table");
                };
                let default_slots = if table.is_mbr() {
                    DEFAULT_MBR_SLOTS
                } else {
                    DEFAULT_GPT_SLOTS
                };
                Self::from_iter(
                    Some(root),
                    default_slots.iter().map(|(name, config)| (*name, config)),
                )
            }
        }
    }

    /// Find a slot by its name.
    pub fn find_by_name(&self, name: &str) -> Option<(SlotIdx, &Slot)> {
        // There are only a few slots, so we can get away with linear search.
        self.iter().find(|(_, slot)| slot.name == name)
    }

    /// Iterator of the slots.
    pub fn iter(&self) -> impl Iterator<Item = (SlotIdx, &Slot)> {
        self.slots
            .iter()
            .enumerate()
            .map(|(idx, slot)| (SlotIdx { idx }, slot))
    }
}

impl Index<SlotIdx> for SystemSlots {
    type Output = Slot;

    fn index(&self, index: SlotIdx) -> &Self::Output {
        &self.slots[index.idx]
    }
}

#[derive(Debug)]
pub struct Slot {
    name: String,
    kind: SlotKind,
    config: SlotConfig,
    active: Mutex<bool>,
}

impl Slot {
    /// Create a new slot.
    fn new(name: String, kind: SlotKind, config: SlotConfig) -> Self {
        Self {
            name,
            kind,
            config,
            active: Mutex::new(false),
        }
    }

    /// Name of the slot.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Kind of the slot.
    pub fn kind(&self) -> &SlotKind {
        &self.kind
    }

    /// Slot configuration.
    pub fn config(&self) -> &SlotConfig {
        &self.config
    }

    /// Indicates whether the slot is active.
    pub fn active(&self) -> bool {
        *self.active.lock().unwrap()
    }

    /// Indicates whether the slot is of type `block`.
    pub fn is_block(&self) -> bool {
        matches!(self.kind, SlotKind::Block(_))
    }

    /// Indicates whether the slot is immutable.
    pub fn is_immutable(&self) -> bool {
        match &self.config {
            SlotConfig::Block(config) => config.immutable.unwrap_or(false),
            SlotConfig::File(config) => config.immutable.unwrap_or(false),
            SlotConfig::Custom(_) => false,
        }
    }

    /// Indicates whether the slot is marked optional in the configuration.
    pub fn is_optional(&self) -> bool {
        match &self.config {
            SlotConfig::Block(config) => config.optional.unwrap_or(false),
            _ => false,
        }
    }

    /// Indicates whether the slot is available (i.e., its underlying
    /// resource is currently resolvable).
    ///
    /// Non-block slots are always considered available. Block slots that
    /// are marked optional and whose device is missing at init time are
    /// reported as unavailable.
    pub fn is_available(&self) -> bool {
        match &self.kind {
            SlotKind::Block(block) => block.device.is_some(),
            SlotKind::File { .. } | SlotKind::Custom { .. } => true,
        }
    }

    /// Returns the resolved block device if the slot is an available
    /// block slot; returns `None` for absent or non-block slots.
    pub fn block_device(&self) -> Option<&BlockDevice> {
        match &self.kind {
            SlotKind::Block(block) => block.device.as_ref(),
            _ => None,
        }
    }

    /// Require that the slot is an available block slot, returning its
    /// device. Used at write sites (update / install), where an absent
    /// target must be a hard error.
    pub fn require_available_block(&self) -> SystemResult<&BlockDevice> {
        match &self.kind {
            SlotKind::Block(block) => block.device.as_ref().ok_or_else(|| {
                whatever!(
                    "slot {:?} is not available: {} is not present",
                    self.name,
                    block.intended_path
                )
            }),
            _ => bail!("slot {:?} is not a block slot", self.name),
        }
    }

    /// Mark the slot as active. No-op (with a warning) if the slot is
    /// not currently available — absent slots cannot be the running
    /// system.
    pub fn mark_active(&self) {
        if !self.is_available() {
            warn!(
                "refusing to mark slot {:?} active: slot is not available",
                self.name
            );
            return;
        }
        *self.active.lock().unwrap() = true;
    }
}

#[derive(Debug)]
pub enum SlotKind {
    Block(BlockSlot),
    File { path: PathBuf },
    Custom { handler: Vec<String> },
}

/// Block device slot.
///
/// A block slot always records the device path declared in the system
/// configuration (`intended_path`); the actual [`BlockDevice`] handle
/// is `None` if the slot is marked optional and the device could not
/// be resolved at construction time.
#[derive(Debug)]
pub struct BlockSlot {
    device: Option<BlockDevice>,
    intended_path: String,
}

impl BlockSlot {
    /// Returns the resolved block device, or `None` if the slot is
    /// currently absent.
    pub fn device(&self) -> Option<&BlockDevice> {
        self.device.as_ref()
    }

    /// The device path or partition descriptor declared in the
    /// configuration. Useful for diagnostics even when the slot is
    /// absent.
    pub fn intended_path(&self) -> &str {
        &self.intended_path
    }
}

/// Resolve the block device for a block slot configuration.
///
/// Returns a human-readable reason string on failure — these end up in
/// log lines when the slot is optional, and in the returned error when
/// it isn't.
fn resolve_block_slot(
    root: Option<&SystemRoot>,
    config: &BlockSlotConfig,
) -> Result<BlockDevice, String> {
    if let Some(device) = &config.device {
        BlockDevice::new(device).map_err(|err| format!("{err}"))
    } else if let Some(partition) = &config.partition {
        let root = root.ok_or_else(|| "no system root".to_owned())?;
        root.resolve_partition(*partition)
            .ok_or_else(|| format!("partition {partition} not found on root device"))
    } else {
        Err("no device and no partition specified".to_owned())
    }
}

/// Default slots of an MBR-partitioned root device.
const DEFAULT_MBR_SLOTS: &[(&str, SlotConfig)] = &[
    ("boot-a", default_slot_config(2, false)),
    ("boot-b", default_slot_config(3, false)),
    ("system-a", default_slot_config(5, true)),
    ("system-b", default_slot_config(6, true)),
];

/// Default slots of a GPT-partitioned root device.
const DEFAULT_GPT_SLOTS: &[(&str, SlotConfig)] = &[
    ("boot-a", default_slot_config(2, false)),
    ("boot-b", default_slot_config(3, false)),
    ("system-a", default_slot_config(4, true)),
    ("system-b", default_slot_config(5, true)),
];

/// Configuration of default slots for the given partition.
const fn default_slot_config(partition: u32, immutable: bool) -> SlotConfig {
    SlotConfig::Block(BlockSlotConfig {
        device: None,
        partition: Some(partition),
        immutable: Some(immutable),
        optional: None,
    })
}
