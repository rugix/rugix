use std::ops::Index;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{self};

use indexmap::IndexMap;
use reportify::bail;

use crate::config::system::BootGroupConfig;

use super::slots::SlotIdx;
use super::slots::SystemSlots;
use super::SystemResult;

/// Unique index of a boot group of a system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootGroupIdx {
    /// Index into the boot group vector.
    idx: usize,
}

#[derive(Debug)]
pub struct BootGroups {
    groups: Vec<BootGroup>,
}

impl BootGroups {
    pub fn from_config(
        slots: &SystemSlots,
        config: Option<&sidex::types::Map<sidex::types::Str, BootGroupConfig>>,
    ) -> SystemResult<Self> {
        let mut groups = Vec::new();
        match config {
            Some(config) => {
                for (group_name, group_config) in config.iter() {
                    let mut map = IndexMap::new();
                    for (alias, name) in &group_config.slots {
                        let Some((idx, _)) = slots.find_by_name(name) else {
                            bail!("slot {name} does not exist");
                        };
                        map.insert(alias.to_owned(), idx);
                    }
                    groups.push(BootGroup {
                        name: group_name.to_owned().into(),
                        slots: map
                            .into_iter()
                            .map(|(key, value)| (key.into(), value))
                            .collect::<IndexMap<_, _>>(),
                        active: AtomicBool::new(false),
                    })
                }
            }
            None => {
                // Create Rugix default boot groups.
                for (group_name, group_slots) in [
                    ("a", [("boot", "boot-a"), ("system", "system-a")]),
                    ("b", [("boot", "boot-b"), ("system", "system-b")]),
                ] {
                    let mut map = IndexMap::new();
                    for (alias, name) in group_slots {
                        let Some((idx, _)) = slots.find_by_name(name) else {
                            bail!("slot {name} does not exist");
                        };
                        map.insert(alias.to_owned(), idx);
                    }
                    groups.push(BootGroup {
                        name: group_name.to_owned(),
                        slots: map,
                        active: AtomicBool::new(false),
                    })
                }
            }
        }
        Ok(Self { groups })
    }

    pub fn iter(&self) -> impl Iterator<Item = (BootGroupIdx, &BootGroup)> {
        self.groups
            .iter()
            .enumerate()
            .map(|(idx, group)| (BootGroupIdx { idx }, group))
    }

    pub fn find_by_name(&self, name: &str) -> Option<(BootGroupIdx, &BootGroup)> {
        self.iter().find(|(_, group)| group.name == name)
    }
}

impl Index<BootGroupIdx> for BootGroups {
    type Output = BootGroup;

    fn index(&self, index: BootGroupIdx) -> &Self::Output {
        &self.groups[index.idx]
    }
}

#[derive(Debug)]
pub struct BootGroup {
    name: String,
    slots: IndexMap<String, SlotIdx>,
    active: AtomicBool,
}

impl BootGroup {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn slots(&self) -> impl Iterator<Item = (&str, SlotIdx)> {
        self.slots.iter().map(|(name, idx)| (name.as_str(), *idx))
    }

    pub fn active(&self) -> bool {
        self.active.load(atomic::Ordering::Acquire)
    }

    pub fn mark_active(&self) {
        self.active.store(true, atomic::Ordering::Release);
    }

    pub fn get_slot(&self, name: &str) -> Option<SlotIdx> {
        self.slots.get(name).cloned()
    }
}
