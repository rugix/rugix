//! Boot flow for systemd-boot.
//!
//! Uses EFI variables (`LoaderEntryDefault`, `LoaderEntryOneShot`) to control
//! which boot entry is selected by systemd-boot. All state changes are atomic
//! EFI variable writes performed by `bootctl`.

use std::path::Path;

use reportify::bail;
use reportify::ResultExt;
use tracing::warn;
use xscript::read_str;
use xscript::Run;

use super::BootFlow;
use super::BootFlowResult;
use crate::system::boot_groups::BootGroupIdx;
use crate::system::boot_groups::BootGroups;
use crate::system::System;

/// The GUID for systemd's loader EFI variables.
const LOADER_GUID: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

/// Systemd-boot boot flow implementation.
#[derive(Debug)]
pub struct SystemdBootFlow {
    /// Mapping from boot group indices to systemd-boot entry IDs.
    entries: Vec<(BootGroupIdx, String)>,
}

impl SystemdBootFlow {
    pub fn new(
        system: &super::super::boot_groups::BootGroups,
        entries_config: &indexmap::IndexMap<String, String>,
    ) -> BootFlowResult<Self> {
        if entries_config.len() != system.iter().count() {
            bail!("systemd-boot requires exactly one entry for every boot group");
        }
        let mut entries = Vec::new();
        let mut entry_ids = hashbrown::HashSet::new();
        for (group_name, entry_id) in entries_config {
            let Some((idx, _)) = system.find_by_name(group_name) else {
                bail!("unknown boot group {group_name:?} in systemd-boot entries config");
            };
            if entry_id.trim().is_empty() {
                bail!("systemd-boot entry ID for group {group_name:?} must not be empty");
            }
            if !entry_ids.insert(entry_id) {
                bail!("duplicate systemd-boot entry ID {entry_id:?}");
            }
            entries.push((idx, entry_id.clone()));
        }
        if entries.len() < 2 {
            bail!("systemd-boot boot flow requires at least 2 entries");
        }
        Ok(Self { entries })
    }

    fn entry_id_for_group(&self, group: BootGroupIdx) -> BootFlowResult<&str> {
        for (idx, entry_id) in &self.entries {
            if *idx == group {
                return Ok(entry_id);
            }
        }
        bail!("no systemd-boot entry configured for boot group");
    }

    fn group_for_entry_id(&self, entry_id: &str) -> Option<BootGroupIdx> {
        for (idx, id) in &self.entries {
            if id == entry_id {
                return Some(*idx);
            }
        }
        None
    }
}

fn decode_loader_efi_var(data: &[u8]) -> Option<String> {
    let value = data.get(4..)?;
    if value.len() % 2 != 0 {
        return None;
    }
    let utf16 = value
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| u16::from_le_bytes(*bytes))
        .collect::<Vec<_>>();
    String::from_utf16(&utf16)
        .ok()
        .map(|value| value.trim_end_matches('\0').to_owned())
}

fn run_bootctl(
    action: &'static str,
    entry_id: &str,
    run: impl FnOnce(&str, &str) -> BootFlowResult<()>,
) -> BootFlowResult<()> {
    run(action, entry_id)
}

/// Read a systemd-boot EFI variable and decode its UTF-16LE value.
fn read_loader_efi_var(name: &str) -> Option<String> {
    let path = format!("/sys/firmware/efi/efivars/{name}-{LOADER_GUID}");
    let data = std::fs::read(Path::new(&path)).ok()?;
    decode_loader_efi_var(&data)
}

impl BootFlow for SystemdBootFlow {
    fn name(&self) -> &str {
        "systemd-boot"
    }

    fn get_default(&self, _system: &System) -> BootFlowResult<BootGroupIdx> {
        if let Some(entry_id) = read_loader_efi_var("LoaderEntryDefault") {
            if let Some(group) = self.group_for_entry_id(&entry_id) {
                return Ok(group);
            }
            warn!(
                entry_id,
                "LoaderEntryDefault does not match any configured entry"
            );
        }
        // Fall back to the first configured entry.
        Ok(self.entries[0].0)
    }

    fn set_try_next(&self, _system: &System, group: BootGroupIdx) -> BootFlowResult<()> {
        let entry_id = self.entry_id_for_group(group)?;
        run_bootctl("set-oneshot", entry_id, |action, entry_id| {
            read_str!(["bootctl", action, entry_id])
                .whatever("error running `bootctl set-oneshot`")?;
            Ok(())
        })
    }

    fn commit(&self, system: &System) -> BootFlowResult<()> {
        let active = system
            .require_active_boot_entry()
            .whatever("unable to commit systemd-boot flow")?;
        let entry_id = self.entry_id_for_group(active)?;
        run_bootctl("set-default", entry_id, |action, entry_id| {
            read_str!(["bootctl", action, entry_id])
                .whatever("error running `bootctl set-default`")?;
            Ok(())
        })
    }

    fn get_active(&self, _boot_entries: &BootGroups) -> BootFlowResult<Option<BootGroupIdx>> {
        // LoaderEntrySelected is set by systemd-boot at boot time and is
        // immutable for the lifetime of the session — it always reflects
        // what was actually booted, regardless of subsequent set_try_next
        // or commit calls.
        if let Some(entry_id) = read_loader_efi_var("LoaderEntrySelected") {
            return Ok(self.group_for_entry_id(&entry_id));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use indexmap::IndexMap;

    use super::decode_loader_efi_var;
    use super::run_bootctl;
    use super::SystemdBootFlow;
    use crate::config::system::BootGroupConfig;
    use crate::config::system::FileSlotConfig;
    use crate::config::system::SlotConfig;
    use crate::system::boot_groups::BootGroups;
    use crate::system::slots::SystemSlots;

    fn groups() -> (SystemSlots, BootGroups) {
        let slot_config = ["a", "b"]
            .into_iter()
            .map(|name| {
                (
                    format!("system-{name}"),
                    SlotConfig::File(FileSlotConfig {
                        path: format!("/tmp/system-{name}"),
                        immutable: Some(true),
                    }),
                )
            })
            .collect::<IndexMap<_, _>>();
        let slots = SystemSlots::from_config(None, Some(&slot_config)).unwrap();
        let group_config = ["a", "b"]
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    BootGroupConfig {
                        slots: [("system".to_owned(), format!("system-{name}"))]
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
    fn entry_mapping_is_complete_unique_and_nonempty() {
        let (_, groups) = groups();
        let valid = [
            ("a".to_owned(), "rugix-a.conf".to_owned()),
            ("b".to_owned(), "rugix-b.conf".to_owned()),
        ]
        .into_iter()
        .collect();
        assert!(SystemdBootFlow::new(&groups, &valid).is_ok());

        let missing = [("a".to_owned(), "rugix-a.conf".to_owned())]
            .into_iter()
            .collect();
        assert!(SystemdBootFlow::new(&groups, &missing).is_err());
        let duplicate = [
            ("a".to_owned(), "same.conf".to_owned()),
            ("b".to_owned(), "same.conf".to_owned()),
        ]
        .into_iter()
        .collect();
        assert!(SystemdBootFlow::new(&groups, &duplicate).is_err());
        let empty = [
            ("a".to_owned(), "rugix-a.conf".to_owned()),
            ("b".to_owned(), "".to_owned()),
        ]
        .into_iter()
        .collect();
        assert!(SystemdBootFlow::new(&groups, &empty).is_err());
    }

    #[test]
    fn mapping_and_commands_cover_stable_trial_commit_rollback_and_invalid_states() {
        let (_, groups) = groups();
        let config = [
            ("a".to_owned(), "rugix-a.conf".to_owned()),
            ("b".to_owned(), "rugix-b.conf".to_owned()),
        ]
        .into_iter()
        .collect();
        let flow = SystemdBootFlow::new(&groups, &config).unwrap();
        let a = groups.find_by_name("a").unwrap().0;
        let b = groups.find_by_name("b").unwrap().0;

        assert_eq!(flow.group_for_entry_id("rugix-a.conf"), Some(a));
        assert_eq!(flow.group_for_entry_id("rugix-b.conf"), Some(b));
        assert_eq!(flow.group_for_entry_id("missing.conf"), None);
        assert_eq!(flow.entry_id_for_group(a).unwrap(), "rugix-a.conf");
        assert_eq!(flow.entry_id_for_group(b).unwrap(), "rugix-b.conf");

        let commands = RefCell::new(Vec::new());
        run_bootctl(
            "set-oneshot",
            flow.entry_id_for_group(b).unwrap(),
            |action, id| {
                commands
                    .borrow_mut()
                    .push((action.to_owned(), id.to_owned()));
                Ok(())
            },
        )
        .unwrap();
        run_bootctl(
            "set-default",
            flow.entry_id_for_group(b).unwrap(),
            |action, id| {
                commands
                    .borrow_mut()
                    .push((action.to_owned(), id.to_owned()));
                Ok(())
            },
        )
        .unwrap();
        run_bootctl(
            "set-oneshot",
            flow.entry_id_for_group(a).unwrap(),
            |action, id| {
                commands
                    .borrow_mut()
                    .push((action.to_owned(), id.to_owned()));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            *commands.borrow(),
            [
                ("set-oneshot".to_owned(), "rugix-b.conf".to_owned()),
                ("set-default".to_owned(), "rugix-b.conf".to_owned()),
                ("set-oneshot".to_owned(), "rugix-a.conf".to_owned()),
            ]
        );
    }

    #[test]
    fn efi_variable_decoder_rejects_truncated_odd_and_invalid_utf16_values() {
        let mut valid = vec![0, 0, 0, 0];
        for unit in "rugix-a.conf\0".encode_utf16() {
            valid.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            decode_loader_efi_var(&valid).as_deref(),
            Some("rugix-a.conf")
        );
        assert_eq!(decode_loader_efi_var(&[0, 0, 0]), None);
        assert_eq!(decode_loader_efi_var(&[0, 0, 0, 0, 1]), None);
        assert_eq!(decode_loader_efi_var(&[0, 0, 0, 0, 0, 0xd8]), None);
    }
}
