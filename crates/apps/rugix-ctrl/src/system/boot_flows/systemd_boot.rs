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
        let mut entries = Vec::new();
        for (group_name, entry_id) in entries_config {
            let Some((idx, _)) = system.find_by_name(group_name) else {
                bail!("unknown boot group {group_name:?} in systemd-boot entries config");
            };
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

/// Read a systemd-boot EFI variable and decode its UTF-16LE value.
fn read_loader_efi_var(name: &str) -> Option<String> {
    let path = format!("/sys/firmware/efi/efivars/{name}-{LOADER_GUID}");
    let data = std::fs::read(Path::new(&path)).ok()?;
    if data.len() < 4 {
        return None;
    }
    // Skip 4 bytes of EFI variable attributes, decode UTF-16LE.
    let utf16: Vec<u16> = data[4..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    Some(
        String::from_utf16_lossy(&utf16)
            .trim_end_matches('\0')
            .to_string(),
    )
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
        read_str!(["bootctl", "set-oneshot", entry_id])
            .whatever("error running `bootctl set-oneshot`")?;
        Ok(())
    }

    fn commit(&self, system: &System) -> BootFlowResult<()> {
        let active = system
            .require_active_boot_entry()
            .whatever("unable to commit systemd-boot flow")?;
        let entry_id = self.entry_id_for_group(active)?;
        read_str!(["bootctl", "set-default", entry_id])
            .whatever("error running `bootctl set-default`")?;
        Ok(())
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
