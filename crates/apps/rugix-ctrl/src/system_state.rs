use std::path::Path;

use reportify::ResultExt;
use rugix_common::disk::blkdev::find_block_device;
use tracing::error;

use crate::payload_db;
use crate::system::paths::MOUNT_POINT_DATA;
use crate::system::System;
use crate::system::SystemResult;

use crate::config::output::BootGroupInfoOutput;
use crate::config::output::BootInfoOutput;
use crate::config::output::SlotInfoOutput;
use crate::config::output::StateInfoActiveOutput;
use crate::config::output::StateInfoOutput;
use crate::config::output::SystemInfoOutput;

pub fn state_from_system(system: &System) -> SystemResult<SystemInfoOutput> {
    let boot_flow = system.boot_flow().name().to_owned();
    let slots = system
        .slots()
        .iter()
        .map(|(_, slot)| {
            let slot_state = match payload_db::get_stored_state(slot.name()) {
                Ok(state) => state,
                Err(error) => {
                    error!("unable to get state for slot {}: {:?}", slot.name(), error);
                    None
                }
            };
            (
                slot.name().to_owned(),
                SlotInfoOutput {
                    active: Some(slot.active()),
                    hashes: slot_state.as_ref().map(|s| {
                        s.hashes
                            .iter()
                            .map(|(a, h)| (a.name().to_owned(), h.to_string()))
                            .collect()
                    }),
                    size: slot_state.as_ref().and_then(|s| s.size.map(|s| s.raw)),
                    updated_at: slot_state
                        .as_ref()
                        .and_then(|s| s.updated_at.map(|t| t.to_string())),
                },
            )
        })
        .collect();
    let active_boot_group = system
        .active_boot_entry()
        .map(|idx| system.boot_entries()[idx].name().to_owned());
    let default = system
        .boot_flow()
        .get_default(system)
        .whatever("unable to determine default boot group")?;
    let default_boot_group = Some(system.boot_entries()[default].name().to_owned());
    let boot_groups = system
        .boot_entries()
        .iter()
        .map(|(_, group)| (group.name().to_owned(), BootGroupInfoOutput {}))
        .collect();
    let state = state_status(
        Path::new("/run/rugix/state").exists(),
        Path::new("/run/rugix/state/.rugix/overlay-fallback-error.log").exists(),
        Path::new(MOUNT_POINT_DATA)
            .join(".rugix/data-mount-error.log")
            .exists(),
        find_block_device(MOUNT_POINT_DATA)
            .ok()
            .flatten()
            .map(|dev| dev.path().to_string_lossy().into_owned()),
    );
    Ok(
        SystemInfoOutput::new(slots, state).with_boot(Some(BootInfoOutput {
            boot_flow,
            active_group: active_boot_group,
            default_group: default_boot_group,
            groups: boot_groups,
        })),
    )
}

fn state_status(
    state_exists: bool,
    overlay_failed: bool,
    data_mount_failed: bool,
    data_device: Option<String>,
) -> StateInfoOutput {
    if !state_exists {
        StateInfoOutput::Disabled
    } else if data_mount_failed {
        StateInfoOutput::EphemeralFallback
    } else if overlay_failed {
        StateInfoOutput::Error
    } else {
        StateInfoOutput::Active(StateInfoActiveOutput::new().with_data_partition(data_device))
    }
}

#[cfg(test)]
mod tests {
    use super::state_status;
    use crate::config::output::StateInfoOutput;

    #[test]
    fn state_status_exposes_data_mount_fallback() {
        assert!(matches!(
            state_status(true, false, true, None),
            StateInfoOutput::EphemeralFallback
        ));
        assert!(matches!(
            state_status(true, true, false, None),
            StateInfoOutput::Error
        ));
        assert!(matches!(
            state_status(true, false, false, Some("/dev/test".to_owned())),
            StateInfoOutput::Active(_)
        ));
    }
}
