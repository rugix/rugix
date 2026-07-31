//! Builds machine-readable snapshots of the configured Rugix system.
//!
//! The primary entry point is [`state_from_system`], which reports slot, boot, and
//! state-management status.

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
use crate::config::output::StateInfoErrorOutput;
use crate::config::output::StateInfoOutput;
use crate::config::output::SystemInfoOutput;

pub fn state_from_system(system: &System) -> SystemResult<SystemInfoOutput> {
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
    let boot = if system.has_boot_flow() {
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
        Some(BootInfoOutput {
            boot_flow: system.boot_flow().name().to_owned(),
            active_group: active_boot_group,
            default_group: default_boot_group,
            groups: boot_groups,
        })
    } else {
        None
    };
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
    Ok(SystemInfoOutput::new(slots, state).with_boot(boot))
}

const DATA_MOUNT_ERROR_MESSAGE: &str =
    "The data partition failed to mount. State is temporarily stored in memory and will not persist.";
const OVERLAY_ERROR_MESSAGE: &str = "The configured root overlay failed. The in-memory fallback is active and overlay changes will not persist.";

fn state_status(
    state_exists: bool,
    overlay_failed: bool,
    data_mount_failed: bool,
    data_device: Option<String>,
) -> StateInfoOutput {
    if !state_exists {
        StateInfoOutput::Disabled
    } else if data_mount_failed {
        state_error(DATA_MOUNT_ERROR_MESSAGE)
    } else if overlay_failed {
        state_error(OVERLAY_ERROR_MESSAGE)
    } else {
        StateInfoOutput::Active(StateInfoActiveOutput::new().with_data_partition(data_device))
    }
}

/// Builds an error status with optional details for additive wire compatibility.
fn state_error(message: &str) -> StateInfoOutput {
    StateInfoOutput::Error(
        StateInfoErrorOutput::new()
            .with_message(Some(message.to_owned()))
            .with_ephemeral(Some(true)),
    )
}

#[cfg(test)]
mod tests {
    use super::state_status;
    use crate::config::output::StateInfoOutput;
    use crate::config::output::SystemInfoOutput;

    #[test]
    fn system_info_without_boot_omits_boot_field() {
        let output = SystemInfoOutput::new(Default::default(), StateInfoOutput::Disabled);
        let json = serde_json::to_value(output).unwrap();
        assert!(json.get("boot").is_none());
    }

    /// Verifies that fallback modes retain the established error status and expose
    /// details.
    #[test]
    fn state_status_reports_fallbacks_as_errors() {
        let data_mount_state = state_status(true, false, true, None);
        let data_mount_json = serde_json::to_value(&data_mount_state).unwrap();
        assert_eq!(data_mount_json["status"], "Error");
        assert_eq!(data_mount_json["ephemeral"], true);

        let StateInfoOutput::Error(data_mount_error) = data_mount_state else {
            panic!("a data mount fallback should be reported as an error");
        };
        assert_eq!(data_mount_error.ephemeral, Some(true));
        assert!(data_mount_error
            .message
            .as_deref()
            .is_some_and(|message| message.contains("data partition failed to mount")));

        let StateInfoOutput::Error(overlay_error) = state_status(true, true, false, None) else {
            panic!("an overlay fallback should be reported as an error");
        };
        assert_eq!(overlay_error.ephemeral, Some(true));
        assert!(overlay_error
            .message
            .as_deref()
            .is_some_and(|message| message.contains("root overlay failed")));

        assert!(matches!(
            state_status(true, false, false, Some("/dev/test".to_owned())),
            StateInfoOutput::Active(_)
        ));
    }

    /// Verifies that error output from older Rugix Ctrl versions remains valid.
    #[test]
    fn state_error_accepts_legacy_output_without_details() {
        let state = serde_json::from_str::<StateInfoOutput>(r#"{"status":"Error"}"#).unwrap();
        let StateInfoOutput::Error(error) = state else {
            panic!("the legacy error status should deserialize as an error");
        };
        assert!(error.message.is_none());
        assert!(error.ephemeral.is_none());
    }
}
