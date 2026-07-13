use std::path::PathBuf;

use reportify::bail;
use reportify::ResultExt;
use serde::Deserialize;
use serde::Serialize;
use xscript::read_str;
use xscript::Run;

use tracing::debug;
use tracing::error;

use super::BootFlow;
use super::BootFlowCapabilities;
use crate::system::boot_groups::BootGroups;

/// Custom boot flow implementation.
#[derive(Debug)]
pub struct CustomBootFlow {
    /// Path to the boot flow executable.
    pub(super) controller: PathBuf,
}

impl BootFlow for CustomBootFlow {
    fn name(&self) -> &str {
        "custom"
    }

    fn capabilities(&self) -> BootFlowCapabilities {
        let Ok(output) = read_str!([&self.controller, "capabilities"]) else {
            debug!("custom boot flow controller failed for `capabilities`");
            return BootFlowCapabilities::default();
        };
        if output.trim().is_empty() {
            debug!("custom boot flow does not implement `capabilities`");
            return BootFlowCapabilities::default();
        }
        serde_json::from_str::<BootFlowCapabilities>(&output).unwrap_or_else(|error| {
            debug!(error = ?error, "custom boot flow returned invalid output for `capabilities`");
            BootFlowCapabilities::default()
        })
    }

    fn set_try_next(
        &self,
        system: &crate::system::System,
        group: crate::system::boot_groups::BootGroupIdx,
    ) -> super::BootFlowResult<()> {
        let name = system.boot_entries()[group].name();
        let output = read_str!([&self.controller, "set_try_next", name])
            .whatever("error running `set_try_next` on custom boot flow")?;
        serde_json::from_str::<OutputNone>(&output)
            .whatever("invalid output produced by custom boot flow")?;
        Ok(())
    }

    fn get_default(
        &self,
        system: &crate::system::System,
    ) -> super::BootFlowResult<crate::system::boot_groups::BootGroupIdx> {
        let output = read_str!([&self.controller, "get_default"])
            .whatever("error running `get_default` on custom boot flow")?;
        let output = serde_json::from_str::<OutputGroup>(&output)
            .whatever("invalid output produced by custom boot flow")?;
        if let Some((idx, _)) = system.boot_entries().find_by_name(&output.group) {
            Ok(idx)
        } else {
            bail!(
                "custom boot flow returned unknown boot group {:?}",
                &output.group
            );
        }
    }

    fn commit(&self, system: &crate::system::System) -> super::BootFlowResult<()> {
        let active = system
            .require_active_boot_entry()
            .whatever("unable to commit custom boot flow")?;
        let name = system.boot_entries()[active].name();
        let output = read_str!([&self.controller, "commit", name])
            .whatever("error running `commit` on custom boot flow")?;
        serde_json::from_str::<OutputNone>(&output)
            .whatever("invalid output produced by custom boot flow")?;
        Ok(())
    }

    fn pre_install(
        &self,
        system: &crate::system::System,
        group: crate::system::boot_groups::BootGroupIdx,
    ) -> super::BootFlowResult<()> {
        let name = system.boot_entries()[group].name();
        let output = read_str!([&self.controller, "pre_install", name])
            .whatever("error running `pre_install` on custom boot flow")?;
        serde_json::from_str::<OutputNone>(&output)
            .whatever("invalid output produced by custom boot flow")?;
        Ok(())
    }

    fn post_install(
        &self,
        system: &crate::system::System,
        group: crate::system::boot_groups::BootGroupIdx,
    ) -> super::BootFlowResult<()> {
        let name = system.boot_entries()[group].name();
        let output = read_str!([&self.controller, "post_install", name])
            .whatever("error running `post_install` on custom boot flow")?;
        serde_json::from_str::<OutputNone>(&output)
            .whatever("invalid output produced by custom boot flow")?;
        Ok(())
    }

    fn mark_good(
        &self,
        system: &crate::system::System,
        group: crate::system::boot_groups::BootGroupIdx,
    ) -> super::BootFlowResult<()> {
        let name = system.boot_entries()[group].name();
        let output = read_str!([&self.controller, "mark_good", name])
            .whatever("error running `mark_good` on custom boot flow")?;
        serde_json::from_str::<OutputNone>(&output)
            .whatever("invalid output produced by custom boot flow")?;
        Ok(())
    }

    fn mark_bad(
        &self,
        system: &crate::system::System,
        group: crate::system::boot_groups::BootGroupIdx,
    ) -> super::BootFlowResult<()> {
        let name = system.boot_entries()[group].name();
        let output = read_str!([&self.controller, "mark_bad", name])
            .whatever("error running `mark_bad` on custom boot flow")?;
        serde_json::from_str::<OutputNone>(&output)
            .whatever("invalid output produced by custom boot flow")?;
        Ok(())
    }

    fn get_active(
        &self,
        boot_entries: &BootGroups,
    ) -> super::BootFlowResult<Option<crate::system::boot_groups::BootGroupIdx>> {
        // The controller may not implement get_active. Per the custom boot flow
        // contract, unknown operations produce empty stdout (and may print to
        // stderr). Treat empty output or parse failure as "unknown".
        let Ok(output) = read_str!([&self.controller, "get_active"]) else {
            error!("custom boot flow controller failed for `get_active`");
            return Ok(None);
        };
        if output.trim().is_empty() {
            debug!("custom boot flow does not implement `get_active`");
            return Ok(None);
        }
        let Ok(output) = serde_json::from_str::<OutputGroup>(&output) else {
            debug!("custom boot flow returned invalid output for `get_active`");
            return Ok(None);
        };
        Ok(boot_entries.find_by_name(&output.group).map(|(idx, _)| idx))
    }

    fn reboot(&self, _system: &crate::system::System) -> super::BootFlowResult<()> {
        // Fall back to the default reboot if the controller doesn't implement
        // `reboot`, mirroring the contract used by `get_active`.
        let output = read_str!([&self.controller, "reboot"])
            .whatever("error running `reboot` on custom boot flow")?;
        if output.trim().is_empty() {
            debug!("custom boot flow does not implement `reboot`; using default");
            return crate::utils::reboot().whatever("unable to reboot system");
        }
        serde_json::from_str::<OutputNone>(&output)
            .whatever("invalid output produced by custom boot flow")?;
        Ok(())
    }
}

/// Output type for operations that output a boot group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputGroup {
    group: String,
}

/// Output type for operations that do not provide any output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputNone {}
