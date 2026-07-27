//! Operations concerning persistent Rugix state.

use reportify::bail;
use reportify::ResultExt;
use rugix_common::path::ValidatedRelativePath;
use rugix_hooks::HooksLoader;
use serde::Deserialize;
use serde::Serialize;
use xscript::Vars;

use super::local::ExecutionContext;
use super::EventSink;
use super::NoEvent;
use super::Operation;
use crate::state::create_state_runtime_directory;
use crate::state::set_state_flag;
use crate::system::SystemResult;
use crate::utils::reboot;

/// Reset persistent system state and reboot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactoryReset {
    pub(crate) backup: bool,
    pub(crate) backup_name: Option<String>,
}

impl Operation for FactoryReset {
    type Input = ();
    type Event = NoEvent;
    type Output = ();

    fn execute(
        self,
        _context: &ExecutionContext<'_>,
        _input: Self::Input,
        _events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        factory_reset(self.backup, self.backup_name)
    }
}

fn factory_reset(backup: bool, backup_name: Option<String>) -> SystemResult<()> {
    if backup_name.is_some() && !backup {
        tracing::warn!("ignoring backup name because state backup is disabled");
    }

    let reset_hooks = HooksLoader::default()
        .load_hooks("state-reset")
        .whatever("unable to load `state-reset` hooks")?;
    reset_hooks
        .run_hooks("prepare", Vars::new(), &Default::default())
        .whatever("unable to run `state-reset/prepare` hooks")?;
    create_state_runtime_directory()?;
    if backup {
        let backup_name = backup_name.unwrap_or_else(default_backup_name);
        let backup_name =
            ValidatedRelativePath::new(backup_name).whatever("invalid state backup name")?;
        if !backup_name.is_single_component() {
            bail!("state backup name must contain exactly one path component");
        }
        set_state_flag("reset-state", Some(backup_name.as_str()))?;
    } else {
        set_state_flag("reset-state", None)?;
    }
    reboot()
}

fn default_backup_name() -> String {
    jiff::Timestamp::now()
        .strftime("default.%Y%m%d%H%M%S")
        .to_string()
}
