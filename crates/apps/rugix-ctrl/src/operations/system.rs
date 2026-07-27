//! Operations concerning the Rugix system and its components.

use reportify::ResultExt;
use rugix_hooks::HooksLoader;
use serde::Deserialize;
use serde::Serialize;
use tracing::info;
use xscript::Vars;

use super::local::ExecutionContext;
use super::EventSink;
use super::NoEvent;
use super::Operation;
use crate::config::output::ComponentsCheckOutput;
use crate::config::output::SystemInfoOutput;
use crate::system::System;
use crate::system::SystemResult;

/// Query the current system state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct QuerySystem;

impl Operation for QuerySystem {
    type Input = ();
    type Event = NoEvent;
    type Output = SystemInfoOutput;

    fn execute(
        self,
        _context: &ExecutionContext<'_>,
        _input: Self::Input,
        _events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        let system = System::initialize()?;
        query_system(&system)
    }
}

/// Check the installed compatibility components.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CheckComponents;

impl Operation for CheckComponents {
    type Input = ();
    type Event = NoEvent;
    type Output = ComponentsCheckOutput;

    fn execute(
        self,
        _context: &ExecutionContext<'_>,
        _input: Self::Input,
        _events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        check_components()
    }
}

/// Commit the active system as the default system.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CommitSystem;

impl Operation for CommitSystem {
    type Input = ();
    type Event = NoEvent;
    type Output = ();

    fn execute(
        self,
        _context: &ExecutionContext<'_>,
        _input: Self::Input,
        _events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        commit_system()
    }
}

/// Reboot the system.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RebootSystem {
    pub(crate) spare: bool,
}

impl Operation for RebootSystem {
    type Input = ();
    type Event = NoEvent;
    type Output = ();

    fn execute(
        self,
        _context: &ExecutionContext<'_>,
        _input: Self::Input,
        _events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        reboot_system(self.spare)
    }
}

fn query_system(system: &System) -> SystemResult<SystemInfoOutput> {
    crate::system_state::state_from_system(system)
}

fn check_components() -> SystemResult<ComponentsCheckOutput> {
    let components = crate::components::InstalledComponents::load()?;
    Ok(components.check_output())
}

fn commit_system() -> SystemResult<()> {
    let system = System::initialize()?;
    if !system.needs_commit()? {
        info!("active boot group is already the default");
        return Ok(());
    }

    let hooks = HooksLoader::default()
        .load_hooks("system-commit")
        .whatever("unable to load `system-commit` hooks")?;
    hooks
        .run_hooks("pre-commit", Vars::new(), &Default::default())
        .whatever("unable to run `pre-commit` hooks")?;
    system.commit()?;
    hooks
        .run_hooks("post-commit", Vars::new(), &Default::default())
        .whatever("unable to run `post-commit` hooks")
}

fn reboot_system(spare: bool) -> SystemResult<()> {
    let system = System::initialize()?;
    if spare {
        if let Some((spare, _)) = system.spare_entry()? {
            system
                .boot_flow()
                .set_try_next(&system, spare)
                .whatever("unable to set next boot group")?;
        }
    }
    system.reboot()
}
