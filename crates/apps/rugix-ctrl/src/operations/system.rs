//! Operations concerning the Rugix system and its components.

use serde::Deserialize;
use serde::Serialize;

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

fn query_system(system: &System) -> SystemResult<SystemInfoOutput> {
    crate::system_state::state_from_system(system)
}

fn check_components() -> SystemResult<ComponentsCheckOutput> {
    let components = crate::components::InstalledComponents::load()?;
    Ok(components.check_output())
}
