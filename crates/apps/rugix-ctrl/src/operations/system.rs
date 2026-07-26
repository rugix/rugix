//! Operations concerning the Rugix system and its components.

use reportify::whatever;
use reportify::ResultExt;
use rugix_bundle::source::ReaderSource;
use rugix_bundle::source::SkipRead;
use rugix_bundle::source::SkipSeek;
use serde::Deserialize;
use serde::Serialize;
use tracing::info;

use super::bundle::BundleInput;
use super::bundle::BundleInstallEvent;
use super::bundle::BundleInstallOptions;
use super::bundle::InstallSource;
use super::local::ExecutionContext;
use super::EventSink;
use super::NoEvent;
use super::Operation;
use crate::cli::install_update_bundle;
use crate::config::output::ComponentsCheckOutput;
use crate::config::output::SystemInfoOutput;
use crate::http_source::HttpSource;
use crate::payload_db;
use crate::system::System;
use crate::system::SystemResult;
use crate::utils::lock_update;
use crate::utils::set_deferred_reboot_target;

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

/// Install a system bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSystemBundle {
    pub(crate) source: InstallSource,
    pub(crate) options: BundleInstallOptions,
    pub(crate) reboot: Option<SystemRebootMode>,
    pub(crate) keep_overlay: bool,
    pub(crate) boot_group: Option<String>,
}

impl Operation for InstallSystemBundle {
    type Input = BundleInput;
    type Event = BundleInstallEvent;
    type Output = ();

    fn execute(
        self,
        context: &ExecutionContext<'_>,
        input: Self::Input,
        events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        let _update_lock = lock_update()?;
        events.emit(BundleInstallEvent::Started);
        let system = System::initialize()?;
        execute_system_bundle_install(context, &system, self, input, events)
    }
}

/// Post-installation behavior for a system update.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SystemRebootMode {
    /// Select the installed system and reboot.
    Yes,
    /// Leave boot selection unchanged.
    No,
    /// Select the installed system without rebooting.
    Set,
    /// Defer boot selection until the next boot.
    Deferred,
}

fn query_system(system: &System) -> SystemResult<SystemInfoOutput> {
    crate::system_state::state_from_system(system)
}

fn check_components() -> SystemResult<ComponentsCheckOutput> {
    let components = crate::components::InstalledComponents::load()?;
    Ok(components.check_output())
}

fn execute_system_bundle_install(
    context: &ExecutionContext<'_>,
    system: &System,
    operation: InstallSystemBundle,
    input: BundleInput,
    events: &mut dyn EventSink<BundleInstallEvent>,
) -> SystemResult<()> {
    if system.needs_commit()? {
        reportify::bail!("system needs to be committed before installing an update");
    }

    let boot_group = match operation.boot_group.as_deref() {
        Some(group_name) => {
            let Some(group) = system.boot_entries().find_by_name(group_name) else {
                reportify::bail!("unable to find boot group {group_name}");
            };
            Some(group)
        }
        None => {
            if system.boot_entries().iter().count() > 2 {
                None
            } else {
                system
                    .boot_entries()
                    .iter()
                    .find(|(_, entry)| !entry.active())
            }
        }
    };
    if let Some((_, boot_group)) = boot_group {
        info!("installing update to boot group {:?}", boot_group.name());
        if boot_group.active() {
            reportify::bail!("selected boot group {} is active", boot_group.name());
        }
    }

    let config = context.config();
    let default_reboot = match operation.source {
        InstallSource::Stream => match input {
            BundleInput::None => {
                reportify::bail!("bundle input stream is required");
            }
            BundleInput::Stream(input) => {
                let source = ReaderSource::<_, SkipRead>::from_unbuffered(input);
                install_update_bundle(
                    system,
                    config,
                    source,
                    boot_group.as_ref(),
                    &operation.options,
                    operation.keep_overlay,
                    events,
                )?
            }
            BundleInput::Seekable(input) => {
                let source = ReaderSource::<_, SkipSeek>::from_unbuffered(input);
                install_update_bundle(
                    system,
                    config,
                    source,
                    boot_group.as_ref(),
                    &operation.options,
                    operation.keep_overlay,
                    events,
                )?
            }
        },
        InstallSource::Http {
            url,
            disable_range_queries,
            retry,
        } => {
            if !matches!(input, BundleInput::None) {
                reportify::bail!("HTTP bundle source does not accept an input stream");
            }
            let mut has_indices = false;
            for (_, slot) in system.slots().iter() {
                has_indices |= payload_db::get_stored_indices(slot.name())
                    .map(|indices| !indices.is_empty())
                    .unwrap_or_default();
                if has_indices {
                    break;
                }
            }
            let mut source = HttpSource::new(&url, !disable_range_queries && has_indices, retry)?;
            let reboot = install_update_bundle(
                system,
                config,
                &mut source,
                boot_group.as_ref(),
                &operation.options,
                operation.keep_overlay,
                events,
            )?;
            let stats = source.get_download_stats();
            info!(
                "downloaded {:.1}% ({}/{}) of the full bundle",
                stats.download_ratio() * 100.0,
                stats.bytes_read,
                stats.total_bytes(),
            );
            reboot
        }
    };

    match operation.reboot.unwrap_or(default_reboot) {
        SystemRebootMode::Yes => {
            let (entry_idx, boot_group) = require_update_target(boot_group, "reboot")?;
            info!(
                "instructing boot flow to try booting into {:?}",
                boot_group.name()
            );
            system
                .boot_flow()
                .set_try_next(system, entry_idx)
                .whatever("unable to set next boot group")?;
            info!("rebooting");
            system.reboot()?;
        }
        SystemRebootMode::No => {}
        SystemRebootMode::Set => {
            let (entry_idx, boot_group) = require_update_target(boot_group, "boot selection")?;
            info!(
                "instructing boot flow to try booting into {:?}",
                boot_group.name()
            );
            system
                .boot_flow()
                .set_try_next(system, entry_idx)
                .whatever("unable to set next boot group")?;
        }
        SystemRebootMode::Deferred => {
            let (_, target) = require_update_target(boot_group, "deferred reboot")?;
            set_deferred_reboot_target(target.name())?;
        }
    }

    Ok(())
}

fn require_update_target<T: Copy>(target: Option<T>, operation: &str) -> SystemResult<T> {
    target.ok_or_else(|| whatever!("{operation} requires a target boot group"))
}
