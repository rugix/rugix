//! Operations concerning installed applications.

use indexmap::IndexMap;
use reportify::bail;
use reportify::ResultExt;
use serde::Deserialize;
use serde::Serialize;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::local::ExecutionContext;
use super::EventSink;
use super::NoEvent;
use super::Operation;
use crate::apps::manager::AppManager;
use crate::config::apps::AppState;
use crate::config::output::AppGcAppOutput;
use crate::config::output::AppInfoOutput;
use crate::config::output::AppListEntryOutput;
use crate::config::output::ComponentsCheckOutput;
use crate::config::output::GenerationInfoOutput;
use crate::system::SystemResult;

/// List installed applications.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ListApps;

impl Operation for ListApps {
    type Input = ();
    type Event = NoEvent;
    type Output = IndexMap<String, AppListEntryOutput>;

    fn execute(
        self,
        context: &ExecutionContext<'_>,
        _input: Self::Input,
        _events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        context.with_app_manager(list_apps)
    }
}

/// Query an installed application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryApp {
    pub(crate) name: String,
}

impl Operation for QueryApp {
    type Input = ();
    type Event = NoEvent;
    type Output = AppInfoOutput;

    fn execute(
        self,
        context: &ExecutionContext<'_>,
        _input: Self::Input,
        _events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        context.with_app_manager(|manager| query_app(manager, self.name))
    }
}

/// Activate an application generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivateApp {
    pub(crate) name: String,
    pub(crate) generation: Option<u64>,
    pub(crate) skip_compatibility_check: bool,
}

impl Operation for ActivateApp {
    type Input = ();
    type Event = AppLifecycleEvent;
    type Output = ();

    fn execute(
        self,
        context: &ExecutionContext<'_>,
        _input: Self::Input,
        events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        context.with_app_manager(|manager| {
            activate_app(
                manager,
                self.name,
                self.generation,
                self.skip_compatibility_check,
                events,
            )
        })
    }
}

/// Deactivate an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeactivateApp {
    pub(crate) name: String,
    pub(crate) skip_compatibility_check: bool,
}

impl Operation for DeactivateApp {
    type Input = ();
    type Event = AppLifecycleEvent;
    type Output = ();

    fn execute(
        self,
        context: &ExecutionContext<'_>,
        _input: Self::Input,
        events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        context.with_app_manager(|manager| {
            deactivate_app(manager, &self.name, self.skip_compatibility_check, events)
        })
    }
}

/// Start an active application's workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartApp {
    pub(crate) name: String,
}

impl Operation for StartApp {
    type Input = ();
    type Event = NoEvent;
    type Output = ();

    fn execute(
        self,
        context: &ExecutionContext<'_>,
        _input: Self::Input,
        _events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        context.with_app_manager(|manager| start_app(manager, &self.name))
    }
}

/// Stop an active application's workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopApp {
    pub(crate) name: String,
}

impl Operation for StopApp {
    type Input = ();
    type Event = NoEvent;
    type Output = ();

    fn execute(
        self,
        context: &ExecutionContext<'_>,
        _input: Self::Input,
        _events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        context.with_app_manager(|manager| stop_app(manager, &self.name))
    }
}

/// Roll an application back to its previous generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackApp {
    pub(crate) name: String,
    pub(crate) skip_compatibility_check: bool,
}

impl Operation for RollbackApp {
    type Input = ();
    type Event = AppLifecycleEvent;
    type Output = ();

    fn execute(
        self,
        context: &ExecutionContext<'_>,
        _input: Self::Input,
        events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        context.with_app_manager(|manager| {
            rollback_app(manager, &self.name, self.skip_compatibility_check, events)
        })
    }
}

/// Remove an application and its generations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveApp {
    pub(crate) name: String,
    pub(crate) skip_compatibility_check: bool,
}

impl Operation for RemoveApp {
    type Input = ();
    type Event = AppLifecycleEvent;
    type Output = ();

    fn execute(
        self,
        context: &ExecutionContext<'_>,
        _input: Self::Input,
        events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        context.with_app_manager(|manager| {
            remove_app(manager, &self.name, self.skip_compatibility_check, events)
        })
    }
}

/// Garbage collect old application generations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarbageCollectApps {
    pub(crate) name: Option<String>,
    pub(crate) keep: usize,
}

impl Operation for GarbageCollectApps {
    type Input = ();
    type Event = NoEvent;
    type Output = IndexMap<String, AppGcAppOutput>;

    fn execute(
        self,
        context: &ExecutionContext<'_>,
        _input: Self::Input,
        _events: &mut dyn EventSink<Self::Event>,
    ) -> SystemResult<Self::Output> {
        context.with_app_manager(|manager| garbage_collect_apps(manager, self.name, self.keep))
    }
}

/// An event emitted while changing application lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppLifecycleEvent {
    /// An activation attempt completed.
    ActivationCompleted {
        app: String,
        generation: u64,
        outcome: String,
    },
    /// A component compatibility check failed.
    CompatibilityCheckFailed {
        /// Component compatibility report.
        report: ComponentsCheckOutput,
    },
}

fn list_apps(manager: &AppManager) -> SystemResult<IndexMap<String, AppListEntryOutput>> {
    let apps = manager.list_apps().whatever("unable to list apps")?;
    let entries = apps
        .iter()
        .map(|app| {
            let status = resolve_app_status(manager.app_status(app).ok());
            let generation = match manager.current_generation(app) {
                Ok(generation) => generation,
                Err(error) => {
                    tracing::error!(app, error = ?error, "unable to read app state");
                    None
                }
            };
            let metadata = generation.and_then(|generation| {
                manager
                    .generation_dir(app, generation)
                    .ok()
                    .and_then(|generation_dir| AppManager::read_metadata(&generation_dir))
            });
            (
                app.clone(),
                AppListEntryOutput::new(status)
                    .with_generation(generation)
                    .with_metadata(metadata),
            )
        })
        .collect();
    Ok(entries)
}

fn query_app(manager: &AppManager, app: String) -> SystemResult<AppInfoOutput> {
    let status = resolve_app_status(manager.app_status(&app).ok());
    let generations = manager
        .list_generations(&app)
        .whatever("unable to list generations")?;
    let current = manager
        .current_generation(&app)
        .whatever("unable to read app state")?;
    let state = manager
        .read_state(&app)
        .whatever("unable to read app state")?;
    let generation_entries = generations
        .iter()
        .map(|generation| {
            let metadata = manager
                .generation_dir(&app, generation.meta.number)
                .ok()
                .and_then(|generation_dir| AppManager::read_metadata(&generation_dir));
            GenerationInfoOutput::new(
                generation.meta.number,
                generation.meta.created_at.clone(),
                generation.complete,
                Some(generation.meta.number) == current,
            )
            .with_last_activated(generation.meta.last_activated.clone())
            .with_metadata(metadata)
        })
        .collect();
    Ok(AppInfoOutput::new(app, status, state, generation_entries))
}

fn activate_app(
    manager: &AppManager,
    app: String,
    generation: Option<u64>,
    skip_compatibility_check: bool,
    events: &mut dyn EventSink<AppLifecycleEvent>,
) -> SystemResult<()> {
    let lock = manager.lock_app(&app).whatever("unable to lock app")?;
    let generation = match generation {
        Some(generation) => generation,
        None => manager
            .last_activated_generation(&app)
            .whatever("unable to find last activated generation")?
            .ok_or_else(|| {
                reportify::whatever!("no previously activated generation found for {app}")
            })?,
    };
    if skip_compatibility_check {
        warn!("skipping app compatibility check");
    } else {
        check_app_generation_compatibility(manager, &app, generation, events)?;
    }
    let activation = manager.activate_generation(&lock, &app, generation);
    let state = manager
        .read_state(&app)
        .whatever("unable to read activation result")?;
    let outcome = app_activation_outcome(generation, activation.is_ok(), &state);
    if outcome == "activated" {
        info!(app, generation, outcome, "app activation completed");
    } else {
        error!(app, generation, outcome, "app activation did not complete");
    }
    events.emit(AppLifecycleEvent::ActivationCompleted {
        app,
        generation,
        outcome: outcome.to_owned(),
    });
    activation.whatever("unable to activate generation")
}

fn deactivate_app(
    manager: &AppManager,
    app: &str,
    skip_compatibility_check: bool,
    events: &mut dyn EventSink<AppLifecycleEvent>,
) -> SystemResult<()> {
    let lock = manager.lock_app(app).whatever("unable to lock app")?;
    if skip_compatibility_check {
        warn!("skipping app compatibility check");
    } else {
        check_app_removal_compatibility(manager, app, events)?;
    }
    manager
        .deactivate(&lock, app)
        .whatever("unable to deactivate app")
}

fn start_app(manager: &AppManager, app: &str) -> SystemResult<()> {
    let lock = manager.lock_app(app).whatever("unable to lock app")?;
    manager
        .start_app(&lock, app)
        .whatever("unable to start app workload")
}

fn stop_app(manager: &AppManager, app: &str) -> SystemResult<()> {
    let lock = manager.lock_app(app).whatever("unable to lock app")?;
    manager
        .stop_app(&lock, app)
        .whatever("unable to stop app workload")
}

fn rollback_app(
    manager: &AppManager,
    app: &str,
    skip_compatibility_check: bool,
    events: &mut dyn EventSink<AppLifecycleEvent>,
) -> SystemResult<()> {
    let lock = manager.lock_app(app).whatever("unable to lock app")?;
    if skip_compatibility_check {
        warn!("skipping app compatibility check");
    } else {
        let generation = manager
            .rollback_target_generation(app)
            .whatever("unable to determine rollback target generation")?;
        check_app_generation_compatibility(manager, app, generation, events)?;
    }
    manager
        .rollback(&lock, app)
        .whatever("unable to rollback app")
}

fn remove_app(
    manager: &AppManager,
    app: &str,
    skip_compatibility_check: bool,
    events: &mut dyn EventSink<AppLifecycleEvent>,
) -> SystemResult<()> {
    let lock = manager.lock_app(app).whatever("unable to lock app")?;
    if skip_compatibility_check {
        warn!("skipping app compatibility check");
    } else {
        check_app_removal_compatibility(manager, app, events)?;
    }
    manager
        .remove_app(&lock, app)
        .whatever("unable to remove app")
}

fn garbage_collect_apps(
    manager: &AppManager,
    app: Option<String>,
    keep: usize,
) -> SystemResult<IndexMap<String, AppGcAppOutput>> {
    let app_names = match app {
        Some(name) => vec![name],
        None => manager.list_apps().whatever("unable to list apps")?,
    };
    let mut results = IndexMap::new();
    for name in &app_names {
        let lock = manager.lock_app(name).whatever("unable to lock app")?;
        let removed = manager
            .gc(&lock, name, keep)
            .whatever("unable to garbage collect")?;
        results.insert(name.clone(), AppGcAppOutput::new(removed));
    }
    Ok(results)
}

fn check_app_generation_compatibility(
    manager: &AppManager,
    app: &str,
    generation: u64,
    events: &mut dyn EventSink<AppLifecycleEvent>,
) -> SystemResult<()> {
    let installed = crate::components::InstalledComponents::load()
        .whatever("unable to load installed components")?;
    let component_root = manager
        .generation_dir(app, generation)
        .whatever("invalid app name")?
        .join(".rugix/components");
    let output = installed
        .check_app_generation(app, generation, component_root)
        .whatever("unable to check app generation compatibility")?;
    require_compatible_components(output, events)
}

fn check_app_removal_compatibility(
    manager: &AppManager,
    app: &str,
    events: &mut dyn EventSink<AppLifecycleEvent>,
) -> SystemResult<()> {
    if manager
        .current_generation(app)
        .whatever("unable to read app state")?
        .is_none()
    {
        return Ok(());
    }
    let installed = crate::components::InstalledComponents::load()
        .whatever("unable to load installed components")?;
    require_compatible_components(installed.check_app_removal(app), events)
}

fn require_compatible_components(
    report: ComponentsCheckOutput,
    events: &mut dyn EventSink<AppLifecycleEvent>,
) -> SystemResult<()> {
    if report.consistent {
        return Ok(());
    }
    events.emit(AppLifecycleEvent::CompatibilityCheckFailed { report });
    bail!("component compatibility check failed")
}

fn app_activation_outcome(requested: u64, succeeded: bool, state: &AppState) -> &'static str {
    if succeeded {
        return "activated";
    }
    match state {
        AppState::Active(active) if active.generation != requested => "rolled-back",
        AppState::Error(error) if error.from.is_some() => "rollback-failed",
        _ => "failed",
    }
}

fn resolve_app_status(
    status: Option<crate::apps::orchestrators::AppStatus>,
) -> crate::apps::orchestrators::AppStatus {
    status.unwrap_or(crate::apps::orchestrators::AppStatus::Unknown)
}

#[cfg(test)]
mod tests {
    use super::app_activation_outcome;
    use crate::config::apps::AppState;
    use crate::config::apps::AppStateActive;
    use crate::config::apps::AppStateError;

    #[test]
    fn activation_outcomes_distinguish_rollback_states() {
        assert_eq!(
            app_activation_outcome(2, true, &AppState::Active(AppStateActive::new(2))),
            "activated"
        );
        assert_eq!(
            app_activation_outcome(2, false, &AppState::Active(AppStateActive::new(1))),
            "rolled-back"
        );
        assert_eq!(
            app_activation_outcome(
                2,
                false,
                &AppState::Error(AppStateError::new(2, "failure".to_owned()).with_from(Some(1)))
            ),
            "rollback-failed"
        );
        assert_eq!(
            app_activation_outcome(
                2,
                false,
                &AppState::Error(AppStateError::new(2, "failure".to_owned()))
            ),
            "failed"
        );
    }
}
