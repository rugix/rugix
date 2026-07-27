//! Operations concerning installed applications.

use indexmap::IndexMap;
use reportify::ResultExt;
use serde::Deserialize;
use serde::Serialize;

use super::local::ExecutionContext;
use super::EventSink;
use super::NoEvent;
use super::Operation;
use crate::apps::manager::AppManager;
use crate::config::output::AppInfoOutput;
use crate::config::output::AppListEntryOutput;
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

fn resolve_app_status(
    status: Option<crate::apps::orchestrators::AppStatus>,
) -> crate::apps::orchestrators::AppStatus {
    status.unwrap_or(crate::apps::orchestrators::AppStatus::Unknown)
}
