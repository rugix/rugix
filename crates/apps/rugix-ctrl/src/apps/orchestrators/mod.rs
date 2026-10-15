//! Orchestrator implementations.

use std::path::Path;

use rugix_bundle::manifest::AppManifest;

use crate::config::apps::AppConfiguration;

use super::files::GenerationFiles;
use super::AppsResult;
pub use crate::config::apps::AppStatus;
pub use crate::config::apps::AppStatusMessage;

mod binary;
mod docker_compose;
mod generic;

/// Context passed to orchestrator methods.
pub struct AppContext<'cx> {
    /// App name.
    pub app_name: &'cx str,
    /// Path to the app directory.
    pub app_dir: &'cx Path,
    /// Generation number.
    pub generation: u64,
    /// Path to the generation directory.
    pub generation_dir: &'cx Path,
    /// Payload files of the generation, including those kept in the store.
    pub files: &'cx GenerationFiles,
    /// Path to persistent app data (survives across generations).
    pub data_dir: &'cx Path,
    /// Path to the effective JSON application configuration, if one exists.
    pub configuration_path: Option<&'cx Path>,
    /// Parsed effective JSON application configuration, if one exists.
    pub configuration: Option<&'cx AppConfiguration>,
    /// Whether this invocation is recovering from an interrupted transition.
    pub recovery: bool,
    /// The system's configured service manager (e.g., `"systemd"`, `"none"`).
    pub service_manager: &'cx str,
    /// The parsed app manifest (`app.toml`).
    pub manifest: &'cx AppManifest,
}

/// Trait for app lifecycle orchestrators.
pub trait Orchestrator: Send + Sync {
    /// Unique identifier (e.g., "docker-compose").
    fn name(&self) -> &str;

    /// Activate a generation: set up resources, start the workload, and register
    /// auto-start behavior.
    fn activate(&self, ctx: &AppContext) -> AppsResult<()>;

    /// Query live status.
    fn status(&self, ctx: &AppContext) -> AppsResult<AppStatus>;

    /// Deactivate a generation: stop the workload, disable auto-start, and tear down
    /// resources.
    fn deactivate(&self, ctx: &AppContext) -> AppsResult<()>;

    /// Start the workload of an already-active generation.
    fn start(&self, ctx: &AppContext) -> AppsResult<()>;

    /// Stop the workload of an already-active generation without tearing down resources.
    fn stop(&self, ctx: &AppContext) -> AppsResult<()>;
}

/// Look up an orchestrator by name.
pub fn get(name: &str) -> AppsResult<&'static dyn Orchestrator> {
    match name {
        "docker-compose" => Ok(&docker_compose::DockerCompose),
        "binary" => Ok(&binary::Binary),
        "generic" => Ok(&generic::Generic),
        other => {
            reportify::bail!("unsupported orchestrator: {other}");
        }
    }
}
