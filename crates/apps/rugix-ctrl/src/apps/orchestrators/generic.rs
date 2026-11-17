//! Generic orchestrator implementation.

use std::process::Command;

use reportify::ResultExt;
use tracing::info;

use super::AppContext;
use super::AppStatus;
use super::Orchestrator;
use crate::apps::logs::LogQuery;
use crate::apps::logs::LogSource;
use crate::apps::logs::LogSourceFormat;
use crate::apps::AppsResult;

/// Generic orchestrator delegating lifecycle operations to an `orchestrator` script.
pub struct Generic;

impl Generic {
    /// Path of the orchestrator script.
    fn orchestrator_path(ctx: &AppContext) -> std::path::PathBuf {
        ctx.generation_dir.join("orchestrator")
    }

    /// Run the orchestrator script and return its output.
    fn run_orchestrator(ctx: &AppContext, operation: &str) -> AppsResult<std::process::Output> {
        let output = Self::orchestrator_command(ctx, operation)
            .output()
            .whatever("unable to run orchestrator")?;
        Ok(output)
    }

    /// Build the command running an operation of the orchestrator script.
    fn orchestrator_command(ctx: &AppContext, operation: &str) -> Command {
        let orchestrator = Self::orchestrator_path(ctx);
        let mut command = Command::new(&orchestrator);
        command
            .arg(operation)
            .env("RUGIX_APP_NAME", ctx.app_name)
            .env("RUGIX_APP_DIR", ctx.app_dir)
            .env("RUGIX_APP_GENERATION", ctx.generation.to_string())
            .env("RUGIX_APP_GENERATION_DIR", ctx.generation_dir)
            .env("RUGIX_APP_DATA_DIR", ctx.data_dir)
            .env(
                "RUGIX_APP_RECOVERY",
                if ctx.recovery { "true" } else { "false" },
            )
            .current_dir(ctx.generation_dir);
        command.env_remove("RUGIX_APP_CONFIG_PATH");
        if let Some(path) = ctx.configuration_path {
            command.env("RUGIX_APP_CONFIG_PATH", path);
        }
        command
    }

    /// Run the orchestrator script and check its result.
    fn run_orchestrator_checked(ctx: &AppContext, operation: &str) -> AppsResult<()> {
        let output = Self::run_orchestrator(ctx, operation)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            reportify::bail!(
                "handler `{operation}` failed (exit {}): {stderr}",
                output.status
            );
        }
        Ok(())
    }
}

impl Orchestrator for Generic {
    fn name(&self) -> &str {
        "generic"
    }

    fn activate(&self, ctx: &AppContext) -> AppsResult<()> {
        info!(app = ctx.app_name, "running generic orchestrator: activate");
        Self::run_orchestrator_checked(ctx, "activate")
    }

    fn status(&self, ctx: &AppContext) -> AppsResult<AppStatus> {
        let output = Self::run_orchestrator(ctx, "status")?;
        if !output.status.success() {
            return Ok(AppStatus::Unknown);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str::<AppStatus>(stdout.trim())
            .whatever("unable to parse orchestrator status output")
    }

    fn deactivate(&self, ctx: &AppContext) -> AppsResult<()> {
        info!(
            app = ctx.app_name,
            "running generic orchestrator: deactivate"
        );
        Self::run_orchestrator_checked(ctx, "deactivate")
    }

    fn start(&self, ctx: &AppContext) -> AppsResult<()> {
        info!(app = ctx.app_name, "running generic orchestrator: start");
        Self::run_orchestrator_checked(ctx, "start")
    }

    fn stop(&self, ctx: &AppContext) -> AppsResult<()> {
        info!(app = ctx.app_name, "running generic orchestrator: stop");
        Self::run_orchestrator_checked(ctx, "stop")
    }

    fn log_sources(&self, ctx: &AppContext, query: &LogQuery) -> AppsResult<Vec<LogSource>> {
        let mut command = Self::orchestrator_command(ctx, "logs");
        command.env("RUGIX_LOGS_LINES", query.lines.to_string());
        for (name, timestamp) in [
            ("RUGIX_LOGS_SINCE", query.since),
            ("RUGIX_LOGS_UNTIL", query.until),
        ] {
            match timestamp {
                Some(timestamp) => command.env(name, timestamp.to_string()),
                None => command.env_remove(name),
            };
        }
        Ok(vec![LogSource {
            command,
            format: LogSourceFormat::Records,
            source: None,
            generation: None,
        }])
    }
}
