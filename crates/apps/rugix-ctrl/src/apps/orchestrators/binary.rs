//! Orchestrator for managing a single executable via a service manager.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use reportify::ResultExt;
use tracing::info;

use super::AppContext;
use super::AppStatus;
use super::AppStatusMessage;
use super::Orchestrator;
use crate::apps::logs;
use crate::apps::logs::LogQuery;
use crate::apps::logs::LogSource;
use crate::apps::logs::LogSourceFormat;
use crate::apps::systemd;
use crate::apps::AppsResult;

/// Manages a single executable via a service manager.
pub struct Binary;

/// Fixed name of the systemd unit template in the generation directory.
const UNIT_TEMPLATE: &str = "systemd.service";

impl Binary {
    /// Ensure that the service manager is systemd.
    fn require_systemd(ctx: &AppContext) -> AppsResult<()> {
        if ctx.service_manager != "systemd" {
            reportify::bail!(
                "binary orchestrator requires service-manager \"systemd\", got \"{}\"",
                ctx.service_manager
            );
        }
        Ok(())
    }

    /// Derive the systemd service name from the app name.
    fn service_name(app_name: &str) -> String {
        format!("rugix-app-{app_name}.service")
    }

    /// Directory that holds the rendered units for the active generation.
    fn app_units_dir(ctx: &AppContext) -> PathBuf {
        ctx.generation_dir.join(".rugix/systemd/units")
    }

    /// Runtime path where systemd can pick up the unit immediately.
    fn runtime_unit_path(app_name: &str) -> PathBuf {
        Path::new(systemd::RUNTIME_UNITS_DIR).join(Self::service_name(app_name))
    }

    /// Read the unit template, substitute placeholders, and tag the journal entries of
    /// the unit with the generation.
    fn render_unit(ctx: &AppContext) -> AppsResult<String> {
        let template_path = ctx.generation_dir.join(UNIT_TEMPLATE);
        let template =
            fs::read_to_string(&template_path).whatever("unable to read unit template")?;
        let rendered = template
            .replace("${GENERATION_DIR}", &ctx.generation_dir.to_string_lossy())
            .replace("${DATA_DIR}", &ctx.data_dir.to_string_lossy())
            .replace(
                "${CONFIG_PATH}",
                &ctx.configuration_path
                    .map(|path| path.to_string_lossy())
                    .unwrap_or_default(),
            );
        let separator = if rendered.ends_with('\n') { "" } else { "\n" };
        Ok(format!(
            "{rendered}{separator}\n[Service]\nLogExtraFields={}={}\n",
            logs::JOURNAL_GENERATION_FIELD,
            ctx.generation
        ))
    }
}

impl Orchestrator for Binary {
    fn name(&self) -> &str {
        "binary"
    }

    fn activate(&self, ctx: &AppContext) -> AppsResult<()> {
        Self::require_systemd(ctx)?;

        let unit_content = Self::render_unit(ctx)?;
        let service_name = Self::service_name(ctx.app_name);

        let units_dir = Self::app_units_dir(ctx);
        fs::create_dir_all(&units_dir).whatever("unable to create units directory")?;
        let unit_path = units_dir.join(&service_name);
        fs::write(&unit_path, &unit_content).whatever("unable to write persistent unit file")?;
        info!(app = ctx.app_name, unit = ?unit_path, "persisted unit");

        let runtime_path = Self::runtime_unit_path(ctx.app_name);
        fs::write(&runtime_path, &unit_content).whatever("unable to write runtime unit file")?;
        info!(app = ctx.app_name, unit = ?runtime_path, "installed runtime unit");

        systemd::daemon_reload()?;
        systemd::enable_runtime(&service_name)?;
        systemd::start(&service_name)?;
        info!(app = ctx.app_name, service = %service_name, "enabled and started");

        Ok(())
    }

    fn status(&self, ctx: &AppContext) -> AppsResult<AppStatus> {
        Self::require_systemd(ctx)?;
        let service_name = Self::service_name(ctx.app_name);
        match systemd::is_active(&service_name)?.as_str() {
            "active" => Ok(AppStatus::Running),
            "inactive" | "dead" => Ok(AppStatus::Stopped),
            "failed" => Ok(AppStatus::Failed(AppStatusMessage::new(
                "unit failed".to_owned(),
            ))),
            _ => Ok(AppStatus::Unknown),
        }
    }

    fn deactivate(&self, ctx: &AppContext) -> AppsResult<()> {
        Self::require_systemd(ctx)?;

        let service = Self::service_name(ctx.app_name);

        systemd::stop(&service)?;
        systemd::disable_runtime(&service)?;
        info!(app = ctx.app_name, service = %service, "stopped and disabled");

        let runtime_path = Self::runtime_unit_path(ctx.app_name);
        if runtime_path.exists() {
            info!(app = ctx.app_name, unit = ?runtime_path, "removing runtime unit");
            fs::remove_file(&runtime_path).whatever("unable to remove runtime unit")?;
            systemd::daemon_reload()?;
        }
        Ok(())
    }

    fn start(&self, ctx: &AppContext) -> AppsResult<()> {
        Self::require_systemd(ctx)?;
        let service = Self::service_name(ctx.app_name);
        systemd::start(&service)?;
        info!(app = ctx.app_name, service = %service, "started");
        Ok(())
    }

    fn stop(&self, ctx: &AppContext) -> AppsResult<()> {
        Self::require_systemd(ctx)?;
        let service = Self::service_name(ctx.app_name);
        systemd::stop(&service)?;
        info!(app = ctx.app_name, service = %service, "stopped");
        Ok(())
    }

    fn log_sources(&self, ctx: &AppContext, query: &LogQuery) -> AppsResult<Vec<LogSource>> {
        Self::require_systemd(ctx)?;
        let mut command = Command::new("journalctl");
        // Matching the unit includes systemd's messages about it, such as the exit
        // status of a crashed workload. Without `--all`, journalctl omits fields
        // larger than 4 KiB, including long messages.
        command
            .arg(format!("--unit={}", Self::service_name(ctx.app_name)))
            .args(["--output=json", "--all", "--no-pager", "--quiet"])
            .arg(format!("--lines={}", query.lines));
        // Journalctl takes whole seconds. Rounding outwards keeps all selected entries;
        // reading the logs drops the surplus.
        if let Some(since) = query.since {
            command.arg(format!("--since=@{}", since.unix_seconds()));
        }
        if let Some(until) = query.until {
            let seconds = until.unix_seconds() + i64::from(until.subsec_nanos() > 0);
            command.arg(format!("--until=@{seconds}"));
        }
        Ok(vec![LogSource {
            command,
            format: LogSourceFormat::Journal,
            source: None,
            generation: None,
        }])
    }
}
