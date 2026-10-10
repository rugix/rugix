//! Orchestrator for managing Docker Compose stacks.

use std::fmt::Write;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use reportify::ResultExt;
use rugix_bundle::manifest::is_valid_environment_variable_name;
use rugix_bundle::manifest::is_valid_json_pointer;
use tracing::info;
use tracing::warn;

use super::AppContext;
use super::AppStatus;
use super::AppStatusMessage;
use super::Orchestrator;
use crate::apps::AppsResult;

/// Name of the env file written into the generation directory.
const ENV_FILE: &str = "rugix-app.env";

/// Default timeout (in seconds) for `docker compose up --wait`.
const DEFAULT_HEALTH_CHECK_TIMEOUT: u64 = 120;

/// Number of log lines per service to include when Compose activation fails.
const DIAGNOSTIC_LOG_TAIL: usize = 120;

/// Maximum number of bytes to include in activation failure diagnostics.
const MAX_DIAGNOSTICS_BYTES: usize = 64 * 1024;

/// Docker Compose orchestrator.
pub struct DockerCompose;

impl DockerCompose {
    /// Write the Rugix environment file into the generation directory.
    fn write_env_file(ctx: &AppContext) -> AppsResult<()> {
        let mut content = String::new();
        writeln!(content, "RUGIX_APP_NAME={}", ctx.app_name).unwrap();
        writeln!(content, "RUGIX_APP_DIR={}", ctx.app_dir.display()).unwrap();
        writeln!(
            content,
            "RUGIX_APP_GENERATION_DIR={}",
            ctx.generation_dir.display()
        )
        .unwrap();
        writeln!(content, "RUGIX_APP_DATA_DIR={}", ctx.data_dir.display()).unwrap();
        if let Some(path) = ctx.configuration_path {
            writeln!(content, "RUGIX_APP_CONFIG_PATH={}", path.display())
                .expect("writing to a String is infallible");
        }
        let env_path = ctx.generation_dir.join(ENV_FILE);
        fs::write(&env_path, content).whatever("unable to write rugix-app.env")?;
        Ok(())
    }

    /// Build a `docker compose` command with the right project name, file, and env file.
    fn compose_cmd(ctx: &AppContext) -> AppsResult<Command> {
        let mut cmd = Command::new("docker");
        cmd.arg("compose");
        cmd.arg("--project-name").arg(ctx.app_name);
        cmd.arg("-f")
            .arg(ctx.generation_dir.join("docker-compose.yml"));
        cmd.env("RUGIX_APP_NAME", ctx.app_name)
            .env("RUGIX_APP_DIR", ctx.app_dir)
            .env("RUGIX_APP_GENERATION_DIR", ctx.generation_dir)
            .env("RUGIX_APP_DATA_DIR", ctx.data_dir)
            .env_remove("RUGIX_APP_CONFIG_PATH");
        if let Some(path) = ctx.configuration_path {
            cmd.env("RUGIX_APP_CONFIG_PATH", path);
        }
        let env_path = ctx.generation_dir.join(ENV_FILE);
        if env_path.exists() {
            cmd.arg("--env-file").arg(env_path);
        }
        Self::project_configuration_environment(ctx, &mut cmd)?;
        Ok(cmd)
    }

    /// Project configured JSON scalar values into the Compose command environment.
    fn project_configuration_environment(
        ctx: &AppContext,
        command: &mut Command,
    ) -> AppsResult<()> {
        let Some(mappings) = ctx
            .manifest
            .docker_compose
            .as_ref()
            .and_then(|configuration| configuration.environment.as_ref())
        else {
            return Ok(());
        };
        let configuration = ctx.configuration;
        for (name, pointer) in mappings {
            validate_environment_name(name)?;
            if !is_valid_json_pointer(pointer) {
                reportify::bail!(
                    "Docker Compose configuration environment mapping for {name} is not a JSON Pointer"
                );
            }
            command.env_remove(name);
            let Some(configuration) = configuration else {
                continue;
            };
            let Some(value) = configuration.pointer(pointer) else {
                continue;
            };
            let value = match value {
                serde_json::Value::Null => continue,
                serde_json::Value::Bool(value) => value.to_string(),
                serde_json::Value::Number(value) => value.to_string(),
                serde_json::Value::String(value) => value.clone(),
                serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                    reportify::bail!(
                        "Docker Compose configuration value {pointer} for {name} must be a scalar"
                    );
                }
            };
            command.env(name, value);
        }
        Ok(())
    }

    /// Get the health check timeout from the manifest, falling back to the default.
    fn health_check_timeout(ctx: &AppContext) -> u64 {
        ctx.manifest
            .health_check
            .as_ref()
            .and_then(|hc| hc.timeout)
            .unwrap_or(DEFAULT_HEALTH_CHECK_TIMEOUT)
    }

    /// Collect best-effort diagnostics while failed containers still exist.
    fn activation_diagnostics(ctx: &AppContext) -> String {
        let mut diagnostics = String::new();
        let _ = writeln!(
            diagnostics,
            "docker compose diagnostics for app {}:",
            ctx.app_name
        );
        let _ = writeln!(diagnostics);

        Self::append_compose_output(
            ctx,
            &mut diagnostics,
            "docker compose ps --all",
            &["ps", "--all"],
        );
        let _ = writeln!(diagnostics);
        let log_tail = DIAGNOSTIC_LOG_TAIL.to_string();
        Self::append_compose_output(
            ctx,
            &mut diagnostics,
            &format!("docker compose logs --no-color --timestamps --tail {log_tail}"),
            &["logs", "--no-color", "--timestamps", "--tail", &log_tail],
        );

        truncate_diagnostics(diagnostics)
    }

    fn append_compose_output(
        ctx: &AppContext,
        diagnostics: &mut String,
        label: &str,
        args: &[&str],
    ) {
        let _ = writeln!(diagnostics, "### {label}");
        let mut command = match Self::compose_cmd(ctx) {
            Ok(command) => command,
            Err(err) => {
                let _ = writeln!(diagnostics, "unable to prepare diagnostics command: {err}");
                return;
            }
        };
        match command.args(args).output() {
            Ok(output) => {
                if !output.status.success() {
                    let _ = writeln!(diagnostics, "command exited with {}", output.status);
                }
                append_command_output(diagnostics, &output.stdout, &output.stderr);
            }
            Err(err) => {
                let _ = writeln!(diagnostics, "unable to run diagnostics command: {err}");
            }
        }
    }

    fn write_activation_diagnostics(ctx: &AppContext, diagnostics: &str) -> Option<PathBuf> {
        let path = ctx
            .generation_dir
            .join(".rugix")
            .join("activation-diagnostics.log");
        let parent = path.parent().expect("diagnostics path has parent");
        if let Err(err) = fs::create_dir_all(parent) {
            warn!(
                app = ctx.app_name,
                path = ?path,
                "unable to create diagnostics directory: {err}"
            );
            return None;
        }
        if let Err(err) = fs::write(&path, diagnostics) {
            warn!(
                app = ctx.app_name,
                path = ?path,
                "unable to write activation diagnostics: {err}"
            );
            return None;
        }
        info!(
            app = ctx.app_name,
            path = ?path,
            "wrote activation diagnostics"
        );
        Some(path)
    }
}

impl Orchestrator for DockerCompose {
    fn name(&self) -> &str {
        "docker-compose"
    }

    fn activate(&self, ctx: &AppContext) -> AppsResult<()> {
        Self::write_env_file(ctx)?;

        let images_dir = ctx.generation_dir.join("images");
        if images_dir.exists() {
            let entries = fs::read_dir(&images_dir).whatever("unable to read images directory")?;
            for entry in entries {
                let entry = entry.whatever("unable to read directory entry")?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("tar") {
                    info!(image = ?path, "loading docker image");
                    let status = Command::new("docker")
                        .arg("image")
                        .arg("load")
                        .arg("-i")
                        .arg(&path)
                        .status()
                        .whatever("unable to run docker image load")?;
                    if !status.success() {
                        reportify::bail!("docker image load failed for {}", path.display());
                    }
                }
            }
        }

        info!(app = ctx.app_name, "starting docker compose");
        let mut cmd = Self::compose_cmd(ctx)?;
        cmd.arg("up").arg("-d").arg("--remove-orphans");

        let timeout = Self::health_check_timeout(ctx);
        if timeout > 0 {
            cmd.arg("--wait")
                .arg("--wait-timeout")
                .arg(timeout.to_string());
        }

        let status = cmd.status().whatever("unable to run docker compose up")?;
        if !status.success() {
            let diagnostics = Self::activation_diagnostics(ctx);
            if let Some(path) = Self::write_activation_diagnostics(ctx, &diagnostics) {
                reportify::bail!(
                    "docker compose up failed; diagnostics written to {}\n\n{diagnostics}",
                    path.display()
                );
            }
            reportify::bail!("docker compose up failed\n\n{diagnostics}");
        }
        Ok(())
    }

    fn status(&self, ctx: &AppContext) -> AppsResult<AppStatus> {
        let output = Self::compose_cmd(ctx)?
            .args(["ps", "--format", "json"])
            .output()
            .whatever("unable to run docker compose ps")?;
        if !output.status.success() {
            return Ok(AppStatus::Unknown);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            return Ok(AppStatus::Stopped);
        }
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(container) = serde_json::from_str::<ContainerStatus>(line) else {
                continue;
            };
            if !container.state.eq_ignore_ascii_case("running") {
                return Ok(AppStatus::Failed(AppStatusMessage::new(format!(
                    "container {} is {}",
                    container.name.as_deref().unwrap_or("unknown"),
                    container.state
                ))));
            }
            if let Some(health) = &container.health {
                if health.eq_ignore_ascii_case("unhealthy") {
                    return Ok(AppStatus::Unhealthy(AppStatusMessage::new(format!(
                        "container {} is unhealthy",
                        container.name.as_deref().unwrap_or("unknown"),
                    ))));
                }
            }
        }
        Ok(AppStatus::Running)
    }

    fn deactivate(&self, ctx: &AppContext) -> AppsResult<()> {
        info!(app = ctx.app_name, "stopping docker compose");
        match Self::compose_cmd(ctx)?.arg("down").status() {
            Ok(status) if !status.success() => {
                warn!(
                    app = ctx.app_name,
                    "docker compose down failed (best-effort)"
                );
            }
            Err(err) => {
                warn!(
                    app = ctx.app_name,
                    "unable to run docker compose down: {err} (best-effort)"
                );
            }
            _ => {}
        }
        Ok(())
    }

    fn start(&self, ctx: &AppContext) -> AppsResult<()> {
        Self::write_env_file(ctx)?;
        info!(app = ctx.app_name, "starting docker compose");
        let mut cmd = Self::compose_cmd(ctx)?;
        cmd.arg("up").arg("-d");

        let timeout = Self::health_check_timeout(ctx);
        if timeout > 0 {
            cmd.arg("--wait")
                .arg("--wait-timeout")
                .arg(timeout.to_string());
        }

        let status = cmd.status().whatever("unable to run docker compose up")?;
        if !status.success() {
            let diagnostics = Self::activation_diagnostics(ctx);
            if let Some(path) = Self::write_activation_diagnostics(ctx, &diagnostics) {
                reportify::bail!(
                    "docker compose up failed; diagnostics written to {}\n\n{diagnostics}",
                    path.display()
                );
            }
            reportify::bail!("docker compose up failed\n\n{diagnostics}");
        }
        Ok(())
    }

    fn stop(&self, ctx: &AppContext) -> AppsResult<()> {
        info!(app = ctx.app_name, "stopping docker compose containers");
        let status = Self::compose_cmd(ctx)?
            .arg("stop")
            .status()
            .whatever("unable to run docker compose stop")?;
        if !status.success() {
            reportify::bail!("docker compose stop failed");
        }
        Ok(())
    }
}

/// Validate the portable environment variable names accepted in app manifests.
fn validate_environment_name(name: &str) -> AppsResult<()> {
    if name.is_empty() {
        reportify::bail!("Docker Compose configuration environment name must not be empty");
    }
    if name.starts_with("RUGIX_") {
        reportify::bail!("Docker Compose configuration environment name {name:?} is reserved");
    }
    if !is_valid_environment_variable_name(name) {
        reportify::bail!("invalid Docker Compose configuration environment name {name:?}");
    }
    Ok(())
}

/// A single container entry from `docker compose ps --format json`.
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerStatus {
    name: Option<String>,
    state: String,
    health: Option<String>,
}

fn append_command_output(output: &mut String, stdout: &[u8], stderr: &[u8]) {
    if stdout.is_empty() && stderr.is_empty() {
        let _ = writeln!(output, "<no output>");
        return;
    }
    for bytes in [stdout, stderr] {
        if bytes.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(bytes);
        output.push_str(&text);
        if !text.ends_with('\n') {
            output.push('\n');
        }
    }
}

fn truncate_diagnostics(mut diagnostics: String) -> String {
    if diagnostics.len() <= MAX_DIAGNOSTICS_BYTES {
        return diagnostics;
    }
    let mut boundary = MAX_DIAGNOSTICS_BYTES;
    while !diagnostics.is_char_boundary(boundary) {
        boundary -= 1;
    }
    diagnostics.truncate(boundary);
    diagnostics.push_str("\n... diagnostics truncated ...\n");
    diagnostics
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::process::Command;

    use rugix_bundle::manifest::AppManifest;
    use rugix_bundle::manifest::DockerComposeConfig;

    use super::AppContext;
    use super::DockerCompose;

    /// Verifies Compose receives only explicitly mapped scalar configuration values.
    #[test]
    fn compose_environment_projects_only_configured_json_scalars() {
        let environment = BTreeMap::from([
            ("APP_URL".to_owned(), "/url".to_owned()),
            ("APP_ENABLED".to_owned(), "/enabled".to_owned()),
            ("APP_MISSING".to_owned(), "/missing".to_owned()),
        ]);
        let manifest = AppManifest::new("docker-compose".to_owned()).with_docker_compose(Some(
            DockerComposeConfig::new().with_environment(Some(environment)),
        ));
        let configuration = crate::apps::configuration::parse(
            r#"{"url":"https://example.com/$device","enabled":true}"#,
        )
        .unwrap();
        let ctx = AppContext {
            app_name: "example",
            app_dir: std::path::Path::new("/apps/example"),
            generation_dir: std::path::Path::new("/apps/example/generations/1"),
            data_dir: std::path::Path::new("/apps/example/data"),
            configuration_path: Some(std::path::Path::new("/apps/example/configurations/1.json")),
            configuration: Some(&configuration),
            recovery: false,
            service_manager: "systemd",
            manifest: &manifest,
        };
        let mut command = Command::new("docker");

        DockerCompose::project_configuration_environment(&ctx, &mut command).unwrap();

        assert!(command
            .get_envs()
            .any(|(name, value)| name == OsStr::new("APP_MISSING") && value.is_none()));
        let values = command
            .get_envs()
            .filter_map(|(name, value)| value.map(|value| (name, value)))
            .collect::<HashMap<_, _>>();
        assert_eq!(
            *values.get(OsStr::new("APP_URL")).unwrap(),
            "https://example.com/$device"
        );
        assert_eq!(*values.get(OsStr::new("APP_ENABLED")).unwrap(), "true");
        assert!(!values.contains_key(OsStr::new("APP_MISSING")));
    }
}
