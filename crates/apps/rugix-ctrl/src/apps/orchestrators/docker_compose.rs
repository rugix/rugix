//! Orchestrator for managing Docker Compose stacks.

use std::fmt::Write;
use std::fs;
use std::io;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use reportify::ResultExt;
use rugix_bundle::manifest::compose::ImageMetadata;
use rugix_bundle::manifest::is_valid_environment_variable_name;
use rugix_bundle::manifest::is_valid_json_pointer;
use rugix_bundle::manifest::owned_image_prefix;
use rugix_bundle::manifest::IMAGE_METADATA_PATH;
use rugix_bundle::manifest::IMAGE_METADATA_SCHEMA_VERSION;
use rugix_common::path::ValidatedRelativePath;
use tracing::info;
use tracing::warn;

use super::AppContext;
use super::AppStatus;
use super::AppStatusMessage;
use super::Orchestrator;
use crate::apps::logs;
use crate::apps::logs::LogQuery;
use crate::apps::logs::LogSource;
use crate::apps::logs::LogSourceFormat;
use crate::apps::AppsResult;

/// Name of the env file written into the generation directory.
const ENV_FILE: &str = "rugix-app.env";

/// Default timeout (in seconds) for `docker compose up --wait`.
const DEFAULT_HEALTH_CHECK_TIMEOUT: u64 = 120;

/// Number of log lines per service to include when Compose activation fails.
const DIAGNOSTIC_LOG_TAIL: usize = 120;

/// Maximum number of bytes to include in activation failure diagnostics.
const MAX_DIAGNOSTICS_BYTES: usize = 64 * 1024;

/// Path of the saved log records of a failed activation, relative to the generation
/// directory.
const ACTIVATION_LOGS_PATH: &str = ".rugix/activation-logs.jsonl";

/// Number of most recent log records to save when Compose activation fails.
const ACTIVATION_LOG_RECORDS: NonZeroUsize = NonZeroUsize::new(500).unwrap();

/// Docker Compose orchestrator.
pub struct DockerCompose;

impl DockerCompose {
    /// Write the Rugix environment file into the generation directory.
    fn write_env_file(ctx: &AppContext) -> AppsResult<()> {
        let mut content = String::new();
        writeln!(content, "RUGIX_APP_NAME={}", ctx.app_name).unwrap();
        writeln!(content, "RUGIX_APP_DIR={}", ctx.app_dir.display()).unwrap();
        writeln!(content, "RUGIX_APP_GENERATION={}", ctx.generation).unwrap();
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
            .env("RUGIX_APP_GENERATION", ctx.generation.to_string())
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

    /// Load the bundled images, `images/*.tar` in the generation directory or the store.
    fn load_images(ctx: &AppContext) -> AppsResult<()> {
        let images_dir = ctx.generation_dir.join("images");
        if images_dir.exists() {
            let entries = fs::read_dir(&images_dir).whatever("unable to read images directory")?;
            for entry in entries {
                let entry = entry.whatever("unable to read directory entry")?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("tar") {
                    info!(image = ?path, "loading docker image");
                    let image = fs::File::open(&path).whatever("unable to open docker image")?;
                    load_image(image, &path.to_string_lossy())?;
                }
            }
        }
        for file in ctx.files.list()? {
            let is_image = file
                .path
                .strip_prefix("images/")
                .is_some_and(|name| !name.contains('/') && name.ends_with(".tar"));
            if file.object.is_none() || !is_image {
                continue;
            }
            info!(image = %file.path, "loading docker image from store");
            let path = ValidatedRelativePath::new(file.path.clone())
                .whatever("invalid docker image path")?;
            load_image(ctx.files.open(&path)?, &file.path)?;
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

    /// Save the log records of the failed generation's containers (best-effort).
    ///
    /// Cleaning up after the failed activation removes the containers together with
    /// their logs. [`Orchestrator::log_sources`] includes the saved records.
    fn save_activation_logs(ctx: &AppContext) {
        let query = LogQuery {
            lines: ACTIVATION_LOG_RECORDS,
            since: None,
            until: None,
        };
        let records = container_log_sources(ctx, &query).and_then(|sources| {
            logs::read_logs(sources, &query, &logs::app_log_format(ctx.manifest))
        });
        let records = match records {
            Ok(records) => records,
            Err(err) => {
                warn!(
                    app = ctx.app_name,
                    "unable to read logs of failed activation: {err:?}"
                );
                return;
            }
        };
        let mut content = String::new();
        for record in &records {
            content.push_str(
                &sidex::formats::json::to_string(record)
                    .expect("log records can always be encoded as JSON"),
            );
            content.push('\n');
        }
        let path = ctx.generation_dir.join(ACTIVATION_LOGS_PATH);
        let parent = path.parent().expect("activation logs path has parent");
        if let Err(err) = fs::create_dir_all(parent).and_then(|()| fs::write(&path, content)) {
            warn!(
                app = ctx.app_name,
                path = ?path,
                "unable to save logs of failed activation: {err}"
            );
        }
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

    /// Remove the generation's bundled images with Rugix-owned tags (best-effort).
    ///
    /// Activation loads them again. Tags kept with `--disable-pinning` may also be used
    /// outside of the app, so they are left in place.
    fn remove_bundled_images(ctx: &AppContext) {
        let path = ctx.generation_dir.join(IMAGE_METADATA_PATH);
        let metadata = match fs::read(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(err) => {
                warn!(app = ctx.app_name, path = ?path, "unable to read image metadata: {err}");
                return;
            }
        };
        let metadata = match serde_json::from_slice::<ImageMetadata>(&metadata) {
            Ok(metadata) => metadata,
            Err(err) => {
                warn!(app = ctx.app_name, path = ?path, "unable to parse image metadata: {err}");
                return;
            }
        };
        if !(1..=IMAGE_METADATA_SCHEMA_VERSION).contains(&metadata.schema_version) {
            warn!(
                app = ctx.app_name,
                path = ?path,
                version = metadata.schema_version,
                "unsupported image metadata version, keeping images"
            );
            return;
        }
        let owned_prefix = owned_image_prefix(ctx.app_name);
        let tags = metadata
            .images
            .iter()
            .map(|image| image.bundle_tag.as_str())
            .filter(|tag| tag.starts_with(&owned_prefix))
            .collect::<Vec<_>>();
        if tags.is_empty() {
            return;
        }
        info!(app = ctx.app_name, ?tags, "removing docker images");
        // Keep Docker's listing of removed layers out of Rugix Ctrl's stdout.
        let status = Command::new("docker")
            .args(["image", "rm"])
            .args(&tags)
            .stdout(Stdio::null())
            .status();
        match status {
            Ok(status) if !status.success() => {
                warn!(app = ctx.app_name, "docker image rm failed (best-effort)");
            }
            Err(err) => {
                warn!(
                    app = ctx.app_name,
                    "unable to run docker image rm: {err} (best-effort)"
                );
            }
            _ => {}
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
        Self::load_images(ctx)?;

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
            Self::save_activation_logs(ctx);
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
        Self::remove_bundled_images(ctx);
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

    fn log_sources(&self, ctx: &AppContext, query: &LogQuery) -> AppsResult<Vec<LogSource>> {
        let mut sources = container_log_sources(ctx, query)?;
        sources.extend(saved_activation_log_sources(ctx)?);
        Ok(sources)
    }
}

/// Describe the logs of the containers of an app's Compose project.
fn container_log_sources(ctx: &AppContext, query: &LogQuery) -> AppsResult<Vec<LogSource>> {
    let generations_dir = ctx.app_dir.join("generations");
    let sources = project_containers(ctx.app_name)?
        .into_iter()
        .map(|container| {
            let mut command = Command::new("docker");
            command
                .args(["logs", "--timestamps"])
                .arg(format!("--tail={}", query.lines));
            for (option, timestamp) in [("--since", query.since), ("--until", query.until)] {
                if let Some(timestamp) = timestamp {
                    command.arg(format!(
                        "{option}={}.{:09}",
                        timestamp.unix_seconds(),
                        timestamp.subsec_nanos()
                    ));
                }
            }
            command.arg(&container.id);
            // Compose runs a generation's containers in the generation directory.
            let generation = Path::new(&container.working_dir)
                .strip_prefix(&generations_dir)
                .ok()
                .and_then(|generation| generation.to_str()?.parse().ok());
            LogSource {
                command,
                format: LogSourceFormat::DockerLogs,
                source: Some(container.service),
                generation,
            }
        })
        .collect();
    Ok(sources)
}

/// Describe the saved log records of the failed activations of the app's generations.
///
/// The saved records name their source and generation.
fn saved_activation_log_sources(ctx: &AppContext) -> AppsResult<Vec<LogSource>> {
    let generations_dir = ctx.app_dir.join("generations");
    let mut sources = Vec::new();
    for entry in fs::read_dir(&generations_dir).whatever("unable to read generations directory")? {
        let path = entry
            .whatever("unable to read generations directory")?
            .path()
            .join(ACTIVATION_LOGS_PATH);
        if !path.exists() {
            continue;
        }
        let mut command = Command::new("cat");
        command.arg(path);
        sources.push(LogSource {
            command,
            format: LogSourceFormat::Records,
            source: None,
            generation: None,
        });
    }
    Ok(sources)
}

/// Container of an app's Compose project.
struct ProjectContainer {
    /// ID of the container.
    id: String,
    /// Compose service of the container.
    service: String,
    /// Directory in which Compose ran the project.
    working_dir: String,
}

/// List the containers of an app's Compose project, including stopped ones.
///
/// The containers are ordered by service.
fn project_containers(app_name: &str) -> AppsResult<Vec<ProjectContainer>> {
    let output = Command::new("docker")
        .args(["ps", "--all", "--no-trunc", "--filter"])
        .arg(format!("label=com.docker.compose.project={app_name}"))
        .args([
            "--format",
            "{{.ID}}\t{{.Label \"com.docker.compose.service\"}}\t{{.Label \"com.docker.compose.project.working_dir\"}}",
        ])
        .output()
        .whatever("unable to run docker ps")?;
    if !output.status.success() {
        reportify::bail!(
            "docker ps failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut containers = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            let mut columns = line.splitn(3, '\t');
            let id = columns
                .next()
                .expect("splitting yields at least one column");
            let (Some(service), Some(working_dir)) = (columns.next(), columns.next()) else {
                reportify::bail!("unexpected line in output of docker ps: {line:?}");
            };
            Ok(ProjectContainer {
                id: id.to_owned(),
                service: service.to_owned(),
                working_dir: working_dir.to_owned(),
            })
        })
        .collect::<AppsResult<Vec<_>>>()?;
    containers.sort_by(|first, second| first.service.cmp(&second.service));
    Ok(containers)
}

/// Stream an image archive into `docker image load`.
fn load_image(mut image: impl Read, name: &str) -> AppsResult<()> {
    let mut child = Command::new("docker")
        .arg("image")
        .arg("load")
        .stdin(Stdio::piped())
        .spawn()
        .whatever("unable to run docker image load")?;
    let mut stdin = child.stdin.take().expect("stdin of the child is piped");
    let streamed = io::copy(&mut image, &mut stdin);
    drop(stdin);
    let status = child.wait().whatever("unable to run docker image load")?;
    match streamed {
        // A broken pipe means that Docker stopped reading, which its status explains.
        Err(error) if error.kind() != io::ErrorKind::BrokenPipe || status.success() => {
            Err(error).whatever_with(|_| format!("unable to stream docker image {name}"))
        }
        _ if !status.success() => reportify::bail!("docker image load failed for {name}"),
        _ => Ok(()),
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
    use rugix_store::Store;

    use super::AppContext;
    use super::DockerCompose;
    use crate::apps::files::GenerationFiles;

    /// Verifies Compose receives only explicitly mapped scalar configuration values.
    #[test]
    fn compose_environment_projects_only_configured_json_scalars() {
        let environment = BTreeMap::from([
            ("APP_URL".to_owned(), "/url".to_owned()),
            ("APP_ENABLED".to_owned(), "/enabled".to_owned()),
            ("APP_MISSING".to_owned(), "/missing".to_owned()),
        ]);
        let manifest = AppManifest::new("docker-compose".to_owned()).with_docker_compose(Some(
            DockerComposeConfig::new().with_environment(Some(
                environment
                    .into_iter()
                    .map(|(key, value)| (key.into(), value.into()))
                    .collect::<BTreeMap<_, _>>(),
            )),
        ));
        let configuration = crate::apps::configuration::parse(
            r#"{"url":"https://example.com/$device","enabled":true}"#,
        )
        .unwrap();
        let files = GenerationFiles::new(
            Store::new("/store"),
            "example",
            1,
            "/apps/example/generations/1".into(),
        );
        let ctx = AppContext {
            app_name: "example",
            app_dir: std::path::Path::new("/apps/example"),
            generation: 1,
            generation_dir: std::path::Path::new("/apps/example/generations/1"),
            files: &files,
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
