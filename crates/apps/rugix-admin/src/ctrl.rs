use std::process::Stdio;

use axum::extract::multipart::Field;
use axum::extract::Multipart;
use serde_json::Value;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncRead;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::process::Child;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;
use tracing::Instrument;

use crate::error::ApiError;
use crate::generated::jobs;
use crate::jobs::JobManager;
use crate::ApiResult;

#[derive(Debug, Clone)]
pub(crate) struct CommandSpec {
    pub(crate) title: String,
    pub(crate) kind: String,
    pub(crate) target: Option<String>,
    pub(crate) args: Vec<String>,
}

impl CommandSpec {
    pub(crate) fn new(title: &str, kind: &str, target: Option<String>, args: Vec<String>) -> Self {
        Self {
            title: title.to_owned(),
            kind: kind.to_owned(),
            target,
            args,
        }
    }
}

pub(crate) async fn run_json_command(args: &[&str]) -> ApiResult<Value> {
    debug!(args = ?args, "running rugix-ctrl JSON command");
    let output = Command::new("rugix-ctrl")
        .args(args)
        .output()
        .await
        .map_err(|err| {
            error!(args = ?args, error = %err, "unable to spawn rugix-ctrl");
            ApiError::command_spawn("rugix-ctrl", err)
        })?;

    if !output.status.success() {
        warn!(
            args = ?args,
            status = %output.status,
            stderr = %String::from_utf8_lossy(&output.stderr),
            "rugix-ctrl command failed"
        );
        return Err(ApiError::command_failed("rugix-ctrl", args, &output));
    }

    debug!(
        args = ?args,
        stdout_bytes = output.stdout.len(),
        "rugix-ctrl JSON command completed"
    );
    serde_json::from_slice(&output.stdout).map_err(ApiError::invalid_ctrl_output)
}

pub(crate) async fn run_components_check_command() -> ApiResult<Value> {
    let args = ["components", "check"];
    debug!(args = ?args, "running rugix-ctrl components check");
    let output = Command::new("rugix-ctrl")
        .args(args)
        .output()
        .await
        .map_err(|err| {
            error!(args = ?args, error = %err, "unable to spawn rugix-ctrl");
            ApiError::command_spawn("rugix-ctrl", err)
        })?;

    match output.status.code() {
        Some(0 | 1) => {
            debug!(
                args = ?args,
                status = %output.status,
                stdout_bytes = output.stdout.len(),
                "rugix-ctrl components check completed"
            );
            serde_json::from_slice(&output.stdout).map_err(ApiError::invalid_ctrl_output)
        }
        _ => {
            warn!(
                args = ?args,
                status = %output.status,
                stderr = %String::from_utf8_lossy(&output.stderr),
                "rugix-ctrl components check failed"
            );
            Err(ApiError::command_failed("rugix-ctrl", &args, &output))
        }
    }
}

pub(crate) fn spawn_command_job(jobs: JobManager, job_id: String, args: Vec<String>) {
    let span = tracing::info_span!("rugix_ctrl_job", %job_id, args = ?args);
    tokio::spawn(
        async move {
            info!("starting rugix-ctrl job");
            jobs.set_status(&job_id, jobs::JobStatus::Running).await;
            let mut child = match Command::new("rugix-ctrl")
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(child) => child,
                Err(err) => {
                    error!(error = %err, "unable to spawn rugix-ctrl for job");
                    jobs.fail(&job_id, format!("unable to spawn rugix-ctrl: {err}"), None)
                        .await;
                    return;
                }
            };

            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let stdout_task = stdout.map(|stdout| {
                tokio::spawn(read_output_lines(
                    jobs.clone(),
                    job_id.clone(),
                    "stdout",
                    stdout,
                ))
            });
            let stderr_task = stderr.map(|stderr| {
                tokio::spawn(read_output_lines(
                    jobs.clone(),
                    job_id.clone(),
                    "stderr",
                    stderr,
                ))
            });

            wait_for_child(jobs, job_id, child, stdout_task, stderr_task, true).await;
        }
        .instrument(span),
    );
}

pub(crate) async fn stream_upload_job(
    jobs: JobManager,
    job_id: String,
    args: Vec<String>,
    mut multipart: Multipart,
    file_field: &'static str,
) {
    info!(%job_id, args = ?args, %file_field, "starting upload job");
    jobs.set_status(&job_id, jobs::JobStatus::Running).await;
    let mut child = match Command::new("rugix-ctrl")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            error!(%job_id, args = ?args, error = %err, "unable to spawn rugix-ctrl for upload");
            jobs.fail(&job_id, format!("unable to spawn rugix-ctrl: {err}"), None)
                .await;
            drain_upload_after_failure(&job_id, &mut multipart).await;
            return;
        }
    };

    let stdout_task = child.stdout.take().map(|stdout| {
        tokio::spawn(read_output_lines(
            jobs.clone(),
            job_id.clone(),
            "stdout",
            stdout,
        ))
    });
    let stderr_task = child.stderr.take().map(|stderr| {
        tokio::spawn(read_output_lines(
            jobs.clone(),
            job_id.clone(),
            "stderr",
            stderr,
        ))
    });

    let Some(stdin) = child.stdin.take() else {
        error!(%job_id, "rugix-ctrl stdin is unavailable");
        jobs.fail(&job_id, "rugix-ctrl stdin is unavailable".to_owned(), None)
            .await;
        drain_upload_after_failure(&job_id, &mut multipart).await;
        spawn_wait_for_child(jobs, job_id, child, stdout_task, stderr_task, false);
        return;
    };

    let mut stdin = Some(stdin);
    let mut found_file = false;
    let mut bytes_read = 0u64;
    let mut bytes_written = 0u64;
    let mut upload_error = None::<String>;
    'fields: loop {
        match multipart.next_field().await {
            Ok(Some(mut field)) => {
                let field_name = field.name().map(ToOwned::to_owned);
                debug!(%job_id, field = ?field_name, "received multipart field");
                if field_name.as_deref() != Some(file_field) {
                    if let Err(err) = drain_field(&mut field).await {
                        let message = format!("unable to drain multipart field: {err}");
                        warn!(%job_id, field = ?field_name, %message);
                        upload_error.get_or_insert(message);
                        break 'fields;
                    }
                    continue;
                }
                found_file = true;
                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => {
                            bytes_read += chunk.len() as u64;
                            if let Some(child_stdin) = stdin.as_mut() {
                                if let Err(err) = child_stdin.write_all(&chunk).await {
                                    let message =
                                        format!("unable to stream upload to rugix-ctrl: {err}");
                                    warn!(
                                        %job_id,
                                        bytes_read,
                                        bytes_written,
                                        %message,
                                        "rugix-ctrl stopped accepting upload data"
                                    );
                                    upload_error.get_or_insert(message);
                                    stdin.take();
                                } else {
                                    bytes_written += chunk.len() as u64;
                                    jobs.emit_upload_progress(&job_id, bytes_written).await;
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(err) => {
                            let message = format!("unable to read upload stream: {err}");
                            warn!(
                                %job_id,
                                bytes_read,
                                bytes_written,
                                %message,
                                "failed reading upload stream"
                            );
                            upload_error.get_or_insert(message);
                            stdin.take();
                            break 'fields;
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(err) => {
                let message = format!("invalid multipart upload: {err}");
                warn!(
                    %job_id,
                    bytes_read,
                    bytes_written,
                    %message,
                    "failed reading multipart upload"
                );
                upload_error.get_or_insert(message);
                stdin.take();
                break;
            }
        }
    }

    if !found_file {
        upload_error.get_or_insert_with(|| format!("missing `{file_field}` file field"));
    }

    if let Some(message) = &upload_error {
        jobs.fail(&job_id, message.clone(), None).await;
    } else {
        info!(
            %job_id,
            bytes_read,
            bytes_written,
            "upload streamed to rugix-ctrl"
        );
    }

    drop(stdin);
    spawn_wait_for_child(
        jobs,
        job_id,
        child,
        stdout_task,
        stderr_task,
        upload_error.is_none(),
    );
}

fn spawn_wait_for_child(
    jobs: JobManager,
    job_id: String,
    child: Child,
    stdout_task: Option<JoinHandle<()>>,
    stderr_task: Option<JoinHandle<()>>,
    update_job_status: bool,
) {
    let span = tracing::info_span!("rugix_ctrl_wait", %job_id, update_job_status);
    tokio::spawn(
        async move {
            wait_for_child(
                jobs,
                job_id,
                child,
                stdout_task,
                stderr_task,
                update_job_status,
            )
            .await;
        }
        .instrument(span),
    );
}

async fn wait_for_child(
    jobs: JobManager,
    job_id: String,
    mut child: Child,
    stdout_task: Option<JoinHandle<()>>,
    stderr_task: Option<JoinHandle<()>>,
    update_job_status: bool,
) {
    match child.wait().await {
        Ok(status) if status.success() => {
            info!(%job_id, %status, "rugix-ctrl exited successfully");
            if update_job_status {
                jobs.set_status(&job_id, jobs::JobStatus::Succeeded).await;
            }
        }
        Ok(status) => {
            warn!(%job_id, %status, "rugix-ctrl exited with failure");
            if update_job_status {
                jobs.fail(
                    &job_id,
                    format!("rugix-ctrl exited with {status}"),
                    status.code(),
                )
                .await;
            }
        }
        Err(err) => {
            error!(%job_id, error = %err, "unable to wait for rugix-ctrl");
            if update_job_status {
                jobs.fail(
                    &job_id,
                    format!("unable to wait for rugix-ctrl: {err}"),
                    None,
                )
                .await;
            }
        }
    }

    if let Some(task) = stdout_task {
        if let Err(err) = task.await {
            warn!(%job_id, error = %err, "rugix-ctrl stdout reader task failed");
        }
    }
    if let Some(task) = stderr_task {
        if let Err(err) = task.await {
            warn!(%job_id, error = %err, "rugix-ctrl stderr reader task failed");
        }
    }
}

async fn read_output_lines<R>(jobs: JobManager, job_id: String, stream: &'static str, reader: R)
where
    R: AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                debug!(%job_id, %stream, line = %line, "rugix-ctrl output");
                if stream == "stdout" {
                    if let Some(progress) = parse_update_progress(&line) {
                        jobs.emit_install_progress(&job_id, progress).await;
                        continue;
                    }
                }
                jobs.emit_output(&job_id, stream, line).await;
            }
            Ok(None) => break,
            Err(err) => {
                warn!(%job_id, %stream, error = %err, "unable to read rugix-ctrl output");
                break;
            }
        }
    }
}

fn parse_update_progress(line: &str) -> Option<f64> {
    let value: Value = serde_json::from_str(line).ok()?;
    if value.get("event").and_then(Value::as_str) != Some("UpdateProgress") {
        return None;
    }
    let progress = value.get("progress").and_then(Value::as_f64)?;
    progress.is_finite().then(|| progress.clamp(0.0, 100.0))
}

async fn drain_upload_after_failure(job_id: &str, multipart: &mut Multipart) {
    match drain_multipart(multipart).await {
        Ok(bytes) => {
            debug!(%job_id, bytes, "drained upload body after early failure");
        }
        Err(err) => {
            warn!(%job_id, error = %err, "unable to drain upload body after early failure");
        }
    }
}

async fn drain_multipart(multipart: &mut Multipart) -> Result<u64, String> {
    let mut bytes = 0u64;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|err| err.to_string())?
    {
        bytes += drain_field(&mut field).await?;
    }
    Ok(bytes)
}

async fn drain_field(field: &mut Field<'_>) -> Result<u64, String> {
    let mut bytes = 0u64;
    while let Some(chunk) = field.chunk().await.map_err(|err| err.to_string())? {
        bytes += chunk.len() as u64;
    }
    Ok(bytes)
}
