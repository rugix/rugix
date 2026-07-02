use std::collections::VecDeque;
use std::sync::Arc;

use indexmap::IndexMap;
use tokio::sync::broadcast;
use tokio::sync::RwLock;

use crate::error::ApiError;
use crate::generated::events;
use crate::generated::jobs;
use crate::ApiResult;

#[derive(Debug, Clone, Default)]
pub(crate) struct JobManager {
    inner: Arc<RwLock<IndexMap<String, JobEntry>>>,
}

#[derive(Debug)]
struct JobEntry {
    job: jobs::Job,
    events: VecDeque<events::AdminEvent>,
    tx: broadcast::Sender<events::AdminEvent>,
}

impl JobManager {
    pub(crate) async fn create(
        &self,
        id: Option<String>,
        title: String,
        kind: String,
        target: Option<String>,
    ) -> ApiResult<jobs::Job> {
        let id = id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        tracing::info!(job_id = %id, %title, %kind, target = ?target, "creating job");
        let now = now();
        let job = jobs::Job::new(
            id.clone(),
            title,
            kind,
            jobs::JobStatus::Queued,
            now.clone(),
            now,
        )
        .with_target(target);
        let event = events::AdminEvent::JobChanged(events::JobChangedEvent::new(job.clone()));
        let (tx, _) = broadcast::channel(128);
        let mut events = VecDeque::new();
        events.push_back(event.clone());

        let mut inner = self.inner.write().await;
        if inner.contains_key(&id) {
            return Err(ApiError::conflict("job-exists", "job id already exists"));
        }
        inner.insert(
            id,
            JobEntry {
                job: job.clone(),
                events,
                tx: tx.clone(),
            },
        );
        let _ = tx.send(event);
        Ok(job)
    }

    pub(crate) async fn list(&self) -> Vec<jobs::Job> {
        self.inner
            .read()
            .await
            .values()
            .rev()
            .map(|entry| entry.job.clone())
            .collect()
    }

    pub(crate) async fn get(&self, job_id: &str) -> ApiResult<jobs::Job> {
        self.inner
            .read()
            .await
            .get(job_id)
            .map(|entry| entry.job.clone())
            .ok_or_else(|| ApiError::not_found("job-not-found", "job not found"))
    }

    pub(crate) async fn subscribe(
        &self,
        job_id: &str,
    ) -> ApiResult<(
        VecDeque<events::AdminEvent>,
        broadcast::Receiver<events::AdminEvent>,
    )> {
        let inner = self.inner.read().await;
        let entry = inner
            .get(job_id)
            .ok_or_else(|| ApiError::not_found("job-not-found", "job not found"))?;
        Ok((entry.events.clone(), entry.tx.subscribe()))
    }

    pub(crate) async fn set_status(&self, job_id: &str, status: jobs::JobStatus) {
        tracing::info!(%job_id, ?status, "updating job status");
        self.update_job(job_id, |job| job.status = status).await;
    }

    pub(crate) async fn fail(&self, job_id: &str, message: String, exit_code: Option<i32>) {
        tracing::warn!(%job_id, %message, ?exit_code, "failing job");
        self.set_status(
            job_id,
            jobs::JobStatus::Failed(jobs::JobFailure::new(message).with_exit_code(exit_code)),
        )
        .await;
    }

    pub(crate) async fn emit_output(&self, job_id: &str, stream: &str, line: String) {
        self.push_event(
            job_id,
            events::AdminEvent::JobOutput(events::JobOutputEvent::new(
                job_id.to_owned(),
                stream.to_owned(),
                line,
            )),
        )
        .await;
    }

    pub(crate) async fn emit_upload_progress(&self, job_id: &str, bytes: u64) {
        self.push_event(
            job_id,
            events::AdminEvent::UploadProgress(events::UploadProgressEvent::new(
                job_id.to_owned(),
                bytes,
            )),
        )
        .await;
    }

    pub(crate) async fn emit_install_progress(&self, job_id: &str, progress: f64) {
        self.push_event(
            job_id,
            events::AdminEvent::InstallProgress(events::InstallProgressEvent::new(
                job_id.to_owned(),
                progress,
            )),
        )
        .await;
    }

    async fn update_job(&self, job_id: &str, update: impl FnOnce(&mut jobs::Job)) {
        let event = {
            let mut inner = self.inner.write().await;
            let Some(entry) = inner.get_mut(job_id) else {
                return;
            };
            update(&mut entry.job);
            entry.job.updated_at = now();
            events::AdminEvent::JobChanged(events::JobChangedEvent::new(entry.job.clone()))
        };
        self.push_event(job_id, event).await;
    }

    async fn push_event(&self, job_id: &str, event: events::AdminEvent) {
        let tx = {
            let mut inner = self.inner.write().await;
            let Some(entry) = inner.get_mut(job_id) else {
                return;
            };
            entry.events.push_back(event.clone());
            while entry.events.len() > 512 {
                entry.events.pop_front();
            }
            entry.tx.clone()
        };
        let _ = tx.send(event);
    }
}

fn now() -> String {
    jiff::Timestamp::now().to_string()
}
