use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use reportify::ResultExt;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::config::apps::AppGeneration;
use crate::config::apps::AppState;
use crate::config::apps::AppStateActive;
use crate::config::apps::AppStateError;
use crate::config::apps::AppStateStarting;
use crate::config::apps::AppStateStopping;
use crate::config::apps::AppStateSwitching;
use crate::config::apps::AppsConfig;
use crate::payload_db::PayloadState;

use super::config;
use super::orchestrators;
use super::orchestrators::AppContext;
use super::orchestrators::AppStatus;
use super::AppsResult;
use rugix_bundle::manifest::AppManifest;

/// An advisory file lock held for the duration of a mutating operation.
///
/// The lock is released when this guard is dropped (via [`nix::fcntl::Flock`]).
pub type AppLock = nix::fcntl::Flock<fs::File>;

/// A generation with its completeness status resolved from the filesystem.
pub struct ResolvedGeneration {
    /// The persisted generation metadata.
    pub meta: AppGeneration,
    /// Whether the generation is complete (has the `.rugix/complete` marker).
    pub complete: bool,
}

/// Manages app generations on the data partition.
pub struct AppManager {
    /// Root directory for all apps.
    apps_dir: PathBuf,
    /// Resolved service manager name.
    service_manager: String,
}

impl AppManager {
    /// Create a new app manager.
    pub fn new(apps_dir: PathBuf, apps_config: AppsConfig) -> Self {
        let service_manager = config::effective_service_manager(&apps_config);
        Self {
            apps_dir,
            service_manager,
        }
    }

    /// Acquire an exclusive advisory lock for the given app.
    ///
    /// The lock file is created in `<app_dir>/.rugix/lock`. Callers must hold the
    /// returned [`AppLock`] for the duration of the mutating operation. The lock
    /// is released when the guard is dropped.
    pub fn lock_app(&self, app_name: &str) -> AppsResult<AppLock> {
        rugix_bundle::manifest::validate_app_name(app_name).whatever("invalid app name")?;
        let lock_dir = self.app_dir(app_name).join(".rugix");
        fs::create_dir_all(&lock_dir).whatever("unable to create app .rugix directory")?;
        let lock_path = lock_dir.join("lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .whatever("unable to open app lock file")?;
        nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_file, errno)| errno)
            .whatever("unable to acquire app lock")
    }

    /// Path to the directory of an app.
    fn app_dir(&self, app_name: &str) -> PathBuf {
        self.apps_dir.join(app_name)
    }

    /// Path to the generations directory of an app.
    fn generations_dir(&self, app_name: &str) -> PathBuf {
        self.app_dir(app_name).join("generations")
    }

    /// Path to a specific generation directory.
    pub fn generation_dir(&self, app_name: &str, number: u64) -> PathBuf {
        self.generations_dir(app_name).join(number.to_string())
    }

    /// Path to the data directory of an app.
    fn data_dir(&self, app_name: &str) -> PathBuf {
        self.app_dir(app_name).join("data")
    }

    /// Path to the state file of an app.
    fn state_path(&self, app_name: &str) -> PathBuf {
        self.app_dir(app_name).join(".rugix/state.json")
    }

    /// Write the state of an app.
    fn write_state(&self, app_name: &str, state: &AppState) -> AppsResult<()> {
        let path = self.state_path(app_name);
        let content =
            serde_json::to_string_pretty(state).whatever("unable to serialize app state")?;
        rugix_common::fsutils::atomic_write(&path, content.as_bytes())
            .whatever("unable to write app state")?;
        Ok(())
    }

    /// Read the persisted app state, defaulting to `Inactive` if absent.
    pub fn read_state(&self, app_name: &str) -> AppsResult<AppState> {
        let path = self.state_path(app_name);
        match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).whatever("unable to parse app state"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(AppState::Inactive),
            Err(err) => Err(err).whatever("unable to read app state"),
        }
    }

    /// Check for and recover any interrupted transition for a single app.
    ///
    /// The caller must hold the [`AppLock`] for this app.
    pub fn recover_app(&self, _lock: &AppLock, app_name: &str) -> AppsResult<()> {
        match self.read_state(app_name)? {
            AppState::Switching(AppStateSwitching { from, to, recovery }) => {
                if recovery.unwrap_or(false) {
                    warn!(
                        app = app_name,
                        ?from,
                        ?to,
                        "recovering interrupted switch that was itself a recovery"
                    );
                } else {
                    info!(app = app_name, ?from, ?to, "recovering interrupted switch");
                }
                self.do_switch(app_name, from, to, true)?;
            }
            AppState::Starting(AppStateStarting { generation }) => {
                info!(app = app_name, generation, "recovering interrupted start");
                if let Err(e) = self.run_start(app_name, generation, true) {
                    warn!(app = app_name, generation, "start recovery failed: {e:?}");
                }
                self.write_state(app_name, &AppState::Active(AppStateActive::new(generation)))?;
            }
            AppState::Stopping(AppStateStopping { generation }) => {
                info!(app = app_name, generation, "recovering interrupted stop");
                if let Err(e) = self.run_stop(app_name, generation, true) {
                    warn!(app = app_name, generation, "stop recovery failed: {e:?}");
                }
                self.write_state(app_name, &AppState::Active(AppStateActive::new(generation)))?;
            }
            AppState::Error(AppStateError { from, to, message }) => {
                // Try to recover by activating the previously working generation first. If there
                // was none, or if that also fails, try the generation that originally failed. The
                // underlying issue may have been transient.
                let target = from.unwrap_or(to);
                info!(
                    app = app_name,
                    from, to, target, message, "recovering from error state"
                );
                if let Err(e) = self.run_activate(app_name, target, true) {
                    warn!(app = app_name, target, "recovery activation failed: {e:?}");
                    // If we tried `from` and it failed, fall back to `to`.
                    if from.is_some() {
                        info!(app = app_name, to, "falling back to failed generation");
                        if let Err(e) = self.run_activate(app_name, to, true) {
                            warn!(app = app_name, to, "fallback activation also failed: {e:?}");
                        }
                    }
                }
            }
            // Nothing to recover.
            AppState::Inactive | AppState::Active(..) => {}
        }
        Ok(())
    }

    /// Check for and recover interrupted transitions across all apps.
    ///
    /// Acquires the lock for each app internally.
    pub fn recover_all(&self) -> AppsResult<()> {
        let apps = self.list_apps()?;
        for app_name in &apps {
            match self.lock_app(app_name) {
                Ok(lock) => {
                    if let Err(e) = self.recover_app(&lock, app_name) {
                        warn!(app = %app_name, "recovery failed: {e:?}");
                    }
                }
                Err(e) => {
                    warn!(app = %app_name, "unable to lock app for recovery: {e:?}");
                }
            }
        }
        Ok(())
    }

    /// Allocate the next generation number and create its directory.
    ///
    /// The caller must hold the [`AppLock`] for this app for the duration of the
    /// installation that follows.
    pub fn create_generation(&self, _lock: &AppLock, app_name: &str) -> AppsResult<(u64, PathBuf)> {
        rugix_bundle::manifest::validate_app_name(app_name).whatever("invalid app name")?;
        let generations_dir = self.generations_dir(app_name);
        fs::create_dir_all(&generations_dir).whatever("unable to create generations directory")?;
        fs::create_dir_all(self.data_dir(app_name))
            .whatever("unable to create app data directory")?;

        let next = self.next_generation_number(app_name)?;
        let gen_dir = generations_dir.join(next.to_string());
        fs::create_dir_all(&gen_dir).whatever("unable to create generation directory")?;
        Ok((next, gen_dir))
    }

    /// Determine the number of the next generation.
    fn next_generation_number(&self, app_name: &str) -> AppsResult<u64> {
        let generations_dir = self.generations_dir(app_name);
        let mut max = 0u64;
        if generations_dir.exists() {
            let entries =
                fs::read_dir(&generations_dir).whatever("unable to read generations directory")?;
            for entry in entries {
                let entry = entry.whatever("unable to read directory entry")?;
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(n) = name.parse::<u64>() {
                        max = max.max(n);
                    }
                }
            }
        }
        Ok(max + 1)
    }

    /// Write generation metadata.
    pub fn write_generation_metadata(
        &self,
        gen_dir: &Path,
        generation: &AppGeneration,
    ) -> AppsResult<()> {
        let metadata = serde_json::to_string_pretty(generation)
            .whatever("unable to serialize generation metadata")?;
        rugix_common::fsutils::atomic_write(
            &gen_dir.join(".rugix/generation.json"),
            metadata.as_bytes(),
        )
        .whatever("unable to write generation metadata")?;
        Ok(())
    }

    /// Mark a generation as complete (all payloads have been fully written).
    ///
    /// The marker file is fsynced, and the parent directory is fsynced afterwards,
    /// so that the marker survives a crash.
    pub fn mark_complete(gen_dir: &Path) -> AppsResult<()> {
        let rugix_dir = gen_dir.join(".rugix");
        fs::create_dir_all(&rugix_dir).whatever("unable to create .rugix directory")?;
        let marker_path = rugix_dir.join("complete");
        let file = fs::File::create(&marker_path).whatever("unable to create complete marker")?;
        file.sync_all().whatever("unable to sync complete marker")?;
        drop(file);
        // Fsync the directory so the new entry is durable.
        if let Ok(dir) = fs::File::open(&rugix_dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// Check whether a generation is complete (fully installed).
    pub fn is_complete(gen_dir: &Path) -> bool {
        gen_dir.join(".rugix/complete").exists()
    }

    /// Read user-supplied metadata for a generation, if present.
    pub fn read_metadata(gen_dir: &Path) -> Option<serde_json::Value> {
        let path = gen_dir.join("app-meta.json");
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
            Err(err) => {
                error!(path = ?path, error = %err, "unable to read metadata file");
                return None;
            }
        };
        match serde_json::from_str(&content) {
            Ok(value) => Some(value),
            Err(err) => {
                error!(path = ?path, error = %err, "unable to parse metadata file");
                None
            }
        }
    }

    /// Save per-payload state (hashes, sizes) for a generation.
    pub fn save_payload_states(
        gen_dir: &Path,
        states: &HashMap<String, PayloadState>,
    ) -> AppsResult<()> {
        let path = gen_dir.join(".rugix/payloads.json");
        fs::create_dir_all(path.parent().unwrap()).whatever("unable to create .rugix directory")?;
        let json =
            serde_json::to_string_pretty(states).whatever("unable to serialize payload states")?;
        rugix_common::fsutils::atomic_write(&path, json.as_bytes())
            .whatever("unable to write payload states")?;
        Ok(())
    }

    /// Load per-payload state for a generation. Returns empty map if absent.
    pub fn load_payload_states(gen_dir: &Path) -> HashMap<String, PayloadState> {
        let path = gen_dir.join(".rugix/payloads.json");
        let Ok(content) = fs::read_to_string(&path) else {
            return HashMap::new();
        };
        serde_json::from_str(&content).unwrap_or_default()
    }

    /// Update the generation metadata to record the current time as `last_activated`.
    fn mark_activated(gen_dir: &Path) -> AppsResult<()> {
        let meta_path = gen_dir.join(".rugix/generation.json");
        let content =
            fs::read_to_string(&meta_path).whatever("unable to read generation metadata")?;
        let mut gen: AppGeneration =
            serde_json::from_str(&content).whatever("unable to parse generation metadata")?;
        gen.last_activated = Some(jiff::Timestamp::now().to_string());
        let updated = serde_json::to_string_pretty(&gen)
            .whatever("unable to serialize generation metadata")?;
        rugix_common::fsutils::atomic_write(&meta_path, updated.as_bytes())
            .whatever("unable to write generation metadata")?;
        Ok(())
    }

    /// Activate a generation.
    ///
    /// If another generation is currently active it is deactivated first.
    ///
    /// If activation fails, the previous generation is automatically rolled back.
    ///
    /// If rollback also fails, the app enters the `error` state.
    ///
    /// The caller must hold the [`AppLock`] for this app.
    pub fn activate_generation(
        &self,
        _lock: &AppLock,
        app_name: &str,
        gen_number: u64,
    ) -> AppsResult<()> {
        let gen_dir = self.generation_dir(app_name, gen_number);
        if !Self::is_complete(&gen_dir) {
            reportify::bail!("generation is not complete (installation may have been interrupted)");
        }

        let from = self.current_generation(app_name)?;
        self.do_switch(app_name, from, Some(gen_number), false)
    }

    /// Deactivate the current generation.
    ///
    /// The caller must hold the [`AppLock`] for this app.
    pub fn deactivate(&self, _lock: &AppLock, app_name: &str) -> AppsResult<()> {
        let Some(current) = self.current_generation(app_name)? else {
            reportify::bail!("app {app_name} has no active generation");
        };

        self.do_switch(app_name, Some(current), None, false)
    }

    /// Execute a switch: deactivate `from` (if set), then activate `to` (if set).
    ///
    /// On activation failure, attempts to roll back to the `from` generation.
    ///
    /// If rollback also fails, transitions to the `Error` state.
    fn do_switch(
        &self,
        app_name: &str,
        from: Option<u64>,
        to: Option<u64>,
        recovery: bool,
    ) -> AppsResult<()> {
        self.write_state(
            app_name,
            &AppState::Switching(
                AppStateSwitching::new()
                    .with_from(from)
                    .with_to(to)
                    .with_recovery(Some(recovery)),
            ),
        )?;

        if let Some(from_gen) = from {
            if let Err(e) = self.run_deactivate(app_name, from_gen, recovery) {
                if to.is_some() {
                    // We're switching to a new generation. Press on despite the deactivation
                    // failure so we don't leave nothing running.
                    warn!(
                        app = app_name,
                        generation = from_gen,
                        "deactivation of old generation failed, continuing with activation: {e:?}"
                    );
                } else {
                    // Pure deactivation with no target. Propagate the error.
                    return Err(e);
                }
            }
        }

        let Some(to_gen) = to else {
            // Pure deactivation, already done.
            self.write_state(app_name, &AppState::Inactive)?;
            info!(app = app_name, recovery, "generation deactivated");
            return Ok(());
        };

        if let Err(err) = self.run_activate(app_name, to_gen, recovery) {
            error!(
                app = app_name,
                generation = to_gen,
                "activation failed: {err:?}"
            );
            // Try to clean up any residual resources from the failed activation
            // (e.g. partially started containers) before attempting rollback.
            if let Err(cleanup_err) = self.run_deactivate(app_name, to_gen, true) {
                warn!(
                    app = app_name,
                    generation = to_gen,
                    "failed to clean up after failed activation: {cleanup_err:?}"
                );
            }
            // Attempt rollback to the previous generation.
            if let Some(prev) = from {
                let prev_dir = self.generation_dir(app_name, prev);
                if prev_dir.exists() && Self::is_complete(&prev_dir) {
                    info!(
                        app = app_name,
                        from = to_gen,
                        to = prev,
                        "rolling back to previous generation"
                    );
                    if let Err(rollback_err) = self.run_activate(app_name, prev, true) {
                        warn!(
                            app = app_name,
                            generation = prev,
                            "rollback also failed: {rollback_err:?}"
                        );
                        self.write_state(
                            app_name,
                            &AppState::Error(
                                AppStateError::new(
                                    to_gen,
                                    format!(
                                        "activation failed and rollback to generation {prev} also failed"
                                    ),
                                )
                                .with_from(Some(prev)),
                            ),
                        )?;
                        return Err(err);
                    }
                    // Rollback succeeded.
                    return Ok(());
                }
            }
            // No previous generation to roll back to.
            self.write_state(
                app_name,
                &AppState::Error(
                    AppStateError::new(to_gen, format!("activation failed: {err:?}"))
                        .with_from(from),
                ),
            )?;
            return Err(err);
        }

        Ok(())
    }

    /// Run the orchestrator's activate operation.
    fn run_activate(&self, app_name: &str, gen_number: u64, recovery: bool) -> AppsResult<()> {
        let gen_dir = self.generation_dir(app_name, gen_number);
        let manifest = load_manifest(&gen_dir)?;
        let orchestrator = orchestrators::get(manifest.orchestrator.as_str())?;
        let app_dir = self.app_dir(app_name);
        let data_dir = self.data_dir(app_name);
        let ctx = AppContext {
            app_name,
            app_dir: &app_dir,
            generation_dir: &gen_dir,
            data_dir: &data_dir,
            recovery,
            service_manager: &self.service_manager,
            manifest: &manifest,
        };

        orchestrator
            .activate(&ctx)
            .whatever("orchestrator activation failed")?;

        Self::mark_activated(&gen_dir)?;

        self.write_state(app_name, &AppState::Active(AppStateActive::new(gen_number)))?;
        info!(
            app = app_name,
            generation = gen_number,
            recovery,
            "generation activated"
        );
        Ok(())
    }

    /// Run the orchestrator's deactivate operation for a specific generation.
    fn run_deactivate(&self, app_name: &str, gen_number: u64, recovery: bool) -> AppsResult<()> {
        let gen_dir = self.generation_dir(app_name, gen_number);
        if !gen_dir.exists() {
            return Ok(());
        }
        let manifest = load_manifest(&gen_dir)?;
        let orchestrator = orchestrators::get(manifest.orchestrator.as_str())?;
        let app_dir = self.app_dir(app_name);
        let data_dir = self.data_dir(app_name);
        let ctx = AppContext {
            app_name,
            app_dir: &app_dir,
            generation_dir: &gen_dir,
            data_dir: &data_dir,
            recovery,
            service_manager: &self.service_manager,
            manifest: &manifest,
        };

        orchestrator
            .deactivate(&ctx)
            .whatever("orchestrator deactivation failed")?;
        Ok(())
    }

    /// Start the workload of an already-active generation.
    ///
    /// The state transitions to `Starting` before the orchestrator is called and back to
    /// `Active` afterwards, ensuring crash recovery can replay the operation if it is
    /// interrupted.
    /// The caller must hold the [`AppLock`] for this app.
    pub fn start_app(&self, _lock: &AppLock, app_name: &str) -> AppsResult<()> {
        let AppState::Active(AppStateActive { generation }) = self.read_state(app_name)? else {
            reportify::bail!("app {app_name} has no active generation");
        };

        self.write_state(
            app_name,
            &AppState::Starting(AppStateStarting::new(generation)),
        )?;

        let result = self.run_start(app_name, generation, false);

        // Always transition back to Active regardless of outcome.
        self.write_state(app_name, &AppState::Active(AppStateActive::new(generation)))?;

        result.whatever("failed to start app workload")?;
        info!(app = app_name, "workload started");
        Ok(())
    }

    /// Stop the workload of an already-active generation without deactivating it.
    ///
    /// The state transitions to `Stopping` before the orchestrator is called and back to
    /// `Active` afterwards, ensuring crash recovery can replay the operation if it is
    /// interrupted.
    /// The caller must hold the [`AppLock`] for this app.
    pub fn stop_app(&self, _lock: &AppLock, app_name: &str) -> AppsResult<()> {
        let AppState::Active(AppStateActive { generation }) = self.read_state(app_name)? else {
            reportify::bail!("app {app_name} has no active generation");
        };

        self.write_state(
            app_name,
            &AppState::Stopping(AppStateStopping::new(generation)),
        )?;

        let result = self.run_stop(app_name, generation, false);

        // Always transition back to Active regardless of outcome.
        self.write_state(app_name, &AppState::Active(AppStateActive::new(generation)))?;

        result.whatever("failed to stop app workload")?;
        info!(app = app_name, "workload stopped");
        Ok(())
    }

    /// Run the orchestrator's start operation for a specific generation.
    fn run_start(&self, app_name: &str, gen_number: u64, recovery: bool) -> AppsResult<()> {
        let gen_dir = self.generation_dir(app_name, gen_number);
        let manifest = load_manifest(&gen_dir)?;
        let orchestrator = orchestrators::get(manifest.orchestrator.as_str())?;
        let app_dir = self.app_dir(app_name);
        let data_dir = self.data_dir(app_name);
        let ctx = AppContext {
            app_name,
            app_dir: &app_dir,
            generation_dir: &gen_dir,
            data_dir: &data_dir,
            recovery,
            service_manager: &self.service_manager,
            manifest: &manifest,
        };
        orchestrator
            .start(&ctx)
            .whatever("orchestrator start failed")
    }

    /// Run the orchestrator's stop operation for a specific generation.
    fn run_stop(&self, app_name: &str, gen_number: u64, recovery: bool) -> AppsResult<()> {
        let gen_dir = self.generation_dir(app_name, gen_number);
        let manifest = load_manifest(&gen_dir)?;
        let orchestrator = orchestrators::get(manifest.orchestrator.as_str())?;
        let app_dir = self.app_dir(app_name);
        let data_dir = self.data_dir(app_name);
        let ctx = AppContext {
            app_name,
            app_dir: &app_dir,
            generation_dir: &gen_dir,
            data_dir: &data_dir,
            recovery,
            service_manager: &self.service_manager,
            manifest: &manifest,
        };
        orchestrator.stop(&ctx).whatever("orchestrator stop failed")
    }

    /// Get status of the currently active generation.
    pub fn app_status(&self, app_name: &str) -> AppsResult<AppStatus> {
        let Some(gen_dir) = self.resolve_current(app_name)? else {
            return Ok(AppStatus::Stopped);
        };
        let manifest = load_manifest(&gen_dir)?;
        let orchestrator = orchestrators::get(manifest.orchestrator.as_str())?;
        let app_dir = self.app_dir(app_name);
        let data_dir = self.data_dir(app_name);
        let ctx = AppContext {
            app_name,
            app_dir: &app_dir,
            generation_dir: &gen_dir,
            data_dir: &data_dir,
            recovery: false,
            service_manager: &self.service_manager,
            manifest: &manifest,
        };
        orchestrator
            .status(&ctx)
            .whatever("failed to get app status")
    }

    /// List all installed apps.
    pub fn list_apps(&self) -> AppsResult<Vec<String>> {
        let mut apps = Vec::new();
        if !self.apps_dir.exists() {
            return Ok(apps);
        }
        let entries = fs::read_dir(&self.apps_dir).whatever("unable to read apps directory")?;
        for entry in entries {
            let entry = entry.whatever("unable to read directory entry")?;
            if entry
                .file_type()
                .whatever("unable to get file type")?
                .is_dir()
            {
                if let Some(name) = entry.file_name().to_str() {
                    apps.push(name.to_owned());
                }
            }
        }
        apps.sort();
        Ok(apps)
    }

    /// List generations for a given app.
    pub fn list_generations(&self, app_name: &str) -> AppsResult<Vec<ResolvedGeneration>> {
        let generations_dir = self.generations_dir(app_name);
        let mut generations = Vec::new();
        if !generations_dir.exists() {
            return Ok(generations);
        }
        let entries =
            fs::read_dir(&generations_dir).whatever("unable to read generations directory")?;
        for entry in entries {
            let entry = entry.whatever("unable to read directory entry")?;
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(number) = name.parse::<u64>() {
                    let gen_dir = entry.path();
                    let complete = Self::is_complete(&gen_dir);
                    let meta_path = gen_dir.join(".rugix").join("generation.json");
                    let meta = if let Ok(content) = fs::read_to_string(&meta_path) {
                        serde_json::from_str::<AppGeneration>(&content).ok()
                    } else {
                        None
                    };
                    let meta = meta.unwrap_or_else(|| AppGeneration::new(number, String::new()));
                    generations.push(ResolvedGeneration { meta, complete });
                }
            }
        }
        generations.sort_by_key(|g| g.meta.number);
        Ok(generations)
    }

    /// Get the currently active generation number, if any.
    pub fn current_generation(&self, app_name: &str) -> AppsResult<Option<u64>> {
        match self.read_state(app_name)? {
            AppState::Active(AppStateActive { generation })
            | AppState::Starting(AppStateStarting { generation })
            | AppState::Stopping(AppStateStopping { generation }) => Ok(Some(generation)),
            _ => Ok(None),
        }
    }

    /// Find the most recently activated generation (by `lastActivated` timestamp).
    pub fn last_activated_generation(&self, app_name: &str) -> AppsResult<Option<u64>> {
        let generations = self.list_generations(app_name)?;
        let best = generations
            .iter()
            .filter_map(|g| {
                g.meta
                    .last_activated
                    .as_deref()
                    .map(|ts| (g.meta.number, ts))
            })
            .max_by_key(|(_num, ts)| ts.to_owned());
        Ok(best.map(|(num, _)| num))
    }

    /// Find the generation that [`Self::rollback`] would activate.
    pub fn rollback_target_generation(&self, app_name: &str) -> AppsResult<u64> {
        let Some(current) = self.current_generation(app_name)? else {
            reportify::bail!("no current generation to rollback from");
        };
        let generations = self.list_generations(app_name)?;
        let Some(previous) = generations
            .iter()
            .rev()
            .find(|g| g.meta.number < current && g.meta.last_activated.is_some())
        else {
            reportify::bail!("no previous activated generation to rollback to");
        };
        Ok(previous.meta.number)
    }

    /// Rollback: deactivate the current generation and activate the most recent
    /// previous generation that was successfully activated before.
    /// The caller must hold the [`AppLock`] for this app.
    pub fn rollback(&self, _lock: &AppLock, app_name: &str) -> AppsResult<()> {
        let Some(current) = self.current_generation(app_name)? else {
            reportify::bail!("no current generation to rollback from");
        };
        let previous = self.rollback_target_generation(app_name)?;
        info!(
            app = app_name,
            from = current,
            to = previous,
            "rolling back"
        );
        self.activate_generation(_lock, app_name, previous)
    }

    /// Remove a generation directory.
    ///
    /// Removes the complete marker first so that an interrupted removal leaves
    /// the generation in an incomplete state rather than appearing valid.
    fn remove_generation(&self, app_name: &str, gen_number: u64) -> std::io::Result<()> {
        let gen_dir = self.generation_dir(app_name, gen_number);
        let complete_marker = gen_dir.join(".rugix/complete");
        if complete_marker.exists() {
            fs::remove_file(&complete_marker)?;
        }
        fs::remove_dir_all(&gen_dir)
    }

    /// Garbage collect old generations.
    ///
    /// Generations that were never activated are always removed (they are not valid
    /// rollback targets). Among previously-activated generations, at most `keep` of
    /// the most recent ones are retained. The currently active generation is never
    /// removed.
    /// The caller must hold the [`AppLock`] for this app.
    pub fn gc(&self, _lock: &AppLock, app_name: &str, keep: usize) -> AppsResult<Vec<u64>> {
        let current = self.current_generation(app_name)?;
        let mut generations = self.list_generations(app_name)?;
        generations.sort_by_key(|g| g.meta.number);
        let mut removed = Vec::new();

        // Remove all never-activated generations.
        for gen in &generations {
            if gen.meta.last_activated.is_none() {
                if let Err(e) = self.remove_generation(app_name, gen.meta.number) {
                    info!(
                        generation = gen.meta.number,
                        "failed to remove generation: {e}"
                    );
                } else {
                    removed.push(gen.meta.number);
                }
            }
        }

        // Among previously-activated generations, keep the most recent `keep`.
        let activated: Vec<_> = generations
            .iter()
            .filter(|g| g.meta.last_activated.is_some() && Some(g.meta.number) != current)
            .collect();
        if activated.len() > keep {
            let to_remove = activated.len() - keep;
            for gen in activated.iter().take(to_remove) {
                if let Err(e) = self.remove_generation(app_name, gen.meta.number) {
                    info!(
                        generation = gen.meta.number,
                        "failed to remove generation: {e}"
                    );
                } else {
                    removed.push(gen.meta.number);
                }
            }
        }

        removed.sort();
        Ok(removed)
    }

    /// Remove an app entirely.
    ///
    /// The caller must hold the [`AppLock`] for this app.
    pub fn remove_app(&self, _lock: &AppLock, app_name: &str) -> AppsResult<()> {
        // Deactivate if active (stops workload + cleans up orchestrator resources).
        if self.current_generation(app_name)?.is_some() {
            self.deactivate(_lock, app_name)?;
        }
        let app_dir = self.app_dir(app_name);
        if app_dir.exists() {
            fs::remove_dir_all(&app_dir).whatever("unable to remove app directory")?;
        }
        info!(app = app_name, "app removed");
        Ok(())
    }

    /// Resolve the active generation directory from the persisted state.
    fn resolve_current(&self, app_name: &str) -> AppsResult<Option<PathBuf>> {
        let Some(gen) = self.current_generation(app_name)? else {
            return Ok(None);
        };
        let dir = self.generation_dir(app_name, gen);
        Ok(dir.exists().then_some(dir))
    }
}

#[cfg(test)]
mod tests {
    use crate::config::apps::AppsConfig;

    use super::AppManager;

    #[test]
    fn invalid_app_names_are_rejected_before_lock_paths_are_created() {
        let tempdir = tempfile::tempdir().unwrap();
        let apps_dir = tempdir.path().join("apps");
        let manager = AppManager::new(apps_dir, AppsConfig::new());

        assert!(manager.lock_app("../escape").is_err());
        assert!(!tempdir.path().join("escape").exists());
    }
}

/// Load an app manifest.
fn load_manifest(gen_dir: &Path) -> AppsResult<AppManifest> {
    let manifest_path = gen_dir.join("app.toml");
    let content = fs::read_to_string(&manifest_path).whatever("unable to read app.toml")?;
    toml::from_str(&content).whatever("unable to parse app.toml")
}
