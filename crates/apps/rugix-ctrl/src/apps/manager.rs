//! Persistent generation, lifecycle, rollback, and configuration management for Rugix
//! Apps.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use reportify::ResultExt;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::config::apps::AppConfiguration;
use crate::config::apps::AppConfigurationState;
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
use super::configuration;
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
        validate_app_name(app_name)?;
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
    pub fn generation_dir(&self, app_name: &str, number: u64) -> AppsResult<PathBuf> {
        validate_app_name(app_name)?;
        Ok(self.generation_dir_unchecked(app_name, number))
    }

    fn generation_dir_unchecked(&self, app_name: &str, number: u64) -> PathBuf {
        self.generations_dir(app_name).join(number.to_string())
    }

    /// Path to the data directory of an app.
    fn data_dir(&self, app_name: &str) -> PathBuf {
        self.app_dir(app_name).join("data")
    }

    /// Path to the device-specific configuration revisions of an app.
    fn configurations_dir(&self, app_name: &str) -> PathBuf {
        self.app_dir(app_name).join("configurations")
    }

    /// Path to a device-specific configuration revision.
    fn configuration_path(&self, app_name: &str, revision: u64) -> PathBuf {
        self.configurations_dir(app_name)
            .join(format!("{revision}.json"))
    }

    /// Path to the state file of an app.
    fn state_path(&self, app_name: &str) -> PathBuf {
        self.app_dir(app_name).join(".rugix/state.json")
    }

    /// Path to the desired revision and revision-allocation state.
    fn configuration_state_path(&self, app_name: &str) -> PathBuf {
        self.app_dir(app_name)
            .join(".rugix/configuration-state.json")
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
        validate_app_name(app_name)?;
        let path = self.state_path(app_name);
        match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).whatever("unable to parse app state"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(AppState::Inactive),
            Err(err) => Err(err).whatever("unable to read app state"),
        }
    }

    /// Read configuration state, defaulting to an empty state if absent.
    fn read_configuration_state(&self, app_name: &str) -> AppsResult<AppConfigurationState> {
        let path = self.configuration_state_path(app_name);
        match fs::read_to_string(&path) {
            Ok(content) => {
                serde_json::from_str(&content).whatever("unable to parse app configuration state")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(AppConfigurationState::new())
            }
            Err(error) => Err(error).whatever("unable to read app configuration state"),
        }
    }

    /// Persist configuration state atomically.
    fn write_configuration_state(
        &self,
        app_name: &str,
        state: &AppConfigurationState,
    ) -> AppsResult<()> {
        let content = serde_json::to_vec_pretty(state)
            .whatever("unable to serialize app configuration state")?;
        rugix_common::fsutils::atomic_write(&self.configuration_state_path(app_name), &content)
            .whatever("unable to write app configuration state")
    }

    /// Read the desired device-specific configuration revision.
    fn read_configuration_revision(&self, app_name: &str) -> AppsResult<Option<u64>> {
        Ok(self.read_configuration_state(app_name)?.revision)
    }

    /// Persist the desired device-specific configuration revision.
    fn write_configuration_revision(
        &self,
        app_name: &str,
        revision: Option<u64>,
    ) -> AppsResult<()> {
        let state = self
            .read_configuration_state(app_name)?
            .with_revision(revision);
        self.write_configuration_state(app_name, &state)
    }

    /// Return the effective application configuration.
    pub fn read_configuration(&self, app_name: &str) -> AppsResult<Option<AppConfiguration>> {
        validate_app_name(app_name)?;
        let generation = self.configuration_generation(app_name)?;
        let manifest = load_manifest(&generation)?;
        let revision = self.read_configuration_revision(app_name)?;
        let revision_path = revision.map(|revision| self.configuration_path(app_name, revision));
        Ok(configuration::load_effective(&generation, &manifest, revision, revision_path)?.value)
    }

    /// Return the JSON Schema declared by the current app generation.
    pub fn read_configuration_schema(
        &self,
        app_name: &str,
    ) -> AppsResult<Option<AppConfiguration>> {
        validate_app_name(app_name)?;
        let generation = self.configuration_generation(app_name)?;
        let manifest = load_manifest(&generation)?;
        configuration::load_schema(&generation, &manifest)
    }

    /// Store and apply a new device-specific JSON configuration revision.
    ///
    /// The caller must hold the [`AppLock`] for this app.
    #[tracing::instrument(level = "info", skip(self, _lock, value), fields(app = app_name))]
    pub fn set_configuration(
        &self,
        _lock: &AppLock,
        app_name: &str,
        value: &AppConfiguration,
    ) -> AppsResult<u64> {
        validate_app_name(app_name)?;
        let active = match self.read_state(app_name)? {
            AppState::Inactive => None,
            AppState::Active(state) => Some(AppDeployment::new(
                state.generation,
                state.configuration_revision,
            )),
            AppState::Starting(..)
            | AppState::Stopping(..)
            | AppState::Switching(..)
            | AppState::Error(..) => {
                reportify::bail!(
                    "unable to set app configuration while lifecycle state requires recovery"
                );
            }
        };
        let generation_dir = self.configuration_generation(app_name)?;
        let revision = self.store_configuration_in(app_name, &generation_dir, value)?;

        match active {
            // Re-applying the document an active app already runs with would otherwise
            // restart a healthy workload for nothing.
            Some(active) if active.configuration_revision == Some(revision) => {
                info!(app = app_name, revision, "app configuration unchanged");
            }
            Some(active) => {
                let target = AppDeployment::new(active.generation, Some(revision));
                self.do_switch(app_name, Some(active), Some(target), false)?;
            }
            None => self.write_configuration_revision(app_name, Some(revision))?,
        }
        Ok(revision)
    }

    /// Resolve the deployment a generation should be activated as.
    ///
    /// A supplied document is validated against the configuration schema declared by
    /// `generation` and stored as a revision. This is what allows a generation that
    /// tightens its schema to be installed together with a document satisfying it,
    /// since [`Self::set_configuration`] can only validate against the generation an
    /// app currently runs. Without a document, the app's desired revision is carried
    /// forward.
    ///
    /// The resulting effective configuration is validated against the generation, so
    /// callers can fail an installation before any workload is stopped.
    ///
    /// The caller must hold the [`AppLock`] for this app.
    #[tracing::instrument(level = "info", skip(self, _lock, configuration), fields(app = app_name))]
    pub fn prepare_configuration(
        &self,
        _lock: &AppLock,
        app_name: &str,
        generation: u64,
        configuration: Option<&AppConfiguration>,
    ) -> AppsResult<AppDeployment> {
        validate_app_name(app_name)?;
        let revision = match configuration {
            Some(configuration) => {
                let generation_dir = self.generation_dir_unchecked(app_name, generation);
                Some(self.store_configuration_in(app_name, &generation_dir, configuration)?)
            }
            None => self.read_configuration_revision(app_name)?,
        };
        let deployment = AppDeployment::new(generation, revision);
        self.resolve_configuration(app_name, deployment)?;
        Ok(deployment)
    }

    /// Validate a document against a generation and store it as a revision.
    fn store_configuration_in(
        &self,
        app_name: &str,
        generation_dir: &Path,
        value: &AppConfiguration,
    ) -> AppsResult<u64> {
        let manifest = load_manifest(generation_dir)?;
        configuration::validate(generation_dir, &manifest, value)?;
        let content = configuration::serialize(value)?;
        if let Some(revision) = self.desired_revision_with_content(app_name, &content)? {
            return Ok(revision);
        }

        let revision = self.allocate_configuration_revision(app_name)?;
        let configurations_dir = self.configurations_dir(app_name);
        fs::create_dir_all(&configurations_dir)
            .whatever("unable to create app configurations directory")?;
        fs::set_permissions(&configurations_dir, fs::Permissions::from_mode(0o700))
            .whatever("unable to protect app configurations directory")?;
        rugix_common::fsutils::atomic_write(&self.configuration_path(app_name, revision), &content)
            .whatever("unable to write app configuration revision")?;
        Ok(revision)
    }

    /// Return the desired revision if its stored document is `content`.
    ///
    /// Reusing it keeps revision numbers stable when a rollout supplies the same
    /// document on every installation.
    fn desired_revision_with_content(
        &self,
        app_name: &str,
        content: &[u8],
    ) -> AppsResult<Option<u64>> {
        let Some(revision) = self.read_configuration_revision(app_name)? else {
            return Ok(None);
        };
        match fs::read(self.configuration_path(app_name, revision)) {
            Ok(stored) => Ok((stored == content).then_some(revision)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).whatever("unable to read app configuration revision"),
        }
    }

    /// Check for and recover any interrupted transition for a single app.
    ///
    /// The caller must hold the [`AppLock`] for this app.
    pub fn recover_app(&self, _lock: &AppLock, app_name: &str) -> AppsResult<()> {
        validate_app_name(app_name)?;
        match self.read_state(app_name)? {
            AppState::Switching(AppStateSwitching {
                from,
                from_configuration_revision,
                to,
                to_configuration_revision,
                recovery,
            }) => {
                let from = from
                    .map(|generation| AppDeployment::new(generation, from_configuration_revision));
                let to =
                    to.map(|generation| AppDeployment::new(generation, to_configuration_revision));
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
            AppState::Starting(AppStateStarting {
                generation,
                configuration_revision,
            }) => {
                info!(app = app_name, generation, "recovering interrupted start");
                let deployment = AppDeployment::new(generation, configuration_revision);
                if let Err(e) = self.run_start(app_name, deployment, true) {
                    warn!(app = app_name, generation, "start recovery failed: {e:?}");
                }
                self.write_active_state(app_name, deployment)?;
            }
            AppState::Stopping(AppStateStopping {
                generation,
                configuration_revision,
            }) => {
                info!(app = app_name, generation, "recovering interrupted stop");
                let deployment = AppDeployment::new(generation, configuration_revision);
                if let Err(e) = self.run_stop(app_name, deployment, true) {
                    warn!(app = app_name, generation, "stop recovery failed: {e:?}");
                }
                self.write_active_state(app_name, deployment)?;
            }
            AppState::Error(AppStateError {
                from,
                from_configuration_revision,
                to,
                to_configuration_revision,
                message,
            }) => {
                // Try to recover by activating the previously working generation first. If there
                // was none, or if that also fails, try the generation that originally failed. The
                // underlying issue may have been transient.
                let target = match from {
                    Some(generation) => AppDeployment::new(generation, from_configuration_revision),
                    None => AppDeployment::new(to, to_configuration_revision),
                };
                info!(
                    app = app_name,
                    from,
                    to,
                    target = target.generation,
                    message,
                    "recovering from error state"
                );
                if let Err(e) = self.run_activate(app_name, target, true) {
                    warn!(
                        app = app_name,
                        target = target.generation,
                        "recovery activation failed: {e:?}"
                    );
                    // If we tried `from` and it failed, fall back to `to`.
                    if from.is_some() {
                        info!(app = app_name, to, "falling back to failed generation");
                        let target = AppDeployment::new(to, to_configuration_revision);
                        if let Err(e) = self.run_activate(app_name, target, true) {
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
        validate_app_name(app_name)?;
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
        fs::File::open(&rugix_dir)
            .whatever("unable to open generation metadata directory")?
            .sync_all()
            .whatever("unable to sync generation metadata directory")?;
        Ok(())
    }

    /// Synchronize a generation tree and only then create its durable completion marker.
    pub fn finalize_generation(gen_dir: &Path) -> AppsResult<()> {
        finalize_generation_with(
            || {
                rugix_common::fsutils::sync_tree(gen_dir)
                    .whatever("unable to synchronize app generation")
            },
            || Self::mark_complete(gen_dir),
        )
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
    fn mark_activated(gen_dir: &Path, configuration_revision: Option<u64>) -> AppsResult<()> {
        let meta_path = gen_dir.join(".rugix/generation.json");
        let content =
            fs::read_to_string(&meta_path).whatever("unable to read generation metadata")?;
        let mut gen: AppGeneration =
            serde_json::from_str(&content).whatever("unable to parse generation metadata")?;
        gen.last_activated = Some(jiff::Timestamp::now().to_string());
        gen.configuration_revision = configuration_revision;
        let updated = serde_json::to_string_pretty(&gen)
            .whatever("unable to serialize generation metadata")?;
        rugix_common::fsutils::atomic_write(&meta_path, updated.as_bytes())
            .whatever("unable to write generation metadata")?;
        Ok(())
    }

    /// Activate a generation with exactly the given configuration revision.
    ///
    /// The deployment is activated as given, which is what lets a caller restore a
    /// generation together with the revision it previously ran, including no revision
    /// at all. Use [`Self::prepare_configuration`] to resolve the revision for a new
    /// activation.
    ///
    /// If another generation is currently active it is deactivated first.
    ///
    /// If activation fails, the previous generation is automatically rolled back.
    ///
    /// If rollback also fails, the app enters the `error` state.
    ///
    /// The caller must hold the [`AppLock`] for this app.
    pub fn activate_deployment(
        &self,
        _lock: &AppLock,
        app_name: &str,
        target: AppDeployment,
    ) -> AppsResult<()> {
        validate_app_name(app_name)?;
        let gen_dir = self.generation_dir_unchecked(app_name, target.generation);
        if !Self::is_complete(&gen_dir) {
            reportify::bail!("generation is not complete (installation may have been interrupted)");
        }

        self.resolve_configuration(app_name, target)?;
        let from = self.current_deployment(app_name)?;
        self.do_switch(app_name, from, Some(target), false)
    }

    /// Deactivate the current generation.
    ///
    /// The caller must hold the [`AppLock`] for this app.
    pub fn deactivate(&self, _lock: &AppLock, app_name: &str) -> AppsResult<()> {
        validate_app_name(app_name)?;
        let Some(current) = self.current_deployment(app_name)? else {
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
        from: Option<AppDeployment>,
        to: Option<AppDeployment>,
        recovery: bool,
    ) -> AppsResult<()> {
        let switching = AppStateSwitching::new()
            .with_from(from.map(|deployment| deployment.generation))
            .with_from_configuration_revision(
                from.and_then(|deployment| deployment.configuration_revision),
            )
            .with_to(to.map(|deployment| deployment.generation))
            .with_to_configuration_revision(
                to.and_then(|deployment| deployment.configuration_revision),
            )
            .with_recovery(Some(recovery));
        self.write_state(app_name, &AppState::Switching(switching))?;

        if let Some(from_deployment) = from {
            if let Err(e) = self.run_deactivate(app_name, from_deployment, recovery) {
                if to.is_some() {
                    // We're switching to a new generation. Press on despite the deactivation
                    // failure so we don't leave nothing running.
                    warn!(
                        app = app_name,
                        generation = from_deployment.generation,
                        "deactivation of old generation failed, continuing with activation: {e:?}"
                    );
                } else {
                    // Pure deactivation with no target. Propagate the error.
                    return Err(e);
                }
            }
        }

        let Some(to_deployment) = to else {
            // Pure deactivation, already done.
            self.write_state(app_name, &AppState::Inactive)?;
            info!(app = app_name, recovery, "generation deactivated");
            return Ok(());
        };

        if let Err(err) = self.run_activate(app_name, to_deployment, recovery) {
            error!(
                app = app_name,
                generation = to_deployment.generation,
                "activation failed: {err:?}"
            );
            // Try to clean up any residual resources from the failed activation
            // (e.g. partially started containers) before attempting rollback.
            if let Err(cleanup_err) = self.run_deactivate(app_name, to_deployment, true) {
                warn!(
                    app = app_name,
                    generation = to_deployment.generation,
                    "failed to clean up after failed activation: {cleanup_err:?}"
                );
            }
            // Attempt rollback to the previous generation.
            if let Some(previous) = from {
                let prev_dir = self.generation_dir_unchecked(app_name, previous.generation);
                if prev_dir.exists() && Self::is_complete(&prev_dir) {
                    info!(
                        app = app_name,
                        from = to_deployment.generation,
                        to = previous.generation,
                        "rolling back to previous generation"
                    );
                    if let Err(rollback_err) = self.run_activate(app_name, previous, true) {
                        warn!(
                            app = app_name,
                            generation = previous.generation,
                            "rollback also failed: {rollback_err:?}"
                        );
                        self.write_state(
                            app_name,
                            &AppState::Error(
                                AppStateError::new(
                                    to_deployment.generation,
                                    format!(
                                        "activation failed and rollback to generation {} also failed",
                                        previous.generation
                                    ),
                                )
                                .with_from(Some(previous.generation))
                                .with_from_configuration_revision(
                                    previous.configuration_revision,
                                )
                                .with_to_configuration_revision(
                                    to_deployment.configuration_revision,
                                ),
                            ),
                        )?;
                        return Err(err);
                    }
                    // Rollback succeeded.
                    reportify::bail!(
                        "activation of generation {} failed; successfully rolled back to generation {}: {err:?}",
                        to_deployment.generation,
                        previous.generation
                    );
                }
            }
            // No previous generation to roll back to.
            self.write_state(
                app_name,
                &AppState::Error(
                    AppStateError::new(
                        to_deployment.generation,
                        format!("activation failed: {err:?}"),
                    )
                    .with_from(from.map(|deployment| deployment.generation))
                    .with_from_configuration_revision(
                        from.and_then(|deployment| deployment.configuration_revision),
                    )
                    .with_to_configuration_revision(to_deployment.configuration_revision),
                ),
            )?;
            return Err(err);
        }

        Ok(())
    }

    /// Run the orchestrator's activate operation.
    fn run_activate(
        &self,
        app_name: &str,
        deployment: AppDeployment,
        recovery: bool,
    ) -> AppsResult<()> {
        let gen_dir = self.generation_dir_unchecked(app_name, deployment.generation);
        let manifest = load_manifest(&gen_dir)?;
        let configuration = self.resolve_configuration(app_name, deployment)?;
        let orchestrator = orchestrators::get(manifest.orchestrator.as_str())?;
        let app_dir = self.app_dir(app_name);
        let data_dir = self.data_dir(app_name);
        let ctx = AppContext {
            app_name,
            app_dir: &app_dir,
            generation_dir: &gen_dir,
            data_dir: &data_dir,
            configuration_path: configuration.path.as_deref(),
            configuration: configuration.value.as_ref(),
            recovery,
            service_manager: &self.service_manager,
            manifest: &manifest,
        };

        orchestrator
            .activate(&ctx)
            .whatever("orchestrator activation failed")?;

        Self::mark_activated(&gen_dir, deployment.configuration_revision)?;

        self.write_configuration_revision(app_name, deployment.configuration_revision)?;
        self.write_active_state(app_name, deployment)?;
        info!(
            app = app_name,
            generation = deployment.generation,
            recovery,
            "generation activated"
        );
        Ok(())
    }

    /// Run the orchestrator's deactivate operation for a specific generation.
    fn run_deactivate(
        &self,
        app_name: &str,
        deployment: AppDeployment,
        recovery: bool,
    ) -> AppsResult<()> {
        let gen_dir = self.generation_dir_unchecked(app_name, deployment.generation);
        if !gen_dir.exists() {
            return Ok(());
        }
        let manifest = load_manifest(&gen_dir)?;
        let configuration = self.resolve_configuration(app_name, deployment)?;
        let orchestrator = orchestrators::get(manifest.orchestrator.as_str())?;
        let app_dir = self.app_dir(app_name);
        let data_dir = self.data_dir(app_name);
        let ctx = AppContext {
            app_name,
            app_dir: &app_dir,
            generation_dir: &gen_dir,
            data_dir: &data_dir,
            configuration_path: configuration.path.as_deref(),
            configuration: configuration.value.as_ref(),
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
        validate_app_name(app_name)?;
        let AppState::Active(AppStateActive {
            generation,
            configuration_revision,
        }) = self.read_state(app_name)?
        else {
            reportify::bail!("app {app_name} has no active generation");
        };
        let deployment = AppDeployment::new(generation, configuration_revision);

        self.write_state(
            app_name,
            &AppState::Starting(
                AppStateStarting::new(generation)
                    .with_configuration_revision(configuration_revision),
            ),
        )?;

        let result = self.run_start(app_name, deployment, false);

        // Always transition back to Active regardless of outcome.
        self.write_active_state(app_name, deployment)?;

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
        validate_app_name(app_name)?;
        let AppState::Active(AppStateActive {
            generation,
            configuration_revision,
        }) = self.read_state(app_name)?
        else {
            reportify::bail!("app {app_name} has no active generation");
        };
        let deployment = AppDeployment::new(generation, configuration_revision);

        self.write_state(
            app_name,
            &AppState::Stopping(
                AppStateStopping::new(generation)
                    .with_configuration_revision(configuration_revision),
            ),
        )?;

        let result = self.run_stop(app_name, deployment, false);

        // Always transition back to Active regardless of outcome.
        self.write_active_state(app_name, deployment)?;

        result.whatever("failed to stop app workload")?;
        info!(app = app_name, "workload stopped");
        Ok(())
    }

    /// Run the orchestrator's start operation for a specific generation.
    fn run_start(
        &self,
        app_name: &str,
        deployment: AppDeployment,
        recovery: bool,
    ) -> AppsResult<()> {
        let gen_dir = self.generation_dir_unchecked(app_name, deployment.generation);
        let manifest = load_manifest(&gen_dir)?;
        let configuration = self.resolve_configuration(app_name, deployment)?;
        let orchestrator = orchestrators::get(manifest.orchestrator.as_str())?;
        let app_dir = self.app_dir(app_name);
        let data_dir = self.data_dir(app_name);
        let ctx = AppContext {
            app_name,
            app_dir: &app_dir,
            generation_dir: &gen_dir,
            data_dir: &data_dir,
            configuration_path: configuration.path.as_deref(),
            configuration: configuration.value.as_ref(),
            recovery,
            service_manager: &self.service_manager,
            manifest: &manifest,
        };
        orchestrator
            .start(&ctx)
            .whatever("orchestrator start failed")
    }

    /// Run the orchestrator's stop operation for a specific generation.
    fn run_stop(
        &self,
        app_name: &str,
        deployment: AppDeployment,
        recovery: bool,
    ) -> AppsResult<()> {
        let gen_dir = self.generation_dir_unchecked(app_name, deployment.generation);
        let manifest = load_manifest(&gen_dir)?;
        let configuration = self.resolve_configuration(app_name, deployment)?;
        let orchestrator = orchestrators::get(manifest.orchestrator.as_str())?;
        let app_dir = self.app_dir(app_name);
        let data_dir = self.data_dir(app_name);
        let ctx = AppContext {
            app_name,
            app_dir: &app_dir,
            generation_dir: &gen_dir,
            data_dir: &data_dir,
            configuration_path: configuration.path.as_deref(),
            configuration: configuration.value.as_ref(),
            recovery,
            service_manager: &self.service_manager,
            manifest: &manifest,
        };
        orchestrator.stop(&ctx).whatever("orchestrator stop failed")
    }

    /// Get status of the currently active generation.
    pub fn app_status(&self, app_name: &str) -> AppsResult<AppStatus> {
        validate_app_name(app_name)?;
        let Some(deployment) = self.current_deployment(app_name)? else {
            return Ok(AppStatus::Stopped);
        };
        let gen_dir = self.generation_dir_unchecked(app_name, deployment.generation);
        if !gen_dir.exists() {
            return Ok(AppStatus::Stopped);
        }
        let manifest = load_manifest(&gen_dir)?;
        let configuration = self.resolve_configuration(app_name, deployment)?;
        let orchestrator = orchestrators::get(manifest.orchestrator.as_str())?;
        let app_dir = self.app_dir(app_name);
        let data_dir = self.data_dir(app_name);
        let ctx = AppContext {
            app_name,
            app_dir: &app_dir,
            generation_dir: &gen_dir,
            data_dir: &data_dir,
            configuration_path: configuration.path.as_deref(),
            configuration: configuration.value.as_ref(),
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
                    if validate_app_name(name).is_ok() {
                        apps.push(name.to_owned());
                    } else {
                        warn!(app = name, "ignoring directory with invalid app name");
                    }
                }
            }
        }
        apps.sort();
        Ok(apps)
    }

    /// List generations for a given app.
    pub fn list_generations(&self, app_name: &str) -> AppsResult<Vec<ResolvedGeneration>> {
        validate_app_name(app_name)?;
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
        validate_app_name(app_name)?;
        Ok(self
            .current_deployment(app_name)?
            .map(|deployment| deployment.generation))
    }

    /// Find the most recently activated generation (by `lastActivated` timestamp).
    pub fn last_activated_generation(&self, app_name: &str) -> AppsResult<Option<u64>> {
        validate_app_name(app_name)?;
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
        Ok(self.rollback_target_deployment(app_name)?.generation)
    }

    /// Find the generation and configuration pair restored by rollback.
    fn rollback_target_deployment(&self, app_name: &str) -> AppsResult<AppDeployment> {
        validate_app_name(app_name)?;
        let Some(current) = self.current_generation(app_name)? else {
            reportify::bail!("no current generation to rollback from");
        };
        let generations = self.list_generations(app_name)?;
        let Some(previous) = generations.iter().rev().find(|generation| {
            generation.meta.number < current
                && generation.meta.last_activated.is_some()
                && generation.complete
        }) else {
            reportify::bail!("no previous complete activated generation to rollback to");
        };
        Ok(AppDeployment::new(
            previous.meta.number,
            previous.meta.configuration_revision,
        ))
    }

    /// Rollback: deactivate the current generation and activate the most recent
    /// previous generation that was successfully activated before.
    /// The caller must hold the [`AppLock`] for this app.
    pub fn rollback(&self, _lock: &AppLock, app_name: &str) -> AppsResult<()> {
        validate_app_name(app_name)?;
        let Some(current) = self.current_deployment(app_name)? else {
            reportify::bail!("no current generation to rollback from");
        };
        let previous = self.rollback_target_deployment(app_name)?;
        self.resolve_configuration(app_name, previous)?;
        info!(
            app = app_name,
            from = current.generation,
            to = previous.generation,
            "rolling back"
        );
        self.do_switch(app_name, Some(current), Some(previous), false)
    }

    /// Remove a generation directory.
    ///
    /// Removes the complete marker first so that an interrupted removal leaves
    /// the generation in an incomplete state rather than appearing valid.
    fn remove_generation(&self, app_name: &str, gen_number: u64) -> std::io::Result<()> {
        let gen_dir = self.generation_dir_unchecked(app_name, gen_number);
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
        validate_app_name(app_name)?;
        let state = self.read_state(app_name)?;
        let protected_generations = state_deployments(&state)
            .into_iter()
            .map(|deployment| deployment.generation)
            .collect::<HashSet<_>>();
        let mut generations = self.list_generations(app_name)?;
        generations.sort_by_key(|g| g.meta.number);
        let mut removed = Vec::new();

        // Remove all never-activated generations.
        for gen in &generations {
            if gen.meta.last_activated.is_none()
                && !protected_generations.contains(&gen.meta.number)
            {
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
            .filter(|generation| {
                generation.meta.last_activated.is_some()
                    && !protected_generations.contains(&generation.meta.number)
            })
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

        self.garbage_collect_configuration_revisions(app_name)?;
        removed.sort();
        Ok(removed)
    }

    /// Remove configuration revisions that cannot be used by desired state or rollback.
    fn garbage_collect_configuration_revisions(&self, app_name: &str) -> AppsResult<()> {
        let configurations_dir = self.configurations_dir(app_name);
        if !configurations_dir.exists() {
            return Ok(());
        }

        let mut retained = HashSet::new();
        retained.extend(self.read_configuration_revision(app_name)?);
        for generation in self.list_generations(app_name)? {
            retained.extend(generation.meta.configuration_revision);
        }
        for deployment in state_deployments(&self.read_state(app_name)?) {
            retained.extend(deployment.configuration_revision);
        }

        for entry in fs::read_dir(&configurations_dir)
            .whatever("unable to read app configurations directory")?
        {
            let entry = entry.whatever("unable to read app configuration entry")?;
            let path = entry.path();
            let Some(revision) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<u64>().ok())
                .filter(|_| {
                    path.extension().and_then(|extension| extension.to_str()) == Some("json")
                })
            else {
                continue;
            };
            if !retained.contains(&revision) {
                if let Err(error) = fs::remove_file(&path) {
                    warn!(
                        app = app_name,
                        revision, "failed to remove app configuration revision: {error}"
                    );
                }
            }
        }
        Ok(())
    }

    /// Remove an app entirely.
    ///
    /// The caller must hold the [`AppLock`] for this app.
    pub fn remove_app(&self, _lock: &AppLock, app_name: &str) -> AppsResult<()> {
        validate_app_name(app_name)?;
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

    /// Resolve the active generation and configuration pair from lifecycle state.
    pub fn current_deployment(&self, app_name: &str) -> AppsResult<Option<AppDeployment>> {
        let deployment = match self.read_state(app_name)? {
            AppState::Active(state) => Some(AppDeployment::new(
                state.generation,
                state.configuration_revision,
            )),
            AppState::Starting(state) => Some(AppDeployment::new(
                state.generation,
                state.configuration_revision,
            )),
            AppState::Stopping(state) => Some(AppDeployment::new(
                state.generation,
                state.configuration_revision,
            )),
            _ => None,
        };
        Ok(deployment)
    }

    /// Persist a deployment pair as the active lifecycle state.
    fn write_active_state(&self, app_name: &str, deployment: AppDeployment) -> AppsResult<()> {
        self.write_state(
            app_name,
            &AppState::Active(
                AppStateActive::new(deployment.generation)
                    .with_configuration_revision(deployment.configuration_revision),
            ),
        )
    }

    /// Select the generation whose configuration contract currently applies.
    fn configuration_generation(&self, app_name: &str) -> AppsResult<PathBuf> {
        if let Some(deployment) = self.current_deployment(app_name)? {
            return Ok(self.generation_dir_unchecked(app_name, deployment.generation));
        }
        let generation = self
            .list_generations(app_name)?
            .into_iter()
            .rev()
            .find(|generation| generation.complete)
            .ok_or_else(|| reportify::whatever!("app {app_name} has no complete generation"))?;
        Ok(self.generation_dir_unchecked(app_name, generation.meta.number))
    }

    /// Reserve a never-reused device-specific configuration revision number.
    fn allocate_configuration_revision(&self, app_name: &str) -> AppsResult<u64> {
        let configurations_dir = self.configurations_dir(app_name);
        let mut maximum = 0;
        if configurations_dir.exists() {
            for entry in fs::read_dir(&configurations_dir)
                .whatever("unable to read app configurations directory")?
            {
                let entry = entry.whatever("unable to read app configuration entry")?;
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                    continue;
                }
                if let Some(revision) = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .and_then(|stem| stem.parse::<u64>().ok())
                {
                    maximum = maximum.max(revision);
                }
            }
        }
        let state = self.read_configuration_state(app_name)?;
        maximum = maximum.max(state.last_allocated_revision.unwrap_or(0));
        let revision = maximum
            .checked_add(1)
            .ok_or_else(|| reportify::whatever!("app configuration revision overflow"))?;
        self.write_configuration_state(
            app_name,
            &state.with_last_allocated_revision(Some(revision)),
        )?;
        Ok(revision)
    }

    /// Load and validate the effective configuration for a deployment pair.
    fn resolve_configuration(
        &self,
        app_name: &str,
        deployment: AppDeployment,
    ) -> AppsResult<configuration::EffectiveConfiguration> {
        let generation_dir = self.generation_dir_unchecked(app_name, deployment.generation);
        let manifest = load_manifest(&generation_dir)?;
        let revision_path = deployment
            .configuration_revision
            .map(|revision| self.configuration_path(app_name, revision));
        configuration::load_effective(
            &generation_dir,
            &manifest,
            deployment.configuration_revision,
            revision_path,
        )
    }
}

/// A generation and the device-specific configuration revision used with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppDeployment {
    /// Generation number.
    pub generation: u64,
    /// Configuration revision the generation is deployed with, if any.
    pub configuration_revision: Option<u64>,
}

impl AppDeployment {
    /// Construct a deployment pair.
    pub fn new(generation: u64, configuration_revision: Option<u64>) -> Self {
        Self {
            generation,
            configuration_revision,
        }
    }
}

/// Return every deployment pair that must remain available for lifecycle recovery.
fn state_deployments(state: &AppState) -> Vec<AppDeployment> {
    match state {
        AppState::Inactive => Vec::new(),
        AppState::Active(state) => vec![AppDeployment::new(
            state.generation,
            state.configuration_revision,
        )],
        AppState::Starting(state) => vec![AppDeployment::new(
            state.generation,
            state.configuration_revision,
        )],
        AppState::Stopping(state) => vec![AppDeployment::new(
            state.generation,
            state.configuration_revision,
        )],
        AppState::Switching(state) => [
            state.from.map(|generation| {
                AppDeployment::new(generation, state.from_configuration_revision)
            }),
            state
                .to
                .map(|generation| AppDeployment::new(generation, state.to_configuration_revision)),
        ]
        .into_iter()
        .flatten()
        .collect(),
        AppState::Error(state) => {
            let mut deployments = Vec::with_capacity(2);
            if let Some(generation) = state.from {
                deployments.push(AppDeployment::new(
                    generation,
                    state.from_configuration_revision,
                ));
            }
            deployments.push(AppDeployment::new(
                state.to,
                state.to_configuration_revision,
            ));
            deployments
        }
    }
}

/// Validate an app name before using it in filesystem paths.
fn validate_app_name(app_name: &str) -> AppsResult<()> {
    rugix_bundle::manifest::validate_app_name(app_name).whatever("invalid app name")
}

fn finalize_generation_with(
    synchronize: impl FnOnce() -> AppsResult<()>,
    mark_complete: impl FnOnce() -> AppsResult<()>,
) -> AppsResult<()> {
    synchronize()?;
    mark_complete()
}

/// Load an app manifest.
fn load_manifest(gen_dir: &Path) -> AppsResult<AppManifest> {
    let manifest_path = gen_dir.join("app.toml");
    let content = fs::read_to_string(&manifest_path).whatever("unable to read app.toml")?;
    toml::from_str(&content).whatever("unable to parse app.toml")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use crate::config::apps::AppGeneration;
    use crate::config::apps::AppState;
    use crate::config::apps::AppStateActive;
    use crate::config::apps::AppStateError;
    use crate::config::apps::AppStateSwitching;
    use crate::config::apps::AppsConfig;

    use super::finalize_generation_with;
    use super::AppDeployment;
    use super::AppLock;
    use super::AppManager;

    fn setup_generation(manager: &AppManager, app: &str, generation: u64, script: &str) {
        let dir = manager.generation_dir(app, generation).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app.toml"), "orchestrator = \"generic\"\n").unwrap();
        let orchestrator = dir.join("orchestrator");
        std::fs::write(&orchestrator, script).unwrap();
        std::fs::set_permissions(&orchestrator, std::fs::Permissions::from_mode(0o755)).unwrap();
        manager
            .write_generation_metadata(
                &dir,
                &AppGeneration::new(generation, "2026-07-13T00:00:00Z".to_owned()),
            )
            .unwrap();
        AppManager::mark_complete(&dir).unwrap();
    }

    fn write_configuration(manager: &AppManager, app: &str, revision: u64, content: &str) {
        std::fs::create_dir_all(manager.configurations_dir(app)).unwrap();
        std::fs::write(manager.configuration_path(app, revision), content).unwrap();
    }

    /// Activate a generation the way a caller without an explicit document does.
    fn activate(
        manager: &AppManager,
        lock: &AppLock,
        app: &str,
        generation: u64,
    ) -> super::AppsResult<()> {
        let target = manager.prepare_configuration(lock, app, generation, None)?;
        manager.activate_deployment(lock, app, target)
    }

    /// Declare a configuration schema for an existing generation.
    fn declare_configuration_schema(
        manager: &AppManager,
        app: &str,
        generation: u64,
        schema: &str,
    ) {
        let dir = manager.generation_dir(app, generation).unwrap();
        std::fs::write(dir.join("config.schema.json"), schema).unwrap();
        std::fs::write(
            dir.join("app.toml"),
            "orchestrator = \"generic\"\n[configuration]\nschema = \"config.schema.json\"\n",
        )
        .unwrap();
    }

    #[test]
    fn invalid_app_names_are_rejected_before_lock_paths_are_created() {
        let tempdir = tempfile::tempdir().unwrap();
        let apps_dir = tempdir.path().join("apps");
        let manager = AppManager::new(apps_dir, AppsConfig::new());

        assert!(manager.lock_app("../escape").is_err());
        assert!(manager.generation_dir("../escape", 1).is_err());
        assert!(manager.read_state("../escape").is_err());
        assert!(manager.list_generations("../escape").is_err());
        assert!(manager.current_generation("../escape").is_err());
        assert!(manager.app_status("../escape").is_err());
        assert!(!tempdir.path().join("escape").exists());
    }

    #[test]
    fn failed_activation_returns_error_after_successful_rollback() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        setup_generation(&manager, "example", 1, "#!/bin/sh\nexit 0\n");
        setup_generation(
            &manager,
            "example",
            2,
            "#!/bin/sh\n[ \"$1\" = activate ] && exit 1\nexit 0\n",
        );
        manager
            .write_state("example", &AppState::Active(AppStateActive::new(1)))
            .unwrap();

        let error = manager
            .do_switch(
                "example",
                Some(AppDeployment::new(1, None)),
                Some(AppDeployment::new(2, None)),
                false,
            )
            .unwrap_err();
        assert!(format!("{error:?}").contains("successfully rolled back"));
        assert!(matches!(
            manager.read_state("example").unwrap(),
            AppState::Active(AppStateActive { generation: 1, .. })
        ));
    }

    #[test]
    fn successful_activation_returns_success_and_persists_active_state() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        setup_generation(&manager, "example", 1, "#!/bin/sh\nexit 0\n");

        manager
            .do_switch("example", None, Some(AppDeployment::new(1, None)), false)
            .unwrap();
        assert!(matches!(
            manager.read_state("example").unwrap(),
            AppState::Active(AppStateActive { generation: 1, .. })
        ));
    }

    #[test]
    fn failed_activation_and_rollback_persist_error_state() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        setup_generation(
            &manager,
            "example",
            1,
            "#!/bin/sh\n[ \"$1\" = activate ] && [ \"$RUGIX_APP_RECOVERY\" = true ] && exit 1\nexit 0\n",
        );
        setup_generation(
            &manager,
            "example",
            2,
            "#!/bin/sh\n[ \"$1\" = activate ] && exit 1\nexit 0\n",
        );
        manager
            .write_state("example", &AppState::Active(AppStateActive::new(1)))
            .unwrap();

        assert!(manager
            .do_switch(
                "example",
                Some(AppDeployment::new(1, None)),
                Some(AppDeployment::new(2, None)),
                false,
            )
            .is_err());
        assert!(matches!(
            manager.read_state("example").unwrap(),
            AppState::Error(_)
        ));
    }

    /// Verifies recovery activates the exact generation and configuration revision
    /// requested.
    #[test]
    fn interrupted_switch_is_recovered_to_the_requested_deployment() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        setup_generation(&manager, "example", 1, "#!/bin/sh\nexit 0\n");
        setup_generation(&manager, "example", 2, "#!/bin/sh\nexit 0\n");
        write_configuration(&manager, "example", 1, r#"{"revision":1}"#);
        write_configuration(&manager, "example", 2, r#"{"revision":2}"#);
        manager
            .write_configuration_revision("example", Some(1))
            .unwrap();
        manager
            .write_state(
                "example",
                &AppState::Switching(
                    AppStateSwitching::new()
                        .with_from(Some(1))
                        .with_from_configuration_revision(Some(1))
                        .with_to(Some(2))
                        .with_to_configuration_revision(Some(2)),
                ),
            )
            .unwrap();

        let lock = manager.lock_app("example").unwrap();
        manager.recover_app(&lock, "example").unwrap();
        assert!(matches!(
            manager.read_state("example").unwrap(),
            AppState::Active(AppStateActive {
                generation: 2,
                configuration_revision: Some(2),
            })
        ));
        assert_eq!(
            manager.read_configuration("example").unwrap(),
            Some(crate::apps::configuration::parse(r#"{"revision":2}"#).unwrap())
        );
    }

    /// Verifies updates use desired configuration and rollback restores the old pairing.
    #[test]
    fn app_update_and_rollback_use_their_expected_configuration_revisions() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        setup_generation(&manager, "example", 1, "#!/bin/sh\nexit 0\n");
        setup_generation(&manager, "example", 2, "#!/bin/sh\nexit 0\n");
        write_configuration(&manager, "example", 1, r#"{"revision":1}"#);
        write_configuration(&manager, "example", 2, r#"{"revision":2}"#);
        AppManager::mark_activated(&manager.generation_dir("example", 1).unwrap(), Some(1))
            .unwrap();
        manager
            .write_configuration_revision("example", Some(2))
            .unwrap();
        manager
            .write_state(
                "example",
                &AppState::Active(AppStateActive::new(1).with_configuration_revision(Some(1))),
            )
            .unwrap();
        let lock = manager.lock_app("example").unwrap();

        activate(&manager, &lock, "example", 2).unwrap();
        assert!(matches!(
            manager.read_state("example").unwrap(),
            AppState::Active(AppStateActive {
                generation: 2,
                configuration_revision: Some(2),
            })
        ));

        manager.rollback(&lock, "example").unwrap();
        assert!(matches!(
            manager.read_state("example").unwrap(),
            AppState::Active(AppStateActive {
                generation: 1,
                configuration_revision: Some(1),
            })
        ));
        assert_eq!(
            manager.read_configuration_revision("example").unwrap(),
            Some(1)
        );
    }

    /// Verifies configuration set while inactive becomes the next activation's
    /// configuration.
    #[test]
    fn inactive_configuration_is_used_during_the_next_activation() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        setup_generation(&manager, "example", 1, "#!/bin/sh\nexit 0\n");
        let lock = manager.lock_app("example").unwrap();
        let configuration = crate::apps::configuration::parse(r#"{"enabled":true}"#).unwrap();

        assert_eq!(
            manager
                .set_configuration(&lock, "example", &configuration)
                .unwrap(),
            1
        );
        assert!(matches!(
            manager.read_state("example").unwrap(),
            AppState::Inactive
        ));

        activate(&manager, &lock, "example", 1).unwrap();
        assert!(matches!(
            manager.read_state("example").unwrap(),
            AppState::Active(AppStateActive {
                generation: 1,
                configuration_revision: Some(1),
            })
        ));
    }

    /// Verifies a generation whose schema rejects the carried-forward document can
    /// still be activated with a document supplied for that generation.
    #[test]
    fn activating_a_generation_with_a_stricter_schema_requires_a_matching_document() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        setup_generation(&manager, "example", 1, "#!/bin/sh\nexit 0\n");
        setup_generation(&manager, "example", 2, "#!/bin/sh\nexit 0\n");
        declare_configuration_schema(
            &manager,
            "example",
            2,
            r#"{"type":"object","required":["endpoint"]}"#,
        );
        write_configuration(&manager, "example", 1, r#"{"url":"https://example.com"}"#);
        manager
            .write_configuration_revision("example", Some(1))
            .unwrap();
        manager
            .write_state(
                "example",
                &AppState::Active(AppStateActive::new(1).with_configuration_revision(Some(1))),
            )
            .unwrap();
        let lock = manager.lock_app("example").unwrap();

        assert!(activate(&manager, &lock, "example", 2).is_err());
        assert!(matches!(
            manager.read_state("example").unwrap(),
            AppState::Active(AppStateActive {
                generation: 1,
                configuration_revision: Some(1),
            })
        ));

        let migrated =
            crate::apps::configuration::parse(r#"{"endpoint":"mqtts://example.com"}"#).unwrap();
        let target = manager
            .prepare_configuration(&lock, "example", 2, Some(&migrated))
            .unwrap();
        assert_eq!(target, AppDeployment::new(2, Some(2)));
        manager
            .activate_deployment(&lock, "example", target)
            .unwrap();

        assert!(matches!(
            manager.read_state("example").unwrap(),
            AppState::Active(AppStateActive {
                generation: 2,
                configuration_revision: Some(2),
            })
        ));
        assert_eq!(
            manager.read_configuration("example").unwrap(),
            Some(migrated)
        );
    }

    /// Verifies re-applying an active document leaves the workload alone while new
    /// content never reuses a collected revision number.
    #[test]
    fn setting_an_identical_configuration_reuses_its_revision() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        setup_generation(
            &manager,
            "example",
            1,
            "#!/bin/sh\n[ \"$1\" = activate ] && echo x >> \"$RUGIX_APP_DATA_DIR/activations\"\nexit 0\n",
        );
        std::fs::create_dir_all(manager.data_dir("example")).unwrap();
        let activations = manager.data_dir("example").join("activations");
        let count = || {
            std::fs::read_to_string(&activations)
                .unwrap_or_default()
                .lines()
                .count()
        };
        let lock = manager.lock_app("example").unwrap();
        let first = crate::apps::configuration::parse(r#"{"enabled":true}"#).unwrap();
        let second = crate::apps::configuration::parse(r#"{"enabled":false}"#).unwrap();

        activate(&manager, &lock, "example", 1).unwrap();
        assert_eq!(count(), 1);
        assert_eq!(
            manager.set_configuration(&lock, "example", &first).unwrap(),
            1
        );
        assert_eq!(count(), 2);
        assert_eq!(
            manager.set_configuration(&lock, "example", &first).unwrap(),
            1
        );
        assert_eq!(count(), 2);
        assert_eq!(
            manager
                .set_configuration(&lock, "example", &second)
                .unwrap(),
            2
        );
        assert_eq!(count(), 3);

        manager.gc(&lock, "example", 1).unwrap();
        assert!(!manager.configuration_path("example", 1).exists());
        assert_eq!(
            manager.set_configuration(&lock, "example", &first).unwrap(),
            3
        );
    }

    /// Verifies configuration changes cannot overwrite lifecycle recovery intent.
    #[test]
    fn configuration_changes_require_a_stable_lifecycle_state() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        setup_generation(&manager, "example", 1, "#!/bin/sh\nexit 0\n");
        manager
            .write_state(
                "example",
                &AppState::Switching(AppStateSwitching::new().with_to(Some(1))),
            )
            .unwrap();
        let lock = manager.lock_app("example").unwrap();
        let configuration = crate::apps::configuration::parse("{}").unwrap();

        assert!(manager
            .set_configuration(&lock, "example", &configuration)
            .is_err());
        assert!(!manager.configurations_dir("example").exists());
    }

    /// Verifies a failed configuration switch restores the last working revision.
    #[test]
    fn failed_configuration_application_restores_the_last_working_revision() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        setup_generation(
            &manager,
            "example",
            1,
            "#!/bin/sh\nif [ \"$1\" = activate ] && grep -q '\"fail\": true' \"$RUGIX_APP_CONFIG_PATH\"; then exit 1; fi\nexit 0\n",
        );
        declare_configuration_schema(
            &manager,
            "example",
            1,
            r#"{"type":"object","properties":{"fail":{"type":"boolean"}},"required":["fail"]}"#,
        );
        manager
            .write_state("example", &AppState::Active(AppStateActive::new(1)))
            .unwrap();
        let lock = manager.lock_app("example").unwrap();

        let working = crate::apps::configuration::parse(r#"{"fail":false}"#).unwrap();
        assert_eq!(
            manager
                .set_configuration(&lock, "example", &working)
                .unwrap(),
            1
        );
        let failing = crate::apps::configuration::parse(r#"{"fail":true}"#).unwrap();
        assert!(manager
            .set_configuration(&lock, "example", &failing)
            .is_err());

        assert!(matches!(
            manager.read_state("example").unwrap(),
            AppState::Active(AppStateActive {
                generation: 1,
                configuration_revision: Some(1),
            })
        ));
        assert_eq!(
            manager.read_configuration("example").unwrap(),
            Some(working.clone())
        );

        manager.gc(&lock, "example", 1).unwrap();
        assert!(!manager.configuration_path("example", 2).exists());
    }

    #[test]
    fn garbage_collection_preserves_current_and_recent_rollback_generation() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        for generation in 1..=4 {
            setup_generation(&manager, "example", generation, "#!/bin/sh\nexit 0\n");
        }
        for generation in 1..=3 {
            AppManager::mark_activated(
                &manager.generation_dir("example", generation).unwrap(),
                None,
            )
            .unwrap();
        }
        manager
            .write_state("example", &AppState::Active(AppStateActive::new(3)))
            .unwrap();

        let lock = manager.lock_app("example").unwrap();
        assert_eq!(manager.gc(&lock, "example", 1).unwrap(), vec![1, 4]);
        assert!(manager.generation_dir("example", 2).unwrap().exists());
        assert!(manager.generation_dir("example", 3).unwrap().exists());
    }

    /// Verifies garbage collection retains only revisions required for rollback.
    #[test]
    fn garbage_collection_preserves_only_configuration_revisions_needed_for_rollback() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        for generation in 1..=2 {
            setup_generation(&manager, "example", generation, "#!/bin/sh\nexit 0\n");
        }
        for (generation, revision) in [(1, 1), (2, 2)] {
            AppManager::mark_activated(
                &manager.generation_dir("example", generation).unwrap(),
                Some(revision),
            )
            .unwrap();
        }
        let configurations_dir = manager.configurations_dir("example");
        std::fs::create_dir_all(&configurations_dir).unwrap();
        for revision in 1..=3 {
            std::fs::write(
                manager.configuration_path("example", revision),
                format!("{{\"revision\":{revision}}}"),
            )
            .unwrap();
        }
        manager
            .write_configuration_revision("example", Some(2))
            .unwrap();
        manager
            .write_state(
                "example",
                &AppState::Active(AppStateActive::new(2).with_configuration_revision(Some(2))),
            )
            .unwrap();

        let lock = manager.lock_app("example").unwrap();
        manager.gc(&lock, "example", 1).unwrap();

        assert!(manager.configuration_path("example", 1).exists());
        assert!(manager.configuration_path("example", 2).exists());
        assert!(!manager.configuration_path("example", 3).exists());

        assert_eq!(manager.gc(&lock, "example", 0).unwrap(), vec![1]);
        assert!(!manager.configuration_path("example", 1).exists());
        assert!(manager.configuration_path("example", 2).exists());
    }

    /// Verifies GC preserves both sides of interrupted and failed lifecycle switches.
    #[test]
    fn garbage_collection_preserves_recovery_deployments() {
        let tempdir = tempfile::tempdir().unwrap();
        let manager = AppManager::new(tempdir.path().join("apps"), AppsConfig::new());
        for (app, state) in [
            (
                "switching",
                AppState::Switching(
                    AppStateSwitching::new()
                        .with_from(Some(1))
                        .with_from_configuration_revision(Some(1))
                        .with_to(Some(2))
                        .with_to_configuration_revision(Some(2)),
                ),
            ),
            (
                "error",
                AppState::Error(
                    AppStateError::new(2, "activation and rollback failed".to_owned())
                        .with_from(Some(1))
                        .with_from_configuration_revision(Some(1))
                        .with_to_configuration_revision(Some(2)),
                ),
            ),
        ] {
            for generation in 1..=3 {
                setup_generation(&manager, app, generation, "#!/bin/sh\nexit 0\n");
                write_configuration(
                    &manager,
                    app,
                    generation,
                    &format!(r#"{{"revision":{generation}}}"#),
                );
            }
            AppManager::mark_activated(&manager.generation_dir(app, 1).unwrap(), Some(1)).unwrap();
            manager.write_configuration_revision(app, Some(1)).unwrap();
            manager.write_state(app, &state).unwrap();

            let lock = manager.lock_app(app).unwrap();
            assert_eq!(manager.gc(&lock, app, 0).unwrap(), vec![3]);
            assert!(manager.generation_dir(app, 1).unwrap().exists());
            assert!(manager.generation_dir(app, 2).unwrap().exists());
            assert!(manager.configuration_path(app, 1).exists());
            assert!(manager.configuration_path(app, 2).exists());
            assert!(!manager.configuration_path(app, 3).exists());
        }
    }

    #[test]
    fn synchronization_failure_prevents_generation_completion() {
        let completed = std::cell::Cell::new(false);
        let result = finalize_generation_with(
            || -> super::AppsResult<()> { reportify::bail!("injected synchronization failure") },
            || {
                completed.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!completed.get());
    }
}
