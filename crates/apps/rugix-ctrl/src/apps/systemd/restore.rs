//! Restore app systemd units after reboot.

use std::fs;
use std::path::Path;

use reportify::ResultExt;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::apps::manager::AppManager;
use crate::apps::AppsResult;

/// Restore all persisted app units into the systemd runtime directory.
pub fn restore_units(manager: &AppManager) -> AppsResult<()> {
    let apps = manager.list_apps()?;
    if apps.is_empty() {
        info!("no apps, nothing to restore");
        return Ok(());
    }
    let mut restored_units = Vec::new();
    let mut failures = Vec::new();
    for app_name in &apps {
        if let Err(err) = restore_app_units(manager, app_name, &mut restored_units) {
            error!(app = app_name, error = ?err, "failed to restore units");
            failures.push(format!("app {app_name:?}: {err:?}"));
        }
    }
    if !restored_units.is_empty() {
        super::daemon_reload()?;
        info!(
            count = restored_units.len(),
            "daemon-reload after restoring app units"
        );
        // For each restored unit:
        //
        // 1. `enable --runtime` to track `is-enabled` state.
        // 2. `start --no-block` queues a start job and returns immediately.
        //
        // Note that `enable` alone doesn't actually queue and start the unit.
        for unit in &restored_units {
            if let Err(err) = super::enable_runtime(unit) {
                error!(unit, error = ?err, "failed to enable restored app unit");
                failures.push(format!("unit {unit:?} enable: {err:?}"));
                continue;
            }
            if let Err(err) = super::start_no_block(unit) {
                error!(unit, error = ?err, "failed to queue start for restored app unit");
                failures.push(format!("unit {unit:?} start: {err:?}"));
            } else {
                info!(unit, "queued start for restored app unit");
            }
        }
    }
    if !failures.is_empty() {
        reportify::bail!(
            "one or more app units could not be restored:\n{}",
            failures.join("\n")
        );
    }
    Ok(())
}

/// Restore persisted units of the given app.
fn restore_app_units(
    manager: &AppManager,
    app_name: &str,
    restored_units: &mut Vec<String>,
) -> AppsResult<()> {
    // We only restore units of apps who have a current active generation.
    let Some(generation) = manager.current_generation(app_name)? else {
        debug!(app = app_name, "app has no active generation");
        return Ok(());
    };
    let units_dir = manager
        .generation_dir(app_name, generation)
        .whatever("invalid app name")?
        .join(".rugix/systemd/units");
    if !units_dir.is_dir() {
        debug!(app = app_name, "app has no persisted systemd units");
        return Ok(());
    }
    let runtime_dir = Path::new(super::RUNTIME_UNITS_DIR);
    let entries = fs::read_dir(units_dir).whatever("unable to read units directory")?;
    for entry in entries {
        let entry = entry.whatever("unable to read unit entry")?;
        let unit_path = entry.path();
        let Some(file_name) = unit_path.file_name() else {
            continue;
        };
        let dest = runtime_dir.join(file_name);
        fs::copy(&unit_path, &dest).whatever("unable to copy unit file")?;
        if let Some(name) = file_name.to_str() {
            restored_units.push(name.to_owned());
        } else {
            warn!(app = app_name, unit = ?file_name, "invalid characters in unit name");
        }
        info!(app = app_name, unit = ?file_name, "restored app unit");
    }
    Ok(())
}
