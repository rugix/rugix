use std::fs;
use std::path::Path;
use std::path::PathBuf;

use reportify::ResultExt;

pub use crate::config::apps::AppsConfig;

use super::AppsResult;

/// Apps config path.
const APPS_CONFIG_PATH: &str = "/etc/rugix/apps.toml";

/// Load the apps configuration from `/etc/rugix/apps.toml`.
///
/// Returns default values if the file does not exist.
pub fn load_apps_config() -> AppsResult<AppsConfig> {
    let path = Path::new(APPS_CONFIG_PATH);
    if !path.exists() {
        return Ok(AppsConfig::default());
    }
    let content = fs::read_to_string(path).whatever("unable to read apps config")?;
    toml::from_str(&content).whatever("unable to parse apps config")
}

/// Get the effective service manager name.
///
/// If explicitly configured, use that value. Otherwise, attempt auto-detection
/// by checking for well-known init system indicators. Falls back to `"none"`.
pub fn effective_service_manager(config: &AppsConfig) -> String {
    if let Some(sm) = config.service_manager.as_deref() {
        return sm.to_owned();
    }
    detect_service_manager()
}

/// Auto-detect the service manager by probing the system.
fn detect_service_manager() -> String {
    // systemd: check for the runtime directory it always creates.
    if Path::new(super::systemd::RUNTIME_UNITS_DIR).is_dir() {
        return "systemd".to_owned();
    }
    "none".to_owned()
}

/// Root directory for app data, below the [state directory](crate::state::state_dir).
pub fn apps_dir() -> PathBuf {
    crate::state::state_dir().join("apps")
}
