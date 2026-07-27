use std::fs;
use std::path::Path;

use reportify::ResultExt;
use tracing::warn;

use crate::config::state::StateConfig;
use crate::system::SystemResult;
use crate::utils::clear_flag;
use crate::utils::set_flag_data;

/// The default directory with the configurations for state management.
pub const STATE_CONFIG_DIR: &str = "/etc/rugix/state";
pub const STATE_CONFIG_PATH: &str = "/etc/rugix/state.toml";
const STATE_RUNTIME_DIR: &str = "/run/rugix/state/.rugix";

/// Loads the state configuration from the provided directory.
pub fn load_state_config() -> SystemResult<StateConfig> {
    let mut combined = StateConfig::new();

    if let Ok(state) = fs::read_to_string(STATE_CONFIG_PATH) {
        merge(
            &mut combined,
            toml::from_str(&state).whatever("unable to load state config")?,
        );
    }

    if let Ok(read_dir) = fs::read_dir(STATE_CONFIG_DIR) {
        for entry in read_dir {
            if let Some(config) = entry
                .ok()
                .and_then(|entry| fs::read_to_string(entry.path()).ok())
                .and_then(|config| toml::from_str(&config).ok())
            {
                merge(&mut combined, config);
            }
        }
    }
    Ok(combined)
}

pub(crate) fn create_state_runtime_directory() -> SystemResult<()> {
    fs::create_dir_all(STATE_RUNTIME_DIR).whatever("unable to create Rugix state runtime directory")
}

pub(crate) fn set_state_flag(name: &str, value: Option<&str>) -> SystemResult<()> {
    set_flag_data(
        Path::new(STATE_RUNTIME_DIR).join(name),
        value.unwrap_or_default().as_bytes(),
    )
    .whatever("unable to write state flag")
    .field("name", name.to_owned())
}

pub(crate) fn clear_state_flag(name: &str) -> SystemResult<()> {
    clear_flag(Path::new(STATE_RUNTIME_DIR).join(name))
        .whatever("unable to clear state flag")
        .field("name", name.to_owned())
}

fn merge(target: &mut StateConfig, other: StateConfig) {
    if target.overlay.is_none() {
        target.overlay = other.overlay;
    } else if other.overlay.is_some() {
        warn!("Conflicting overlay options. Will use {:?}", target.overlay);
    }
    if target.overlay_fallback.is_none() {
        target.overlay_fallback = other.overlay_fallback;
    } else if other.overlay_fallback.is_some() {
        warn!(
            "Conflicting overlay fallback options. Will use {:?}",
            target.overlay_fallback
        );
    }
    if let Some(persist) = &mut target.persist {
        if let Some(other) = other.persist {
            persist.extend(other);
        }
    } else {
        target.persist = other.persist;
    }
}
