//! Daemon configuration loading and defaults.

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use reportify::bail;
use reportify::ResultExt;

use crate::config::daemon::DaemonConfig;
use crate::config::daemon::DaemonFeatureInfo;
use crate::config::daemon::DaemonInfo;
use crate::system::SystemResult;

const DAEMON_CONFIG_PATH: &str = "/etc/rugix/daemon.toml";
const DEFAULT_SOCKET_PATH: &str = "/run/rugix/ctrl.sock";
const DEFAULT_MAX_CONTROL_FRAME_SIZE: u64 = 8 * 1024 * 1024;

/// Resolved configuration used by daemon clients and the server.
#[derive(Debug, Clone)]
pub(crate) struct DaemonSettings {
    pub(crate) socket_path: PathBuf,
    pub(crate) max_control_frame_size: usize,
    pub(crate) dangerously_insecure: bool,
    pub(crate) features: DaemonFeatureSettings,
}

/// Additional privileged operation families exposed by the daemon.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DaemonFeatureSettings {
    pub(crate) factory_reset: bool,
    pub(crate) system_commit: bool,
    pub(crate) system_reboot: bool,
    pub(crate) app_lifecycle: bool,
}

impl DaemonSettings {
    pub(crate) fn info(&self) -> DaemonInfo {
        DaemonInfo::new(
            self.dangerously_insecure,
            DaemonFeatureInfo::new(
                self.features.factory_reset,
                self.features.system_commit,
                self.features.system_reboot,
                self.features.app_lifecycle,
            ),
        )
    }
}

pub(crate) fn load_daemon_settings() -> SystemResult<DaemonSettings> {
    load_daemon_settings_from(Path::new(DAEMON_CONFIG_PATH))
}

fn load_daemon_settings_from(path: &Path) -> SystemResult<DaemonSettings> {
    let config = match fs::read_to_string(path) {
        Ok(contents) => toml::from_str(&contents)
            .whatever("unable to parse daemon configuration")
            .field("path", path.to_owned())?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => DaemonConfig::default(),
        Err(error) => {
            return Err(error)
                .whatever("unable to read daemon configuration")
                .field("path", path.to_owned());
        }
    };
    resolve_daemon_settings(config)
}

fn resolve_daemon_settings(config: DaemonConfig) -> SystemResult<DaemonSettings> {
    let max_control_frame_size = config
        .max_control_frame_size
        .unwrap_or(DEFAULT_MAX_CONTROL_FRAME_SIZE);
    if max_control_frame_size == 0 {
        bail!("daemon maximum control frame size must be greater than zero");
    }
    let max_control_frame_size = usize::try_from(max_control_frame_size)
        .whatever("daemon maximum control frame size does not fit this platform")?;
    let features = config.features.unwrap_or_default();
    Ok(DaemonSettings {
        socket_path: config
            .socket_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH)),
        max_control_frame_size,
        dangerously_insecure: config.dangerously_insecure.unwrap_or(false),
        features: DaemonFeatureSettings {
            factory_reset: features.factory_reset.unwrap_or(false),
            system_commit: features.system_commit.unwrap_or(false),
            system_reboot: features.system_reboot.unwrap_or(false),
            app_lifecycle: features.app_lifecycle.unwrap_or(false),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_daemon_settings;
    use crate::config::daemon::DaemonConfig;

    #[test]
    fn privileged_features_and_insecure_options_are_disabled_by_default() {
        let settings = resolve_daemon_settings(DaemonConfig::default()).unwrap();

        assert!(!settings.dangerously_insecure);
        assert!(!settings.features.factory_reset);
        assert!(!settings.features.system_commit);
        assert!(!settings.features.system_reboot);
        assert!(!settings.features.app_lifecycle);
    }

    #[test]
    fn parses_explicit_daemon_capabilities() {
        let config = toml::from_str(
            r#"
                socket-path = "/tmp/rugix.sock"
                max-control-frame-size = 4096
                dangerously-insecure = true

                [features]
                factory-reset = true
                system-commit = true
                system-reboot = true
                app-lifecycle = true
            "#,
        )
        .unwrap();
        let settings = resolve_daemon_settings(config).unwrap();

        assert_eq!(settings.socket_path.to_string_lossy(), "/tmp/rugix.sock");
        assert_eq!(settings.max_control_frame_size, 4096);
        assert!(settings.dangerously_insecure);
        assert!(settings.features.factory_reset);
        assert!(settings.features.system_commit);
        assert!(settings.features.system_reboot);
        assert!(settings.features.app_lifecycle);
    }
}
