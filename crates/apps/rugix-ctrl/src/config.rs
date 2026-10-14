//! Sidex configuration types and Rugix Ctrl configuration loading.

use std::fs;
use std::path::Path;

use reportify::ResultExt;

use crate::system::SystemResult;

sidex::include_bundle! {
    #[allow(clippy::redundant_static_lifetimes, clippy::empty_docs)]
    rugix_ctrl as generated
}

// Re-export the generated data structures.
pub use generated::*;

/// Ctrl config path.
const CTRL_CONFIG_PATH: &str = "/etc/rugix/ctrl.toml";

pub fn load_ctrl_config() -> SystemResult<config::Config> {
    Ok(if Path::new(CTRL_CONFIG_PATH).exists() {
        toml::from_str(
            &fs::read_to_string(CTRL_CONFIG_PATH).whatever("unable to read configuration file")?,
        )
        .whatever("unable to parse configuration file")?
    } else {
        config::Config::default()
    })
}

#[cfg(test)]
mod tests {
    use super::bootstrapping::BootstrappingConfig;
    use super::bootstrapping::SystemLayoutConfig;

    /// Existing byte-size strings and integers load through both Sidex readers.
    #[test]
    fn bootstrapping_sizes_load_in_toml_and_json() {
        for (toml, json) in [
            (
                r#"[layout]
type = "default"
system-size = "4GiB"
"#,
                r#"{"layout":{"type":"default","system-size":"4GiB"}}"#,
            ),
            (
                "[layout]\ntype = \"default\"\nsystem-size = 4294967296",
                r#"{"layout":{"type":"default","system-size":4294967296}}"#,
            ),
        ] {
            let configs = [
                sidex::formats::toml::from_str::<BootstrappingConfig>(toml).unwrap(),
                sidex::formats::json::from_str::<BootstrappingConfig>(json).unwrap(),
            ];
            for config in configs {
                let Some(SystemLayoutConfig::Default(layout)) = config.layout else {
                    panic!("expected default layout");
                };
                assert_eq!(layout.system_size.0, byte_calc::NumBytes::new(4 << 30));
            }
        }
    }

    /// Unknown fields in a tagged configuration retain their full paths.
    #[test]
    fn bootstrapping_unknown_fields_are_reported() {
        let (_, toml_unknown) = sidex::formats::toml::from_str_with_unknown::<BootstrappingConfig>(
            "[layout]\ntype = \"default\"\nsystem-size = 4294967296\nsystem-szie = 1",
        )
        .unwrap();
        let (_, json_unknown) = sidex::formats::json::from_str_with_unknown::<BootstrappingConfig>(
            r#"{"layout":{"type":"default","system-size":4294967296,"system-szie":1}}"#,
        )
        .unwrap();
        for unknown in [toml_unknown, json_unknown] {
            assert_eq!(
                unknown.iter().map(ToString::to_string).collect::<Vec<_>>(),
                ["layout.system-szie"]
            );
        }
    }
}
