//! System configuration.

use std::fs;
use std::path::Path;

use reportify::bail;
use reportify::ResultExt;

use crate::config::system::PartitionConfig;
use crate::config::system::SystemConfig;

use super::SystemResult;

/// Path of the system configuration file.
pub const SYSTEM_CONFIG_PATH: &str = "/etc/rugix/system.toml";

/// Load and validate the system configuration.
pub fn load_system_config() -> SystemResult<SystemConfig> {
    let config = if Path::new(SYSTEM_CONFIG_PATH).exists() {
        toml::from_str::<SystemConfig>(
            &fs::read_to_string(SYSTEM_CONFIG_PATH)
                .whatever("unable to read system configuration file")?,
        )
        .whatever("unable to parse system configuration file")?
    } else {
        SystemConfig::default()
    };
    validate(&config)?;
    Ok(config)
}

/// Cross-field consistency checks that JSON Schema cannot express.
fn validate(config: &SystemConfig) -> SystemResult<()> {
    if let Some(partition) = &config.config_partition {
        if partition.driver.is_some() {
            bail!(
                "config-partition.driver is not supported: drivers are only valid \
                 on the data partition"
            );
        }
    }
    if let Some(partition) = &config.data_partition {
        validate_data_partition(partition)?;
    }
    Ok(())
}

fn validate_data_partition(partition: &PartitionConfig) -> SystemResult<()> {
    if partition.driver.is_some() && partition.mount_script.is_some() {
        bail!(
            "data-partition: `driver` and `mount-script` are mutually exclusive — \
             pick one (use `driver = {{ type = \"custom\", mount-script = \"...\" }}` \
             when migrating an existing `mount-script`)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::validate;
    use super::SystemConfig;

    #[test]
    fn test_from_toml() {
        toml::from_str::<SystemConfig>(indoc! {r#"
            [config-partition]
            disabled = false
            device = "/dev/sda1"

            [data-partition]
            disabled = false
            partition = 7

            [boot-flow]
            type = "rpi-uboot"

            [slots.boot-a]
            type = "block"
            partition = 2

            [slots.boot-b]
            type = "block"
            device = "/dev/sda3"

            [slots.system-a]
            type = "block"
            device = "/dev/sda4"

            [slots.system-b]
            type = "block"
            device = "/dev/sda5"

            [slots.app-config]
            type = "block"
            device = "/dev/sda6"
            protected = true

            [boot-groups.a]
            slots = { boot = "boot-a", system = "system-a" }

            [boot-groups.b]
            slots = { boot = "boot-b", system = "system-b" }
        "#})
        .unwrap();
    }

    #[test]
    fn data_mount_failure_policy_uses_kebab_case_and_defaults_to_false() {
        let config = toml::from_str::<SystemConfig>(indoc! {r#"
            [data-partition]
            fail-on-mount-error = true
        "#})
        .unwrap();
        assert_eq!(
            config.data_partition.unwrap().fail_on_mount_error,
            Some(true)
        );

        let default = toml::from_str::<SystemConfig>("[data-partition]").unwrap();
        assert!(!default
            .data_partition
            .unwrap()
            .fail_on_mount_error
            .unwrap_or(false));
    }

    #[test]
    fn test_driver_and_mount_script_are_mutually_exclusive() {
        let config: SystemConfig = toml::from_str(indoc! {r#"
            [data-partition]
            mount-script = "/usr/lib/example/mount"

            [data-partition.driver]
            type = "plaintext-ext4"
        "#})
        .unwrap();
        let err = validate(&config).expect_err("validation should reject the conflict");
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("mutually exclusive"),
            "expected mutual-exclusion error, got: {rendered}"
        );
    }

    #[test]
    fn test_driver_rejected_on_config_partition() {
        let config: SystemConfig = toml::from_str(indoc! {r#"
            [config-partition.driver]
            type = "plaintext-ext4"
        "#})
        .unwrap();
        let err = validate(&config).expect_err("validation should reject config-partition driver");
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("config-partition"),
            "expected config-partition error, got: {rendered}"
        );
    }

    #[test]
    fn test_luks2_passphrase_round_trips() {
        let config: SystemConfig = toml::from_str(indoc! {r#"
            [data-partition.driver]
            type = "luks2-passphrase"
            passphrase-file = "/run/rugix/mounts/config/.rugix/data.key"
            label = "data"
        "#})
        .unwrap();
        validate(&config).unwrap();
        // Round-trip through serialization to make sure `kebab-case` survives.
        let serialised = toml::to_string(&config).unwrap();
        assert!(serialised.contains("type = \"luks2-passphrase\""));
        assert!(serialised.contains("passphrase-file"));
    }
}
