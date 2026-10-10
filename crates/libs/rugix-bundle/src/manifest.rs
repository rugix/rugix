//! Bundle manifest types, Compose image contracts, and manifest validation.
//!
//! Reexports the generated manifest types and [`compose`] image options and metadata.
//! [`validate_manifest_paths`] checks manifest paths and app names before use.

use crate::BundleResult;
use reportify::ResultExt;
use rugix_common::path::ValidatedRelativePath;

sidex::include_bundle! {
    #[allow(
        clippy::redundant_static_lifetimes,
        clippy::empty_docs,
        clippy::manual_unwrap_or_default,
        clippy::match_single_binding
    )]
    rugix_bundle as generated
}

pub use generated::compose;
pub use generated::manifest::*;

/// Check whether a string is an RFC 6901 JSON Pointer.
pub fn is_valid_json_pointer(pointer: &str) -> bool {
    if pointer.is_empty() {
        return true;
    }
    if !pointer.starts_with('/') {
        return false;
    }
    let mut characters = pointer.chars();
    while let Some(character) = characters.next() {
        if character == '~' && !matches!(characters.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

/// Check whether a string is a portable, non-reserved environment variable name.
pub fn is_valid_environment_variable_name(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
        && !name.starts_with("RUGIX_")
}
/// Validate that an app name is safe for use in file paths, systemd unit names, and
/// Docker project names.
///
/// Allowed characters: ASCII lowercase letters, digits, hyphens, and underscores.
///
/// Names must not be empty, must not start with a hyphen or digit.
pub fn validate_app_name(name: &str) -> BundleResult<()> {
    if name.is_empty() {
        reportify::bail!("app name must not be empty");
    }
    if name.starts_with('-') {
        reportify::bail!("app name must not start with a hyphen: {name:?}");
    }
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        reportify::bail!("app name must not start with a digit: {name:?}");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        reportify::bail!(
            "app name contains invalid characters (allowed: a-z, 0-9, hyphen, underscore): {name:?}"
        );
    }
    Ok(())
}

/// Validate every path and app name declared by a bundle manifest.
///
/// App payloads must all name the same app. Rugix Ctrl installs an app bundle as one
/// generation of one app, so a manifest naming several apps has no valid installation.
pub fn validate_manifest_paths(manifest: &BundleManifest) -> BundleResult<()> {
    let mut declared_app: Option<&str> = None;
    for (payload_idx, payload) in manifest.payloads.iter().enumerate() {
        ValidatedRelativePath::new(payload.filename.clone())
            .whatever_with(|_| format!("invalid filename for payload {payload_idx}"))?;
        let app = match &payload.delivery {
            DeliveryConfig::AppFile(config) => {
                validate_app_name(&config.app)
                    .whatever_with(|_| format!("invalid app name for payload {payload_idx}"))?;
                ValidatedRelativePath::new(config.path.clone()).whatever_with(|_| {
                    format!("invalid app-file path for payload {payload_idx}")
                })?;
                config.app.as_str()
            }
            DeliveryConfig::AppArchive(config) => {
                validate_app_name(&config.app)
                    .whatever_with(|_| format!("invalid app name for payload {payload_idx}"))?;
                config.app.as_str()
            }
            DeliveryConfig::Slot(_) | DeliveryConfig::Execute(_) => continue,
        };
        match declared_app {
            Some(declared) if declared != app => reportify::bail!(
                "bundle declares app payloads for more than one app ({declared:?} and {app:?}); \
                 pack one bundle per app"
            ),
            _ => declared_app = Some(app),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AppArchiveDeliveryConfig;
    use super::AppFileDeliveryConfig;
    use super::BundleManifest;
    use super::DeliveryConfig;
    use super::Payload;
    use super::SlotDeliveryConfig;
    use super::UpdateType;
    use super::validate_manifest_paths;

    fn slot_payload(filename: &str) -> Payload {
        Payload::new(
            DeliveryConfig::Slot(SlotDeliveryConfig::new("system".to_owned())),
            filename.to_owned(),
        )
    }

    #[test]
    fn manifest_payload_paths_are_confined() {
        let valid = BundleManifest::new(UpdateType::Full, vec![slot_payload("system.img")]);
        assert!(validate_manifest_paths(&valid).is_ok());

        for filename in ["../outside", "/absolute", "directory/./file", "C:\\file"] {
            let manifest = BundleManifest::new(UpdateType::Full, vec![slot_payload(filename)]);
            assert!(validate_manifest_paths(&manifest).is_err(), "{filename:?}");
        }

        let app_file = Payload::new(
            DeliveryConfig::AppFile(AppFileDeliveryConfig::new(
                "example".to_owned(),
                "../outside".to_owned(),
            )),
            "payload".to_owned(),
        );
        assert!(
            validate_manifest_paths(&BundleManifest::new(UpdateType::Full, vec![app_file]))
                .is_err()
        );
    }

    /// Verifies a bundle may only carry app payloads for a single app.
    #[test]
    fn manifest_app_payloads_for_several_apps_are_rejected() {
        let archive = |app: &str| {
            Payload::new(
                DeliveryConfig::AppArchive(AppArchiveDeliveryConfig::new(app.to_owned())),
                format!("{app}.tar"),
            )
        };

        let single = BundleManifest::new(
            UpdateType::Full,
            vec![archive("example"), archive("example")],
        );
        assert!(validate_manifest_paths(&single).is_ok());

        let several =
            BundleManifest::new(UpdateType::Full, vec![archive("first"), archive("second")]);
        let error = validate_manifest_paths(&several).unwrap_err();
        assert!(format!("{error:?}").contains("more than one app"));

        // Slot payloads alongside an app payload are rejected on the device rather
        // than here, so they must not interfere with the single-app rule.
        let mixed = BundleManifest::new(
            UpdateType::Full,
            vec![slot_payload("system.img"), archive("example")],
        );
        assert!(validate_manifest_paths(&mixed).is_ok());
    }
}
