sidex::include_bundle! {
    #[allow(
        clippy::redundant_static_lifetimes,
        clippy::empty_docs,
        clippy::manual_unwrap_or_default,
        clippy::match_single_binding
    )]
    rugix_bundle as generated
}

pub use generated::manifest::*;

use crate::BundleResult;
use reportify::ResultExt;
use rugix_common::path::ValidatedRelativePath;

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
pub fn validate_manifest_paths(manifest: &BundleManifest) -> BundleResult<()> {
    for (payload_idx, payload) in manifest.payloads.iter().enumerate() {
        ValidatedRelativePath::new(payload.filename.clone())
            .whatever_with(|_| format!("invalid filename for payload {payload_idx}"))?;
        match &payload.delivery {
            DeliveryConfig::AppFile(config) => {
                validate_app_name(&config.app)
                    .whatever_with(|_| format!("invalid app name for payload {payload_idx}"))?;
                ValidatedRelativePath::new(config.path.clone()).whatever_with(|_| {
                    format!("invalid app-file path for payload {payload_idx}")
                })?;
            }
            DeliveryConfig::AppArchive(config) => {
                validate_app_name(&config.app)
                    .whatever_with(|_| format!("invalid app name for payload {payload_idx}"))?;
            }
            DeliveryConfig::Slot(_) | DeliveryConfig::Execute(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
