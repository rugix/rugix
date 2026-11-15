//! Loading and validation of app manifests (`app.toml`).
//!
//! [`load`] reads the manifest of a generation for lifecycle operations. [`validate`]
//! checks a newly installed generation before Rugix Ctrl marks it complete, so that a
//! generation it cannot activate is never installed. Both reject manifests with a
//! format version that this Rugix Ctrl does not support.

use std::fs;
use std::path::Path;

use reportify::bail;
use reportify::ResultExt;
use rugix_bundle::manifest::AppManifest;
use rugix_bundle::manifest::APP_MANIFEST_FORMAT_VERSION;
use tracing::warn;

use super::configuration;
use super::orchestrators;
use super::AppsResult;

/// Path of the app manifest relative to a generation directory.
const MANIFEST_PATH: &str = "app.toml";

/// Load the manifest of a generation.
pub fn load(generation_dir: &Path) -> AppsResult<AppManifest> {
    Ok(parse(generation_dir)?.0)
}

/// Check that a newly installed generation can be activated.
///
/// Requires a supported manifest with a known orchestrator and a default configuration
/// that matches the configuration schema. Warns about manifest fields unknown to this
/// Rugix Ctrl.
#[tracing::instrument(level = "debug")]
pub fn validate(generation_dir: &Path) -> AppsResult<()> {
    let (manifest, unknown_fields) = parse(generation_dir)?;
    if !unknown_fields.is_empty() {
        warn!(fields = ?unknown_fields, "unknown fields in app.toml");
    }
    orchestrators::get(&manifest.orchestrator)?;
    configuration::load_effective(generation_dir, &manifest, None, None)?;
    Ok(())
}

/// Parse the manifest of a generation and return it with the paths of unknown fields.
fn parse(generation_dir: &Path) -> AppsResult<(AppManifest, Vec<String>)> {
    let content = fs::read_to_string(generation_dir.join(MANIFEST_PATH))
        .whatever("unable to read app.toml")?;
    let (manifest, unknown_fields) =
        sidex::formats::toml::from_str_with_unknown::<AppManifest>(&content)
            .whatever("unable to parse app.toml")?;
    let version = manifest.format_version.unwrap_or(1);
    if !(1..=APP_MANIFEST_FORMAT_VERSION).contains(&version) {
        bail!(
            "app.toml has format version {version}, which this Rugix Ctrl does not support \
             (supported: 1 to {APP_MANIFEST_FORMAT_VERSION})"
        );
    }
    Ok((
        manifest,
        unknown_fields.iter().map(ToString::to_string).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::load;
    use super::validate;

    fn generation_with_manifest(manifest: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("app.toml"), manifest).unwrap();
        dir
    }

    /// Verifies that manifests without a format version and with a supported one load.
    #[test]
    fn supported_format_versions_load() {
        for manifest in [
            "orchestrator = \"generic\"\n",
            "format-version = 1\norchestrator = \"generic\"\n",
        ] {
            let generation = generation_with_manifest(manifest);
            assert_eq!(&*load(generation.path()).unwrap().orchestrator, "generic");
        }
    }

    /// Verifies that manifests with an unsupported format version are rejected.
    #[test]
    fn unsupported_format_versions_are_rejected() {
        for version in [0, 2] {
            let generation = generation_with_manifest(&format!(
                "format-version = {version}\norchestrator = \"generic\"\n"
            ));
            let error = load(generation.path()).unwrap_err();
            assert!(format!("{error:?}").contains("format version"), "{error:?}");
        }
    }

    /// Verifies that installation rejects generations Rugix Ctrl cannot activate.
    #[test]
    fn validation_rejects_generations_that_cannot_be_activated() {
        let unknown_orchestrator = generation_with_manifest("orchestrator = \"unknown\"\n");
        assert!(validate(unknown_orchestrator.path()).is_err());

        let missing_manifest = tempfile::tempdir().unwrap();
        assert!(validate(missing_manifest.path()).is_err());

        let invalid_default = generation_with_manifest(
            "orchestrator = \"generic\"\n\n[configuration]\nschema = \"schema.json\"\ndefault = \"default.json\"\n",
        );
        fs::write(
            invalid_default.path().join("schema.json"),
            r#"{"type": "object", "required": ["port"]}"#,
        )
        .unwrap();
        fs::write(invalid_default.path().join("default.json"), "{}").unwrap();
        assert!(validate(invalid_default.path()).is_err());

        let valid = generation_with_manifest("orchestrator = \"generic\"\nunknown-field = true\n");
        validate(valid.path()).unwrap();
    }
}
