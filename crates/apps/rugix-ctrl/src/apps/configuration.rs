//! Loading and validation for per-application JSON configuration.
//!
//! App configuration is stored independently from app generations. A generation may
//! provide a JSON Schema and a default document through its app manifest.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use reportify::ResultExt;
use rugix_bundle::manifest::AppManifest;
use rugix_common::path::ValidatedRelativePath;
use serde::Deserialize;
use serde::Serialize;

use super::AppsResult;

/// An arbitrary JSON document used to configure an application.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct AppConfiguration(serde_json::Value);

impl AppConfiguration {
    /// Borrow the underlying JSON representation for schema validation.
    pub(crate) fn as_json(&self) -> &serde_json::Value {
        &self.0
    }

    /// Resolve an RFC 6901 JSON Pointer within this configuration.
    pub(crate) fn pointer(&self, pointer: &str) -> Option<&serde_json::Value> {
        self.0.pointer(pointer)
    }
}

/// Effective configuration resolved for an app generation.
pub struct EffectiveConfiguration {
    /// Device-specific configuration revision, if one is active.
    pub revision: Option<u64>,
    /// Path to the effective JSON document, if one exists.
    pub path: Option<PathBuf>,
    /// Parsed effective JSON document, if one exists.
    pub value: Option<AppConfiguration>,
}

/// Load and validate the effective configuration for an app generation.
pub fn load_effective(
    generation_dir: &Path,
    manifest: &AppManifest,
    revision: Option<u64>,
    revision_path: Option<PathBuf>,
) -> AppsResult<EffectiveConfiguration> {
    let path = match revision_path {
        Some(path) => Some(path),
        None => manifest
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.default.as_deref())
            .map(|path| generation_path(generation_dir, path, "configuration default"))
            .transpose()?,
    };
    let value = path
        .as_deref()
        .map(|path| load_json(path, "application configuration"))
        .transpose()?;
    if let Some(value) = &value {
        validate(generation_dir, manifest, value)?;
    }
    Ok(EffectiveConfiguration {
        revision,
        path,
        value,
    })
}

/// Load the optional JSON Schema declared by an app generation.
pub fn load_schema(
    generation_dir: &Path,
    manifest: &AppManifest,
) -> AppsResult<Option<AppConfiguration>> {
    manifest
        .configuration
        .as_ref()
        .and_then(|configuration| configuration.schema.as_deref())
        .map(|path| generation_path(generation_dir, path, "configuration schema"))
        .transpose()?
        .as_deref()
        .map(|path| load_json(path, "application configuration schema"))
        .transpose()
}

/// Validate a configuration document against a generation's optional JSON Schema.
pub fn validate(
    generation_dir: &Path,
    manifest: &AppManifest,
    value: &AppConfiguration,
) -> AppsResult<()> {
    let Some(schema) = load_schema(generation_dir, manifest)? else {
        return Ok(());
    };
    let validator = jsonschema::draft7::options()
        .should_validate_formats(true)
        .build(schema.as_json())
        .map_err(|error| {
            reportify::whatever!("invalid application configuration schema: {error}")
        })?;
    if let Err(error) = validator.validate(value.as_json()) {
        let location = error.instance_path().to_string();
        if location.is_empty() {
            reportify::bail!("application configuration does not match its schema");
        }
        reportify::bail!("application configuration at {location} does not match its schema");
    }
    Ok(())
}

/// Parse an application configuration JSON document.
pub fn parse(content: &str) -> AppsResult<AppConfiguration> {
    serde_json::from_str(content).whatever("unable to parse application configuration JSON")
}

/// Serialize application configuration using a stable, human-readable representation.
pub fn serialize(value: &AppConfiguration) -> AppsResult<Vec<u8>> {
    let mut content = serde_json::to_vec_pretty(value)
        .whatever("unable to serialize application configuration")?;
    content.push(b'\n');
    Ok(content)
}

/// Load an arbitrary JSON document without exposing its content in error reports.
fn load_json(path: &Path, description: &str) -> AppsResult<AppConfiguration> {
    let content = fs::read_to_string(path)
        .whatever_with(|_| format!("unable to read {description}"))
        .field("path", path.to_owned())?;
    serde_json::from_str(&content)
        .whatever_with(|_| format!("unable to parse {description}"))
        .field("path", path.to_owned())
}

/// Resolve a manifest path while preventing traversal outside the generation.
fn generation_path(generation_dir: &Path, path: &str, description: &str) -> AppsResult<PathBuf> {
    let relative = ValidatedRelativePath::new(path.to_owned())
        .whatever_with(|_| format!("invalid {description} path"))?;
    Ok(generation_dir.join(relative))
}

#[cfg(test)]
mod tests {
    use rugix_bundle::manifest::AppConfigurationConfig;
    use rugix_bundle::manifest::AppManifest;

    use super::load_effective;
    use super::parse;

    /// Verifies effective configurations are checked against the bundled schema.
    #[test]
    fn effective_configuration_is_validated_against_the_generation_schema() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::write(
            tempdir.path().join("config.schema.json"),
            r#"{"type":"object","properties":{"url":{"type":"string","format":"uri"}},"required":["url"]}"#,
        )
        .unwrap();
        let manifest = AppManifest::new("generic".to_owned()).with_configuration(Some(
            AppConfigurationConfig::new().with_schema(Some("config.schema.json".to_owned().into())),
        ));
        let valid_path = tempdir.path().join("valid.json");
        std::fs::write(&valid_path, r#"{"url":"https://example.com"}"#).unwrap();
        let invalid_path = tempdir.path().join("invalid.json");
        std::fs::write(&invalid_path, r#"{"url":"not a URI"}"#).unwrap();

        assert!(load_effective(tempdir.path(), &manifest, Some(1), Some(valid_path)).is_ok());
        assert!(load_effective(tempdir.path(), &manifest, Some(2), Some(invalid_path)).is_err());
        assert!(parse("not json").is_err());
    }
}
