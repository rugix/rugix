//! Parsing and validation for Rugix component declarations.
//!
//! This module owns the boundary between the Sidex-defined TOML and JSON
//! declaration format and the in-memory compatibility model from
//! `rugix-component-set`.

use std::path::Path;

use reportify::whatever;
use reportify::ResultExt;
use rugix_component_set::Capability;
use rugix_component_set::CapabilitySelector;
use rugix_component_set::Claim;
use rugix_component_set::Component;

use crate::config::component::CapabilityDeclaration;
use crate::config::component::CapabilitySelectorDeclaration;
use crate::config::component::ComponentDeclaration;
use crate::system::SystemResult;

/// Parse and validate one TOML or JSON component declaration.
#[tracing::instrument(level = "debug", skip(content))]
pub(crate) fn parse_component(path: &Path, content: &str) -> SystemResult<Component> {
    let (component, unknown_fields) = parse_component_with_unknown(path, content)?;
    if !unknown_fields.is_empty() {
        tracing::warn!(
            path = %path.display(),
            fields = ?unknown_fields,
            "unknown fields in component declaration"
        );
    }
    Ok(component)
}

/// Parse and validate a declaration, retaining unknown field paths for diagnostics.
fn parse_component_with_unknown(
    path: &Path,
    content: &str,
) -> SystemResult<(Component, Vec<String>)> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    let (declaration, unknown_fields) = if extension.eq_ignore_ascii_case("json") {
        sidex::formats::json::from_str_with_unknown::<ComponentDeclaration>(content)
            .whatever("unable to parse JSON component file")
    } else {
        sidex::formats::toml::from_str_with_unknown::<ComponentDeclaration>(content)
            .whatever("unable to parse TOML component file")
    }
    .field_debug("path", path)?;
    let component = component_from_declaration(declaration).field_debug("path", path)?;
    Ok((
        component,
        unknown_fields.iter().map(ToString::to_string).collect(),
    ))
}

/// Convert a validated format declaration into the compatibility model.
fn component_from_declaration(declaration: ComponentDeclaration) -> SystemResult<Component> {
    let component_id = String::from(declaration.id);
    let mut component = match declaration.version {
        Some(version) => Component::versioned(component_id.clone(), &version)
            .whatever("invalid component version")
            .field("component", component_id.clone())?,
        None => Component::new(component_id.clone()),
    };

    for capability in declaration.provides.unwrap_or_default() {
        component = component.with_provided_capability(
            capability_from_declaration(capability).field("component", component_id.clone())?,
        );
    }
    for claim in declaration.claims.unwrap_or_default() {
        component = component.with_claim(Claim::new(String::from(claim.id)));
    }
    for selector in declaration.requires.unwrap_or_default() {
        component = component.with_requirement(
            selector_from_declaration(selector).field("component", component_id.clone())?,
        );
    }
    for selector in declaration.conflicts.unwrap_or_default() {
        component = component.with_conflict(
            selector_from_declaration(selector).field("component", component_id.clone())?,
        );
    }

    Ok(component)
}

/// Convert and validate one provided capability.
fn capability_from_declaration(declaration: CapabilityDeclaration) -> SystemResult<Capability> {
    let capability_id = String::from(declaration.id);
    match (declaration.version, declaration.value) {
        (None, None) => Ok(Capability::new(capability_id)),
        (Some(version), None) => Capability::versioned(capability_id.clone(), &version)
            .whatever("invalid capability version")
            .field("capability", capability_id),
        (None, Some(value)) => Ok(Capability::value(capability_id, value)),
        (Some(_), Some(_)) => Err(whatever!(
            "capability must not declare both a version and a value"
        )
        .field("capability", capability_id)),
    }
}

/// Convert and validate one requirement or conflict selector.
fn selector_from_declaration(
    declaration: CapabilitySelectorDeclaration,
) -> SystemResult<CapabilitySelector> {
    let capability_id = String::from(declaration.id);
    match (declaration.version, declaration.value) {
        (None, None) => Ok(CapabilitySelector::new(capability_id)),
        (Some(version), None) => CapabilitySelector::versioned(capability_id.clone(), &version)
            .whatever("invalid capability version requirement")
            .field("capability", capability_id),
        (None, Some(value)) => Ok(CapabilitySelector::value(capability_id, value)),
        (Some(_), Some(_)) => Err(whatever!(
            "capability selector must not declare both a version and a value"
        )
        .field("capability", capability_id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that the Sidex declaration format maps every TOML field into the domain
    /// model.
    #[test]
    fn parses_complete_toml_component_declaration() {
        let component = parse_component(
            Path::new("component.toml"),
            r#"
id = "app.web"
version = "1.2.3"

[[provides]]
id = "service.http"
version = "2.0"

[[claims]]
id = "network.tcp.8080"

[[requires]]
id = "host.arch"
value = "aarch64"

[[conflicts]]
id = "app.legacy"
"#,
        )
        .unwrap();

        assert_eq!(component.id().as_str(), "app.web");
        assert_eq!(
            component.version().map(ToString::to_string).as_deref(),
            Some("1.2.3")
        );
        assert_eq!(component.provides()[0].id().as_str(), "service.http");
        assert_eq!(component.claims()[0].id().as_str(), "network.tcp.8080");
        assert_eq!(component.requires()[0].value_str(), Some("aarch64"));
        assert_eq!(component.conflicts()[0].id().as_str(), "app.legacy");
    }

    /// Verifies that JSON declarations use the same Sidex-owned format as TOML
    /// declarations.
    #[test]
    fn parses_json_component_declaration() {
        let component = parse_component(
            Path::new("component.json"),
            r#"{
                "id": "app.web",
                "provides": [{"id": "service.http", "value": "enabled"}]
            }"#,
        )
        .unwrap();

        assert_eq!(component.id().as_str(), "app.web");
        assert_eq!(component.provides()[0].id().as_str(), "service.http");
        assert_eq!(component.provides()[0].value_str(), Some("enabled"));
    }

    /// Unknown top-level fields are accepted and reported in both formats.
    #[test]
    fn accepts_and_reports_unknown_component_fields() {
        for (path, content) in [
            (
                "component.toml",
                "id = \"app.web\"\nversion = \"1.2.3\"\nfuture = { enabled = true }",
            ),
            (
                "component.json",
                r#"{"id":"app.web","version":"1.2.3","future":{"enabled":true}}"#,
            ),
        ] {
            let (component, unknown_fields) =
                parse_component_with_unknown(Path::new(path), content).unwrap();

            assert_eq!(component.id().as_str(), "app.web");
            assert_eq!(component.version().unwrap().to_string(), "1.2.3");
            assert_eq!(unknown_fields, ["future"]);
        }
    }

    /// Nested unknown fields retain their full paths without changing known data.
    #[test]
    fn accepts_and_reports_unknown_nested_component_fields() {
        for (path, content) in [
            (
                "component.toml",
                r#"
id = "app.web"
provides = [{ id = "service.http" }, { id = "service.https", value = "enabled", future = true }]
claims = [{ id = "network.tcp.8080", future = true }]
requires = [{ id = "host.arch", value = "aarch64", future = true }]
conflicts = [{ id = "app.legacy", future = true }]
"#,
            ),
            (
                "component.json",
                r#"{
                    "id": "app.web",
                    "provides": [
                        {"id": "service.http"},
                        {"id": "service.https", "value": "enabled", "future": true}
                    ],
                    "claims": [{"id": "network.tcp.8080", "future": true}],
                    "requires": [{"id": "host.arch", "value": "aarch64", "future": true}],
                    "conflicts": [{"id": "app.legacy", "future": true}]
                }"#,
            ),
        ] {
            let (component, mut unknown_fields) =
                parse_component_with_unknown(Path::new(path), content).unwrap();

            assert_eq!(component.provides()[1].value_str(), Some("enabled"));
            assert_eq!(component.claims()[0].id().as_str(), "network.tcp.8080");
            assert_eq!(component.requires()[0].value_str(), Some("aarch64"));
            assert_eq!(component.conflicts()[0].id().as_str(), "app.legacy");
            unknown_fields.sort();
            assert_eq!(
                unknown_fields,
                [
                    "claims[0].future",
                    "conflicts[0].future",
                    "provides[1].future",
                    "requires[0].future",
                ]
            );
        }
    }

    /// Accepting unknown fields preserves type, required-field, and version checks.
    #[test]
    fn rejects_invalid_component_declarations_with_unknown_fields() {
        for (toml, json, expected) in [
            ("id = 42", r#"{"id":42}"#, "expected a string"),
            (
                "version = \"1.2.3\"",
                r#"{"version":"1.2.3"}"#,
                "missing field `id`",
            ),
            (
                "id = \"app.web\"\nprovides = [{}]",
                r#"{"id":"app.web","provides":[{}]}"#,
                "missing field `id`",
            ),
            (
                "id = \"app.web\"\nversion = \"\"",
                r#"{"id":"app.web","version":""}"#,
                "invalid component version",
            ),
            (
                "id = \"app.web\"\nprovides = [{ id = \"service.http\", version = \"\" }]",
                r#"{"id":"app.web","provides":[{"id":"service.http","version":""}]}"#,
                "invalid capability version",
            ),
            (
                "id = \"app.web\"\nrequires = [{ id = \"service.http\", version = \"\" }]",
                r#"{"id":"app.web","requires":[{"id":"service.http","version":""}]}"#,
                "invalid capability version requirement",
            ),
            (
                "id = \"app.web\"\nconflicts = [{ id = \"service.http\", version = \"\" }]",
                r#"{"id":"app.web","conflicts":[{"id":"service.http","version":""}]}"#,
                "invalid capability version requirement",
            ),
        ] {
            let toml = format!("future = true\n{toml}");
            let json = json.replacen('{', "{\"future\":true,", 1);
            for (path, content) in [("component.toml", toml), ("component.json", json)] {
                let error = parse_component(Path::new(path), &content).unwrap_err();
                let report = format!("{error:?}");
                assert!(report.contains(expected), "{path}: {report}");
                assert!(report.contains(path), "{report}");
            }
        }
    }

    /// Verifies that a provided capability has at most one kind of associated data.
    #[test]
    fn rejects_capability_with_version_and_value() {
        let error = parse_component(
            Path::new("component.toml"),
            r#"
id = "app.web"

[[provides]]
id = "service.http"
version = "2.0"
value = "enabled"
"#,
        )
        .unwrap_err();

        assert!(
            format!("{error:?}").contains("capability must not declare both a version and a value")
        );
    }

    /// Verifies that a selector has at most one kind of matching constraint.
    #[test]
    fn rejects_selector_with_version_and_value() {
        let error = parse_component(
            Path::new("component.toml"),
            r#"
id = "app.web"

[[requires]]
id = "service.http"
version = ">=2"
value = "enabled"
"#,
        )
        .unwrap_err();

        assert!(format!("{error:?}")
            .contains("capability selector must not declare both a version and a value"));
    }
}
