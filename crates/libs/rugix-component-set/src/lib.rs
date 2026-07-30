//! Component compatibility set evaluation for Rugix.
//!
//! This crate checks whether a set of system components is internally
//! compatible. A component may represent an operating system image, an app, a
//! runtime, a hardware description, or any other participant in the system.
//!
//! The component compatibility model is experimental and may change based on
//! practical deployment experience.
//!
//! Compatibility is modeled in terms of capabilities and exclusive claims. Each
//! component contributes a union of provided capabilities, including an implicit
//! capability for its own component ID and version. Components can also declare
//! requirement selectors (`requires`) and conflict selectors (`conflicts`) over
//! that union. Claims (`claims`) are exclusive resource ownership keys. A set is
//! consistent when every requirement selector matches at least one provided
//! capability, no conflict selector matches any provided capability, and no
//! claim is owned by more than one component.
//!
//! The set is purely in-memory and has no opinion about where component
//! metadata comes from. Callers can use it to validate a complete component set,
//! or to ask whether installing, removing, or replacing components would leave
//! the resulting set consistent.

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt;

pub use anyver::ParseError as VersionParseError;
pub use anyver::Version;
pub use anyver::VersionReq;

/// A component participating in a compatibility check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    id: ComponentId,
    version: Option<Version>,
    provides: Vec<Capability>,
    claims: Vec<Claim>,
    requires: Vec<CapabilitySelector>,
    conflicts: Vec<CapabilitySelector>,
}

impl Component {
    /// Create a component without a version.
    pub fn new(id: impl Into<ComponentId>) -> Self {
        Self {
            id: id.into(),
            version: None,
            provides: Vec::new(),
            claims: Vec::new(),
            requires: Vec::new(),
            conflicts: Vec::new(),
        }
    }

    /// Create a component with a parsed version.
    pub fn versioned(id: impl Into<ComponentId>, version: &str) -> Result<Self, VersionParseError> {
        Ok(Self::new(id).with_version(Version::parse(version)?))
    }

    /// Component identifier.
    pub fn id(&self) -> &ComponentId {
        &self.id
    }

    /// Component version, if present.
    pub fn version(&self) -> Option<&Version> {
        self.version.as_ref()
    }

    /// Explicit capabilities provided by this component.
    pub fn provides(&self) -> &[Capability] {
        &self.provides
    }

    /// Exclusive resource claims made by this component.
    pub fn claims(&self) -> &[Claim] {
        &self.claims
    }

    /// Requirement selectors.
    pub fn requires(&self) -> &[CapabilitySelector] {
        &self.requires
    }

    /// Conflict selectors.
    pub fn conflicts(&self) -> &[CapabilitySelector] {
        &self.conflicts
    }

    /// Set the component version.
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self
    }

    /// Add an explicit provided capability.
    pub fn with_provided_capability(mut self, capability: Capability) -> Self {
        self.provides.push(capability);
        self
    }

    /// Add an exclusive resource claim.
    pub fn with_claim(mut self, claim: Claim) -> Self {
        self.claims.push(claim);
        self
    }

    /// Add a requirement selector.
    pub fn with_requirement(mut self, selector: CapabilitySelector) -> Self {
        self.requires.push(selector);
        self
    }

    /// Add a conflict selector.
    pub fn with_conflict(mut self, selector: CapabilitySelector) -> Self {
        self.conflicts.push(selector);
        self
    }

    fn implicit_capability(&self) -> Capability {
        Capability {
            id: CapabilityId::from(&self.id),
            version: self.version.clone(),
            value: None,
        }
    }
}

/// An exclusive resource claim made by a component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    id: ClaimId,
}

impl Claim {
    /// Create an exclusive resource claim.
    pub fn new(id: impl Into<ClaimId>) -> Self {
        Self { id: id.into() }
    }

    /// Claim identifier.
    pub fn id(&self) -> &ClaimId {
        &self.id
    }
}

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// A capability provided by a component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    id: CapabilityId,
    version: Option<Version>,
    value: Option<String>,
}

impl Capability {
    /// Create an unversioned presence capability.
    pub fn new(id: impl Into<CapabilityId>) -> Self {
        Self {
            id: id.into(),
            version: None,
            value: None,
        }
    }

    /// Create a versioned capability.
    pub fn versioned(
        id: impl Into<CapabilityId>,
        version: &str,
    ) -> Result<Self, VersionParseError> {
        Ok(Self::new(id).with_version(Version::parse(version)?))
    }

    /// Create a value capability.
    pub fn value(id: impl Into<CapabilityId>, value: impl Into<String>) -> Self {
        Self::new(id).with_value(value)
    }

    /// Capability identifier.
    pub fn id(&self) -> &CapabilityId {
        &self.id
    }

    /// Capability version, if present.
    pub fn version(&self) -> Option<&Version> {
        self.version.as_ref()
    }

    /// Capability value, if present.
    pub fn value_str(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Set the capability version.
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self
    }

    /// Set the capability value.
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)?;
        if let Some(version) = &self.version {
            write!(f, " {version}")?;
        }
        if let Some(value) = &self.value {
            write!(f, "={value:?}")?;
        }
        Ok(())
    }
}

/// A selector matching provided capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySelector {
    id: CapabilityId,
    version: Option<VersionReq>,
    value: Option<String>,
}

impl CapabilitySelector {
    /// Create a selector matching capability presence.
    pub fn new(id: impl Into<CapabilityId>) -> Self {
        Self {
            id: id.into(),
            version: None,
            value: None,
        }
    }

    /// Create a selector matching a versioned capability.
    pub fn versioned(
        id: impl Into<CapabilityId>,
        requirement: &str,
    ) -> Result<Self, VersionParseError> {
        Ok(Self::new(id).with_version_req(VersionReq::parse(requirement)?))
    }

    /// Create a selector matching a capability value.
    pub fn value(id: impl Into<CapabilityId>, value: impl Into<String>) -> Self {
        Self::new(id).with_value(value)
    }

    /// Selected capability identifier.
    pub fn id(&self) -> &CapabilityId {
        &self.id
    }

    /// Version requirement used when matching versioned capabilities.
    pub fn version_req(&self) -> Option<&VersionReq> {
        self.version.as_ref()
    }

    /// Value to match.
    pub fn value_str(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Set the version requirement used for matching.
    pub fn with_version_req(mut self, requirement: VersionReq) -> Self {
        self.version = Some(requirement);
        self
    }

    /// Set the value to match.
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Whether this selector matches the provided capability.
    pub fn matches(&self, capability: &Capability) -> bool {
        if self.id != capability.id {
            return false;
        }
        if let Some(expected_value) = &self.value {
            if capability.value.as_ref() != Some(expected_value) {
                return false;
            }
        }
        if let Some(version_req) = &self.version {
            let Some(version) = &capability.version else {
                return false;
            };
            if !version_req.matches(version) {
                return false;
            }
        }
        true
    }
}

impl fmt::Display for CapabilitySelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)?;
        if let Some(version) = &self.version {
            write!(f, " {version}")?;
        }
        if let Some(value) = &self.value {
            write!(f, "={value:?}")?;
        }
        Ok(())
    }
}

/// A capability with the component that provided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvidedCapability {
    /// Component ID providing the capability.
    pub provider: ComponentId,
    /// Capability provided by the component.
    pub capability: Capability,
}

/// A component set.
#[derive(Debug, Clone, Default)]
pub struct ComponentSet {
    components: Vec<Component>,
}

impl ComponentSet {
    /// Create a set from components.
    pub fn new(components: Vec<Component>) -> Self {
        Self { components }
    }

    /// Components in the set.
    pub fn components(&self) -> &[Component] {
        &self.components
    }

    /// Compute the union of provided capabilities.
    pub fn provided_capabilities(&self) -> Vec<ProvidedCapability> {
        let mut capabilities = Vec::new();
        for component in &self.components {
            capabilities.push(ProvidedCapability {
                provider: component.id.clone(),
                capability: component.implicit_capability(),
            });
            capabilities.extend(component.provides.iter().cloned().map(|capability| {
                ProvidedCapability {
                    provider: component.id.clone(),
                    capability,
                }
            }));
        }
        capabilities
    }

    /// Check the set for internal consistency.
    pub fn check(&self) -> ConsistencyReport {
        let mut problems = Vec::new();
        self.check_duplicate_components(&mut problems);
        self.check_duplicate_claims(&mut problems);

        let provided = self.provided_capabilities();
        for component in &self.components {
            for selector in &component.requires {
                if !provided
                    .iter()
                    .any(|provided| selector.matches(&provided.capability))
                {
                    problems.push(Problem::UnsatisfiedRequirement {
                        component: component.id.clone(),
                        selector: selector.clone(),
                    });
                }
            }
            for selector in &component.conflicts {
                for provided in &provided {
                    if selector.matches(&provided.capability) {
                        problems.push(Problem::Conflict {
                            component: component.id.clone(),
                            selector: selector.clone(),
                            provider: provided.provider.clone(),
                            capability: provided.capability.clone(),
                        });
                    }
                }
            }
        }

        ConsistencyReport { problems }
    }

    /// Check whether adding a component would keep the set consistent.
    pub fn check_install(&self, component: &Component) -> ConsistencyReport {
        let mut components = self.components.clone();
        components.push(component.clone());
        Self::new(components).check()
    }

    /// Check whether removing a component would keep the set consistent.
    pub fn check_remove(&self, component_id: impl AsRef<str>) -> ConsistencyReport {
        self.check_replace([component_id], std::iter::empty::<Component>())
    }

    /// Check whether replacing components would keep the set consistent.
    pub fn check_replace<R, S, C>(
        &self,
        remove_component_ids: R,
        install_components: C,
    ) -> ConsistencyReport
    where
        R: IntoIterator<Item = S>,
        S: AsRef<str>,
        C: IntoIterator<Item = Component>,
    {
        let mut components = self.components.clone();
        for id in remove_component_ids.into_iter() {
            components.retain(|component| component.id().as_str() != id.as_ref());
        }
        components.extend(install_components);
        Self::new(components).check()
    }

    /// Whether adding a component would keep the set consistent.
    pub fn can_install(&self, component: &Component) -> bool {
        self.check_install(component).is_consistent()
    }

    /// Whether removing a component would keep the set consistent.
    pub fn can_remove(&self, component_id: impl AsRef<str>) -> bool {
        self.check_remove(component_id).is_consistent()
    }

    fn check_duplicate_components(&self, problems: &mut Vec<Problem>) {
        let mut seen = HashSet::new();
        let mut duplicates = Vec::new();
        for component in &self.components {
            if !seen.insert(component.id()) && !duplicates.contains(component.id()) {
                duplicates.push(component.id().clone());
            }
        }
        for id in duplicates {
            problems.push(Problem::DuplicateComponent { id });
        }
    }

    fn check_duplicate_claims(&self, problems: &mut Vec<Problem>) {
        let mut claims: BTreeMap<ClaimId, Vec<ComponentId>> = BTreeMap::new();
        for component in &self.components {
            let mut component_claims = HashSet::new();
            for claim in &component.claims {
                if !component_claims.insert(claim.id()) {
                    continue;
                }
                claims
                    .entry(claim.id.clone())
                    .or_default()
                    .push(component.id.clone());
            }
        }
        for (id, components) in claims {
            if components.len() > 1 {
                problems.push(Problem::DuplicateClaim { id, components });
            }
        }
    }
}

/// Consistency check result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConsistencyReport {
    problems: Vec<Problem>,
}

impl ConsistencyReport {
    /// Problems found while checking the set.
    pub fn problems(&self) -> &[Problem] {
        &self.problems
    }

    /// Consume the report and return its problems.
    pub fn into_problems(self) -> Vec<Problem> {
        self.problems
    }

    /// Whether the set is internally consistent.
    pub fn is_consistent(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Internal consistency problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// More than one component uses the same component ID.
    DuplicateComponent {
        /// Duplicate component ID.
        id: ComponentId,
    },
    /// More than one component claims the same exclusive resource.
    DuplicateClaim {
        /// Duplicate claim ID.
        id: ClaimId,
        /// Components declaring the duplicate claim.
        components: Vec<ComponentId>,
    },
    /// A requirement selector did not match any provided capability.
    UnsatisfiedRequirement {
        /// Component declaring the requirement selector.
        component: ComponentId,
        /// Requirement selector that was not satisfied.
        selector: CapabilitySelector,
    },
    /// A conflict selector matched a provided capability.
    Conflict {
        /// Component declaring the conflict selector.
        component: ComponentId,
        /// Conflict selector that matched.
        selector: CapabilitySelector,
        /// Component providing the conflicting capability.
        provider: ComponentId,
        /// Capability matched by the conflict selector.
        capability: Capability,
    },
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateComponent { id } => {
                write!(f, "duplicate component id {:?}", id.as_str())
            }
            Self::DuplicateClaim { id, components } => {
                write!(
                    f,
                    "duplicate claim id {:?} declared by {} components",
                    id.as_str(),
                    components.len()
                )
            }
            Self::UnsatisfiedRequirement {
                component,
                selector,
            } => {
                write!(
                    f,
                    "component {:?} requirement selector {selector} was not satisfied",
                    component.as_str()
                )
            }
            Self::Conflict {
                component,
                selector,
                provider,
                capability,
            } => {
                write!(
                    f,
                    "component {:?} conflict selector {selector} matched {capability} provided by {:?}",
                    component.as_str(),
                    provider.as_str()
                )
            }
        }
    }
}

/// Identifier of a component.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComponentId(String);

impl ComponentId {
    /// Create a component identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the identifier as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the identifier and return the owned string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for ComponentId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ComponentId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl AsRef<str> for ComponentId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ComponentId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Identifier of a claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimId(String);

impl ClaimId {
    /// Create a claim identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the identifier as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the identifier and return the owned string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for ClaimId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ClaimId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl AsRef<str> for ClaimId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ClaimId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ClaimId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Identifier of a capability.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityId(String);

impl CapabilityId {
    /// Create a capability identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the identifier as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the identifier and return the owned string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for CapabilityId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for CapabilityId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<ComponentId> for CapabilityId {
    fn from(value: ComponentId) -> Self {
        Self(value.into_string())
    }
}

impl From<&ComponentId> for CapabilityId {
    fn from(value: &ComponentId) -> Self {
        Self(value.as_str().to_owned())
    }
}

impl AsRef<str> for CapabilityId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for CapabilityId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_typed_but_remain_ergonomic() {
        let component_id = ComponentId::from("app.gateway");
        let capability_id = CapabilityId::from("service.modbus");
        let claim_id = ClaimId::from("network.tcp.502");
        let component = Component::new(component_id.clone())
            .with_provided_capability(Capability::new(capability_id.clone()))
            .with_claim(Claim::new(claim_id.clone()));
        let set = ComponentSet::new(vec![component]);

        assert_eq!(set.components()[0].id(), &component_id);
        assert_eq!(set.components()[0].provides()[0].id(), &capability_id);
        assert_eq!(set.components()[0].claims()[0].id(), &claim_id);

        let provided = set.provided_capabilities();
        assert_eq!(provided[0].provider, component_id);
        assert_eq!(
            provided[0].capability.id(),
            &CapabilityId::from("app.gateway")
        );
        assert_eq!(provided[1].capability.id(), &capability_id);
    }

    #[test]
    fn requirement_selectors_match_implicit_component_capabilities() {
        let app = Component::versioned("app.analytics", "1.0.0")
            .unwrap()
            .with_requirement(CapabilitySelector::versioned("system.edge-os", ">=5,<6").unwrap());
        let set = ComponentSet::new(vec![system("5.2.0"), app]);

        assert!(set.check().is_consistent());
    }

    #[test]
    fn requirement_selectors_can_match_hardware_capabilities() {
        let os = system("5.2.0")
            .with_requirement(
                CapabilitySelector::versioned("hardware.edge-gateway", ">=2,<3").unwrap(),
            )
            .with_requirement(CapabilitySelector::value("hardware.arch", "arm64"));
        let set = ComponentSet::new(vec![hardware(), os]);

        assert!(set.check().is_consistent());
    }

    #[test]
    fn unsatisfied_requirement_selector_is_reported() {
        let app = Component::new("app.analytics").with_requirement(
            CapabilitySelector::versioned("runtime.docker-compose", ">=2.20").unwrap(),
        );
        let set = ComponentSet::new(vec![system("5.2.0"), app]);
        let report = set.check();

        assert!(!report.is_consistent());
        assert!(matches!(
            report.problems(),
            [Problem::UnsatisfiedRequirement { component, .. }] if component.as_str() == "app.analytics"
        ));
    }

    #[test]
    fn conflict_selectors_are_reported() {
        let first = Component::new("app.gateway-a")
            .with_provided_capability(Capability::new("service.modbus"));
        let second = Component::new("app.gateway-b")
            .with_conflict(CapabilitySelector::new("service.modbus"));
        let set = ComponentSet::new(vec![first, second]);
        let report = set.check();

        assert!(!report.is_consistent());
        assert!(matches!(
            report.problems(),
            [Problem::Conflict { component, provider, .. }]
                if component.as_str() == "app.gateway-b" && provider.as_str() == "app.gateway-a"
        ));
    }

    #[test]
    fn duplicate_component_ids_are_reported() {
        let set = ComponentSet::new(vec![system("5.1.0"), system("5.2.0")]);
        let report = set.check();

        assert!(matches!(
            report.problems(),
            [Problem::DuplicateComponent { id }] if id.as_str() == "system.edge-os"
        ));
    }

    #[test]
    fn duplicate_claims_are_reported() {
        let first = Component::new("app.gateway-a").with_claim(Claim::new("network.tcp.502"));
        let second = Component::new("app.gateway-b").with_claim(Claim::new("network.tcp.502"));
        let set = ComponentSet::new(vec![first, second]);
        let report = set.check();

        assert!(!report.is_consistent());
        assert!(matches!(
            report.problems(),
            [Problem::DuplicateClaim { id, components }]
                if id.as_str() == "network.tcp.502"
                    && components.iter().map(ComponentId::as_str).collect::<Vec<_>>()
                        == ["app.gateway-a", "app.gateway-b"]
        ));
    }

    #[test]
    fn duplicate_claims_within_one_component_are_ignored() {
        let component = Component::new("app.gateway")
            .with_claim(Claim::new("network.tcp.502"))
            .with_claim(Claim::new("network.tcp.502"));
        let set = ComponentSet::new(vec![component]);

        assert!(set.check().is_consistent());
    }

    #[test]
    fn claims_do_not_satisfy_requirements() {
        let provider = Component::new("app.gateway").with_claim(Claim::new("network.tcp.502"));
        let consumer = Component::new("app.client")
            .with_requirement(CapabilitySelector::new("network.tcp.502"));
        let set = ComponentSet::new(vec![provider, consumer]);
        let report = set.check();

        assert!(matches!(
            report.problems(),
            [Problem::UnsatisfiedRequirement { component, .. }] if component.as_str() == "app.client"
        ));
    }

    #[test]
    fn install_check_reports_new_component_requirement_selectors() {
        let set = ComponentSet::new(vec![system("5.2.0")]);
        let app = Component::new("app.gateway").with_requirement(
            CapabilitySelector::versioned("runtime.docker-compose", ">=2.20").unwrap(),
        );
        let report = set.check_install(&app);

        assert!(!report.is_consistent());
    }

    #[test]
    fn remove_check_reports_broken_dependents() {
        let runtime = Component::versioned("runtime.docker-compose", "2.29.0").unwrap();
        let app = Component::new("app.gateway").with_requirement(
            CapabilitySelector::versioned("runtime.docker-compose", ">=2.20").unwrap(),
        );
        let set = ComponentSet::new(vec![runtime, app]);

        assert!(!set.can_remove("runtime.docker-compose"));
        let report = set.check_remove("runtime.docker-compose");
        assert!(matches!(
            report.problems(),
            [Problem::UnsatisfiedRequirement { component, .. }] if component.as_str() == "app.gateway"
        ));
    }

    #[test]
    fn replace_check_detects_os_downgrade_breaking_an_app() {
        let app = Component::new("app.analytics")
            .with_requirement(CapabilitySelector::versioned("system.edge-os", ">=5").unwrap());
        let set = ComponentSet::new(vec![system("5.2.0"), app]);

        let downgrade = set.check_replace(["system.edge-os"], [system("4.9.0")]);
        assert!(!downgrade.is_consistent());

        let upgrade = set.check_replace(["system.edge-os"], [system("5.3.0")]);
        assert!(upgrade.is_consistent());
    }

    #[test]
    fn replace_check_allows_duplicate_remove_ids() {
        let set = ComponentSet::new(vec![system("5.2.0")]);
        let report = set.check_replace(["system.edge-os", "system.edge-os"], [system("5.3.0")]);

        assert!(report.is_consistent());
    }

    #[test]
    fn remove_check_ignores_missing_component_id() {
        let set = ComponentSet::new(vec![system("5.2.0")]);
        let report = set.check_remove("app.missing");

        assert!(report.is_consistent());
        assert_eq!(set.components().len(), 1);
    }

    #[test]
    fn install_check_reports_duplicate_component_id() {
        let set = ComponentSet::new(vec![system("5.2.0")]);
        let report = set.check_install(&system("5.3.0"));

        assert!(matches!(
            report.problems(),
            [Problem::DuplicateComponent { id }] if id.as_str() == "system.edge-os"
        ));
    }

    fn system(version: &str) -> Component {
        Component::versioned("system.edge-os", version).unwrap()
    }

    fn hardware() -> Component {
        Component::new("hardware.local")
            .with_provided_capability(
                Capability::versioned("hardware.edge-gateway", "2.1.0").unwrap(),
            )
            .with_provided_capability(Capability::value("hardware.arch", "arm64"))
    }
}
