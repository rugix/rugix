use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::str;

use reportify::bail;
use reportify::whatever;
use reportify::ErrorExt;
use reportify::ResultExt;
use rugix_bundle::format::BundleComponents;
use rugix_component_set::Capability;
use rugix_component_set::CapabilitySelector;
use rugix_component_set::Claim;
use rugix_component_set::Component;
use rugix_component_set::ComponentId;
use rugix_component_set::ComponentSet;
use rugix_component_set::Problem;

use crate::apps::manager::AppManager;
use crate::config::output::CapabilityOutput;
use crate::config::output::CapabilitySelectorOutput;
use crate::config::output::ClaimOutput;
use crate::config::output::ComponentConflictProblemOutput;
use crate::config::output::ComponentOutput;
use crate::config::output::ComponentProblemOutput;
use crate::config::output::ComponentRefOutput;
use crate::config::output::ComponentRootOutput;
use crate::config::output::ComponentSourceKindOutput;
use crate::config::output::ComponentSourceOutput;
use crate::config::output::ComponentsCheckOutput;
use crate::config::output::ComponentsOutput;
use crate::config::output::DuplicateClaimProblemOutput;
use crate::config::output::DuplicateComponentProblemOutput;
use crate::config::output::LoadedComponentOutput;
use crate::config::output::UnsatisfiedRequirementProblemOutput;
use crate::system::SystemResult;

const SYSTEM_COMPONENTS_DIR: &str = "/usr/lib/rugix/components";
const LOCAL_COMPONENTS_DIR: &str = "/etc/rugix/components";
const RUNTIME_COMPONENTS_DIR: &str = "/run/rugix/components";
const SYNTHETIC_COMPONENT_ROOT: &str = "rugix:synthetic";

/// Installed components loaded from all active component roots.
#[derive(Debug, Clone)]
pub struct InstalledComponents {
    roots: Vec<ComponentLocation>,
    components: Vec<LoadedComponent>,
}

impl InstalledComponents {
    /// Load installed components from the standard Rugix component roots.
    pub fn load() -> SystemResult<Self> {
        let mut components = Self {
            roots: Vec::new(),
            components: Vec::new(),
        };
        components.load_root(ComponentLocation::new(
            ComponentSourceKindOutput::System,
            SYSTEM_COMPONENTS_DIR,
        ))?;
        components.load_root(ComponentLocation::new(
            ComponentSourceKindOutput::Local,
            LOCAL_COMPONENTS_DIR,
        ))?;
        components.load_root(ComponentLocation::new(
            ComponentSourceKindOutput::Runtime,
            RUNTIME_COMPONENTS_DIR,
        ))?;
        components.load_active_app_roots()?;
        components.load_synthetic_components();
        Ok(components)
    }

    /// Build inventory output for all loaded components.
    pub fn output(&self) -> ComponentsOutput {
        ComponentsOutput::new(self.root_outputs(), self.component_outputs())
    }

    /// Build inventory output for components with the given component ID.
    pub fn output_for_component(&self, component_id: &str) -> SystemResult<ComponentsOutput> {
        let components = self
            .components
            .iter()
            .filter(|component| component.component.id().as_str() == component_id)
            .map(LoadedComponent::output)
            .collect::<Vec<_>>();
        if components.is_empty() {
            bail!("component {component_id:?} not found");
        }
        Ok(ComponentsOutput::new(self.root_outputs(), components))
    }

    /// Check the loaded component set for internal consistency.
    pub fn check_output(&self) -> ComponentsCheckOutput {
        let component_set = ComponentSet::new(
            self.components
                .iter()
                .map(|component| component.component.clone())
                .collect(),
        );
        let report = component_set.check();
        let consistent = report.is_consistent();
        let problems = report
            .problems()
            .iter()
            .map(|problem| self.problem_output(problem))
            .collect();
        ComponentsCheckOutput::new(
            self.root_outputs(),
            self.component_outputs(),
            consistent,
            problems,
        )
    }

    /// Check whether replacing system components with bundle-declared components is
    /// consistent.
    pub fn check_system_update(
        &self,
        bundle_components: &BundleComponents,
    ) -> SystemResult<ComponentsCheckOutput> {
        let mut candidate = self.without_locations(is_system_location);
        candidate.load_bundle_components(bundle_components)?;
        Ok(candidate.check_output())
    }

    /// Check whether replacing installed components declared by an incremental
    /// bundle with the bundle-declared components is consistent.
    pub fn check_incremental_update(
        &self,
        bundle_components: &BundleComponents,
    ) -> SystemResult<ComponentsCheckOutput> {
        let bundle_components = bundle_component_declarations(bundle_components)?;
        let mut candidate = self.without_component_ids(
            bundle_components
                .iter()
                .map(|(_, component)| component.id()),
        );
        candidate.add_bundle_components(bundle_components);
        Ok(candidate.check_output())
    }

    /// Check whether replacing touched app components with bundle-declared components is
    /// consistent.
    pub fn check_app_update(
        &self,
        touched_apps: &[String],
        bundle_components: Option<&BundleComponents>,
    ) -> SystemResult<ComponentsCheckOutput> {
        let mut candidate =
            self.without_locations(|location| is_touched_app_location(location, touched_apps));
        if let Some(bundle_components) = bundle_components {
            candidate.load_bundle_components(bundle_components)?;
        }
        Ok(candidate.check_output())
    }

    /// Check whether removing the active components for an app is consistent.
    pub fn check_app_removal(&self, app: &str) -> ComponentsCheckOutput {
        self.without_locations(|location| is_app_location(location, app))
            .check_output()
    }

    /// Check whether replacing the active components for an app with components
    /// from another generation is consistent.
    pub fn check_app_generation(
        &self,
        app: &str,
        generation: u64,
        component_root: impl Into<PathBuf>,
    ) -> SystemResult<ComponentsCheckOutput> {
        let mut candidate = self.without_locations(|location| is_app_location(location, app));
        candidate.load_root(ComponentLocation::app(
            app.to_owned(),
            generation,
            component_root,
        ))?;
        Ok(candidate.check_output())
    }

    fn root_outputs(&self) -> Vec<ComponentRootOutput> {
        self.roots
            .iter()
            .map(ComponentLocation::root_output)
            .collect()
    }

    fn component_outputs(&self) -> Vec<LoadedComponentOutput> {
        self.components
            .iter()
            .map(LoadedComponent::output)
            .collect()
    }

    fn load_root(&mut self, root: ComponentLocation) -> SystemResult<()> {
        for path in find_component_files(&root.path)? {
            let component = read_component_file(&path)?;
            self.components.push(LoadedComponent {
                source: root.file_location(path),
                component,
            });
        }

        self.roots.push(root);
        Ok(())
    }

    fn load_bundle_components(&mut self, bundle_components: &BundleComponents) -> SystemResult<()> {
        let components = bundle_component_declarations(bundle_components)?;
        self.add_bundle_components(components);
        Ok(())
    }

    fn add_bundle_components(&mut self, components: Vec<(String, Component)>) {
        let root = ComponentLocation::bundle_root();
        for (path, component) in components {
            self.components.push(LoadedComponent {
                source: root.bundle_file_location(&path),
                component,
            });
        }
        self.roots.push(root);
    }

    fn load_active_app_roots(&mut self) -> SystemResult<()> {
        let apps_config =
            crate::apps::config::load_apps_config().whatever("unable to load apps config")?;
        let apps_dir = crate::apps::config::apps_dir().to_owned();
        let manager = AppManager::new(apps_dir, apps_config);
        let apps = manager.list_apps().whatever("unable to list apps")?;
        for app in apps {
            let Some(generation) = manager
                .current_generation(&app)
                .whatever("unable to read app state")
                .field_display("app", &app)?
            else {
                continue;
            };
            let root_path = manager
                .generation_dir(&app, generation)
                .whatever("invalid app name")?
                .join(".rugix/components");
            self.load_root(ComponentLocation::app(app, generation, root_path))?;
        }
        Ok(())
    }

    fn load_synthetic_components(&mut self) {
        let root = ComponentLocation::synthetic_root();
        self.components.push(LoadedComponent {
            source: root.synthetic_component_location("rugix.host"),
            component: synthetic_host_component(),
        });
        self.roots.push(root);
    }

    fn without_locations(&self, remove: impl Fn(&ComponentLocation) -> bool) -> Self {
        Self {
            roots: self
                .roots
                .iter()
                .filter(|root| !remove(root))
                .cloned()
                .collect(),
            components: self
                .components
                .iter()
                .filter(|component| !remove(&component.source))
                .cloned()
                .collect(),
        }
    }

    fn without_component_ids<'a>(
        &self,
        component_ids: impl IntoIterator<Item = &'a ComponentId>,
    ) -> Self {
        let component_ids = component_ids.into_iter().collect::<Vec<_>>();
        Self {
            roots: self.roots.clone(),
            components: self
                .components
                .iter()
                .filter(|component| {
                    !component_ids
                        .iter()
                        .any(|id| component.component.id() == *id)
                })
                .cloned()
                .collect(),
        }
    }

    fn problem_output(&self, problem: &Problem) -> ComponentProblemOutput {
        match problem {
            Problem::DuplicateComponent { id } => {
                ComponentProblemOutput::DuplicateComponent(DuplicateComponentProblemOutput::new(
                    id.to_string(),
                    self.sources_for_component(id),
                ))
            }
            Problem::DuplicateClaim { id, components } => {
                ComponentProblemOutput::DuplicateClaim(DuplicateClaimProblemOutput::new(
                    id.to_string(),
                    components
                        .iter()
                        .map(|component_id| self.component_ref_output(component_id))
                        .collect(),
                ))
            }
            Problem::UnsatisfiedRequirement {
                component,
                selector,
            } => ComponentProblemOutput::UnsatisfiedRequirement(
                UnsatisfiedRequirementProblemOutput::new(
                    self.component_ref_output(component),
                    selector_output(selector),
                ),
            ),
            Problem::Conflict {
                component,
                selector,
                provider,
                capability,
            } => ComponentProblemOutput::Conflict(ComponentConflictProblemOutput::new(
                self.component_ref_output(component),
                selector_output(selector),
                self.component_ref_output(provider),
                capability_output(capability),
            )),
        }
    }

    fn component_ref_output(&self, component_id: &ComponentId) -> ComponentRefOutput {
        ComponentRefOutput::new(component_id.to_string())
            .with_source(self.source_for_component(component_id))
    }

    fn source_for_component(&self, component_id: &ComponentId) -> Option<ComponentSourceOutput> {
        self.components
            .iter()
            .find(|component| component.component.id() == component_id)
            .map(|component| component.source.source_output())
    }

    fn sources_for_component(&self, component_id: &ComponentId) -> Vec<ComponentSourceOutput> {
        self.components
            .iter()
            .filter(|component| component.component.id() == component_id)
            .map(|component| component.source.source_output())
            .collect()
    }
}

/// Write bundle-declared component metadata to a component root.
pub fn write_bundle_components(
    bundle_components: &BundleComponents,
    root: &Path,
) -> SystemResult<()> {
    validate_bundle_components(bundle_components)?;
    prepare_component_root_parent(root)?;
    remove_component_root(root)?;
    fs::create_dir_all(root)
        .whatever("unable to create component root")
        .field_debug("path", root)?;

    let mut files = bundle_components.files.iter().collect::<Vec<_>>();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    for file in files {
        let path = root.join(&file.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .whatever("unable to create component file parent directory")
                .field_debug("path", parent)?;
        }
        fs::write(&path, &file.data.raw)
            .whatever("unable to write component file")
            .field_debug("path", &path)?;
    }
    Ok(())
}

/// Validate bundle-declared component metadata.
pub fn validate_bundle_components(bundle_components: &BundleComponents) -> SystemResult<()> {
    bundle_component_declarations(bundle_components).map(|_| ())
}

fn bundle_component_declarations(
    bundle_components: &BundleComponents,
) -> SystemResult<Vec<(String, Component)>> {
    let mut paths = HashSet::new();
    let mut files = bundle_components.files.iter().collect::<Vec<_>>();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let mut components = Vec::new();
    for file in files {
        validate_bundle_component_path(&file.path)?;
        if !paths.insert(file.path.as_str()) {
            bail!("duplicate bundle component file path: {:?}", file.path);
        }
        components.push((file.path.clone(), read_bundle_component_file(file)?));
    }
    Ok(components)
}

#[derive(Debug, Clone)]
struct LoadedComponent {
    source: ComponentLocation,
    component: Component,
}

impl LoadedComponent {
    fn output(&self) -> LoadedComponentOutput {
        LoadedComponentOutput::new(
            self.source.source_output(),
            component_output(&self.component),
        )
    }
}

#[derive(Debug, Clone)]
struct ComponentLocation {
    kind: ComponentSourceKindOutput,
    path: PathBuf,
    app: Option<String>,
    generation: Option<u64>,
}

impl ComponentLocation {
    fn new(kind: ComponentSourceKindOutput, path: impl Into<PathBuf>) -> Self {
        Self {
            kind,
            path: path.into(),
            app: None,
            generation: None,
        }
    }

    fn app(app: String, generation: u64, path: impl Into<PathBuf>) -> Self {
        Self {
            kind: ComponentSourceKindOutput::App,
            path: path.into(),
            app: Some(app),
            generation: Some(generation),
        }
    }

    fn bundle_root() -> Self {
        Self {
            kind: ComponentSourceKindOutput::Bundle,
            path: PathBuf::from("components"),
            app: None,
            generation: None,
        }
    }

    fn synthetic_root() -> Self {
        Self {
            kind: ComponentSourceKindOutput::Synthetic,
            path: PathBuf::from(SYNTHETIC_COMPONENT_ROOT),
            app: None,
            generation: None,
        }
    }

    fn file_location(&self, path: PathBuf) -> Self {
        Self {
            kind: self.kind.clone(),
            path,
            app: self.app.clone(),
            generation: self.generation,
        }
    }

    fn bundle_file_location(&self, path: &str) -> Self {
        Self {
            kind: self.kind.clone(),
            path: self.path.join(path),
            app: None,
            generation: None,
        }
    }

    fn synthetic_component_location(&self, component_id: &str) -> Self {
        Self {
            kind: self.kind.clone(),
            path: self.path.join(component_id),
            app: None,
            generation: None,
        }
    }

    fn root_output(&self) -> ComponentRootOutput {
        ComponentRootOutput::new(self.kind.clone(), self.path.to_string_lossy().into_owned())
            .with_app(self.app.clone())
            .with_generation(self.generation)
    }

    fn source_output(&self) -> ComponentSourceOutput {
        ComponentSourceOutput::new(self.kind.clone(), self.path.to_string_lossy().into_owned())
            .with_app(self.app.clone())
            .with_generation(self.generation)
    }
}

fn is_system_location(location: &ComponentLocation) -> bool {
    matches!(&location.kind, ComponentSourceKindOutput::System)
}

fn is_app_location(location: &ComponentLocation, app: &str) -> bool {
    matches!(&location.kind, ComponentSourceKindOutput::App) && location.app.as_deref() == Some(app)
}

fn is_touched_app_location(location: &ComponentLocation, touched_apps: &[String]) -> bool {
    location
        .app
        .as_deref()
        .is_some_and(|app| touched_apps.iter().any(|touched| touched == app))
        && matches!(&location.kind, ComponentSourceKindOutput::App)
}

fn synthetic_host_component() -> Component {
    Component::new("rugix.host")
        .with_provided_capability(Capability::value("host.arch", std::env::consts::ARCH))
        .with_provided_capability(rugix_ctrl_capability(rugix_version::RUGIX_GIT_VERSION))
}

fn rugix_ctrl_capability(version: &str) -> Capability {
    if let Ok(capability) = Capability::versioned("rugix.ctrl", version) {
        return capability;
    }
    if let Some(normalized) = version.strip_prefix('v') {
        if let Ok(capability) = Capability::versioned("rugix.ctrl", normalized) {
            return capability;
        }
    }
    Capability::value("rugix.ctrl", version)
}

fn prepare_component_root_parent(root: &Path) -> SystemResult<()> {
    let Some(parent) = root.parent() else {
        return Ok(());
    };

    let metadata = match fs::symlink_metadata(parent) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(parent)
                .whatever("unable to create component root parent")
                .field_debug("path", parent)?;
            return Ok(());
        }
        Err(error) => {
            return Err(error
                .whatever("unable to inspect component root parent")
                .field_debug("path", parent));
        }
    };

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        return Ok(());
    }

    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        fs::remove_file(parent)
    } else {
        fs::remove_dir_all(parent)
    }
    .whatever("unable to remove existing component root parent")
    .field_debug("path", parent)?;

    fs::create_dir_all(parent)
        .whatever("unable to create component root parent")
        .field_debug("path", parent)
}

fn remove_component_root(root: &Path) -> SystemResult<()> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error
                .whatever("unable to inspect component root")
                .field_debug("path", root));
        }
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(root)
    } else {
        fs::remove_file(root)
    }
    .whatever("unable to remove existing component root")
    .field_debug("path", root)
}

fn component_output(component: &Component) -> ComponentOutput {
    ComponentOutput::new(
        component.id().to_string(),
        component.provides().iter().map(capability_output).collect(),
        component.claims().iter().map(claim_output).collect(),
        component.requires().iter().map(selector_output).collect(),
        component.conflicts().iter().map(selector_output).collect(),
    )
    .with_version(component.version().map(ToString::to_string))
}

fn claim_output(claim: &Claim) -> ClaimOutput {
    ClaimOutput::new(claim.id().to_string())
}

fn capability_output(capability: &Capability) -> CapabilityOutput {
    CapabilityOutput::new(capability.id().to_string())
        .with_version(capability.version().map(ToString::to_string))
        .with_value(capability.value_str().map(str::to_owned))
}

fn selector_output(selector: &CapabilitySelector) -> CapabilitySelectorOutput {
    CapabilitySelectorOutput::new(selector.id().to_string())
        .with_version(selector.version_req().map(ToString::to_string))
        .with_value(selector.value_str().map(str::to_owned))
}

fn find_component_files(root: &Path) -> SystemResult<Vec<PathBuf>> {
    let mut component_files = Vec::new();
    collect_component_files(root, &mut component_files)?;
    component_files.sort();
    Ok(component_files)
}

fn collect_component_files(root: &Path, component_files: &mut Vec<PathBuf>) -> SystemResult<()> {
    let metadata = match fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error
                .whatever("unable to inspect component root")
                .field_debug("path", root));
        }
    };
    if !metadata.is_dir() {
        return Err(whatever!("component root is not a directory").field_debug("path", root));
    }

    let entries = fs::read_dir(root)
        .whatever("unable to read component directory")
        .field_debug("path", root)?;
    for entry in entries {
        let entry = entry
            .whatever("unable to read component directory entry")
            .field_debug("path", root)?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .whatever("unable to inspect component directory entry")
            .field_debug("path", &path)?;
        if file_type.is_dir() {
            collect_component_files(&path, component_files)?;
        } else if is_component_file(&path) && is_regular_file(&path)? {
            component_files.push(path);
        }
    }

    Ok(())
}

fn read_component_file(path: &Path) -> SystemResult<Component> {
    let content = fs::read_to_string(path)
        .whatever("unable to read component file")
        .field_debug("path", path)?;
    parse_component_content(path, &content)
}

fn read_bundle_component_file(
    file: &rugix_bundle::format::BundleComponentFile,
) -> SystemResult<Component> {
    validate_bundle_component_path(&file.path)?;
    let content = str::from_utf8(&file.data.raw)
        .whatever("bundle component file is not UTF-8")
        .field_debug("path", &file.path)?;
    parse_component_content(Path::new(&file.path), content).field_debug("path", &file.path)
}

fn parse_component_content(path: &Path, content: &str) -> SystemResult<Component> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    if extension.eq_ignore_ascii_case("json") {
        serde_json::from_str(content)
            .whatever("unable to parse JSON component file")
            .field_debug("path", path)
    } else {
        toml::from_str(content)
            .whatever("unable to parse TOML component file")
            .field_debug("path", path)
    }
}

fn validate_bundle_component_path(path: &str) -> SystemResult<()> {
    let path = Path::new(path);
    if path.is_absolute() {
        bail!("bundle component path must be relative");
    }
    let mut has_component = false;
    for component in path.components() {
        let std::path::Component::Normal(part) = component else {
            bail!("invalid bundle component path: {path:?}");
        };
        if part.to_str().is_some_and(str::is_empty) {
            bail!("invalid bundle component path: {path:?}");
        }
        has_component = true;
    }
    if !has_component {
        bail!("invalid bundle component path: {path:?}");
    }
    if !is_component_file(path) {
        bail!("unsupported bundle component file extension: {path:?}");
    }
    Ok(())
}

fn is_component_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("toml") || extension.eq_ignore_ascii_case("json")
        })
}

fn is_regular_file(path: &Path) -> SystemResult<bool> {
    fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .whatever("unable to inspect component file")
        .field_debug("path", path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rugix_bundle::format::BundleComponentFile;

    #[test]
    fn loads_components_recursively_in_path_order() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join("components");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(
            root.join("z.toml"),
            r#"
id = "component.z"
version = "1.0.0"
"#,
        )
        .unwrap();
        fs::write(
            root.join("nested/a.toml"),
            r#"
id = "component.a"
"#,
        )
        .unwrap();

        let mut components = InstalledComponents {
            roots: Vec::new(),
            components: Vec::new(),
        };
        components
            .load_root(ComponentLocation::new(
                ComponentSourceKindOutput::Local,
                root,
            ))
            .unwrap();

        let ids = components
            .components
            .iter()
            .map(|component| component.component.id().as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["component.a", "component.z"]);
    }

    #[test]
    fn loads_component_claims_from_metadata() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join("components");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("app.toml"),
            r#"
id = "app.web"

[[claims]]
id = "network.tcp.8080"
"#,
        )
        .unwrap();

        let mut components = InstalledComponents {
            roots: Vec::new(),
            components: Vec::new(),
        };
        components
            .load_root(ComponentLocation::new(
                ComponentSourceKindOutput::Local,
                root,
            ))
            .unwrap();

        assert_eq!(
            components.components[0].component.claims()[0].id().as_str(),
            "network.tcp.8080"
        );
    }

    #[test]
    fn reports_duplicate_component_sources() {
        let source_a = ComponentLocation {
            kind: ComponentSourceKindOutput::Local,
            path: PathBuf::from("/etc/rugix/components/a.toml"),
            app: None,
            generation: None,
        };
        let source_b = ComponentLocation {
            kind: ComponentSourceKindOutput::Runtime,
            path: PathBuf::from("/run/rugix/components/b.toml"),
            app: None,
            generation: None,
        };
        let components = InstalledComponents {
            roots: Vec::new(),
            components: vec![
                LoadedComponent {
                    source: source_a,
                    component: Component::new("component.duplicate"),
                },
                LoadedComponent {
                    source: source_b,
                    component: Component::new("component.duplicate"),
                },
            ],
        };

        let output = components.check_output();
        assert!(!output.consistent);
        assert_eq!(output.problems.len(), 1);
        let ComponentProblemOutput::DuplicateComponent(problem) = &output.problems[0] else {
            panic!("expected duplicate component problem");
        };
        assert_eq!(problem.id, "component.duplicate");
        assert_eq!(problem.sources.len(), 2);
    }

    #[test]
    fn reports_conflict_participants_as_component_refs() {
        let provider_source = ComponentLocation {
            kind: ComponentSourceKindOutput::Local,
            path: PathBuf::from("/etc/rugix/components/provider.toml"),
            app: None,
            generation: None,
        };
        let consumer_source = ComponentLocation {
            kind: ComponentSourceKindOutput::Runtime,
            path: PathBuf::from("/run/rugix/components/consumer.toml"),
            app: None,
            generation: None,
        };
        let components = InstalledComponents {
            roots: Vec::new(),
            components: vec![
                LoadedComponent {
                    source: provider_source,
                    component: Component::new("component.provider")
                        .with_provided_capability(Capability::new("service.modbus")),
                },
                LoadedComponent {
                    source: consumer_source,
                    component: Component::new("component.consumer")
                        .with_conflict(CapabilitySelector::new("service.modbus")),
                },
            ],
        };

        let output = components.check_output();
        assert!(!output.consistent);
        assert_eq!(output.problems.len(), 1);
        let ComponentProblemOutput::Conflict(problem) = &output.problems[0] else {
            panic!("expected conflict problem");
        };
        assert_eq!(problem.component.id, "component.consumer");
        assert_eq!(
            problem
                .component
                .source
                .as_ref()
                .map(|source| source.path.as_str()),
            Some("/run/rugix/components/consumer.toml")
        );
        assert_eq!(problem.provider.id, "component.provider");
        assert_eq!(
            problem
                .provider
                .source
                .as_ref()
                .map(|source| source.path.as_str()),
            Some("/etc/rugix/components/provider.toml")
        );
    }

    #[test]
    fn reports_duplicate_claim_participants_as_component_refs() {
        let first_source = ComponentLocation {
            kind: ComponentSourceKindOutput::Local,
            path: PathBuf::from("/etc/rugix/components/first.toml"),
            app: None,
            generation: None,
        };
        let second_source = ComponentLocation {
            kind: ComponentSourceKindOutput::Runtime,
            path: PathBuf::from("/run/rugix/components/second.toml"),
            app: None,
            generation: None,
        };
        let components = InstalledComponents {
            roots: Vec::new(),
            components: vec![
                LoadedComponent {
                    source: first_source,
                    component: Component::new("component.first")
                        .with_claim(Claim::new("network.tcp.8080")),
                },
                LoadedComponent {
                    source: second_source,
                    component: Component::new("component.second")
                        .with_claim(Claim::new("network.tcp.8080")),
                },
            ],
        };

        let output = components.check_output();
        assert!(!output.consistent);
        assert_eq!(output.problems.len(), 1);
        let ComponentProblemOutput::DuplicateClaim(problem) = &output.problems[0] else {
            panic!("expected duplicate claim problem");
        };
        assert_eq!(problem.id, "network.tcp.8080");
        assert_eq!(
            problem
                .components
                .iter()
                .map(|component| component.id.as_str())
                .collect::<Vec<_>>(),
            ["component.first", "component.second"]
        );
        assert_eq!(
            problem.components[0]
                .source
                .as_ref()
                .map(|source| source.path.as_str()),
            Some("/etc/rugix/components/first.toml")
        );
        assert_eq!(
            problem.components[1]
                .source
                .as_ref()
                .map(|source| source.path.as_str()),
            Some("/run/rugix/components/second.toml")
        );
    }

    #[test]
    fn system_update_candidate_replaces_system_components() {
        let components = InstalledComponents {
            roots: vec![ComponentLocation::new(
                ComponentSourceKindOutput::System,
                "/usr/lib/rugix/components",
            )],
            components: vec![LoadedComponent {
                source: ComponentLocation {
                    kind: ComponentSourceKindOutput::System,
                    path: PathBuf::from("/usr/lib/rugix/components/os.toml"),
                    app: None,
                    generation: None,
                },
                component: Component::new("system.os"),
            }],
        };

        let output = components
            .check_system_update(&bundle_components([(
                "os.toml",
                r#"
id = "system.os"
version = "2.0.0"
"#,
            )]))
            .unwrap();

        assert!(output.consistent);
        assert_eq!(output.components.len(), 1);
        assert_eq!(output.components[0].component.id, "system.os");
        assert!(matches!(
            output.components[0].source.kind,
            ComponentSourceKindOutput::Bundle
        ));
    }

    #[test]
    fn incremental_update_candidate_replaces_declared_component_ids() {
        let components = InstalledComponents {
            roots: Vec::new(),
            components: vec![
                LoadedComponent {
                    source: ComponentLocation {
                        kind: ComponentSourceKindOutput::System,
                        path: PathBuf::from("/usr/lib/rugix/components/runtime.toml"),
                        app: None,
                        generation: None,
                    },
                    component: Component::new("runtime.container"),
                },
                LoadedComponent {
                    source: ComponentLocation {
                        kind: ComponentSourceKindOutput::App,
                        path: PathBuf::from(
                            "/data/apps/foo/generations/1/.rugix/components/app.toml",
                        ),
                        app: Some("foo".to_owned()),
                        generation: Some(1),
                    },
                    component: Component::new("app.foo"),
                },
            ],
        };

        let output = components
            .check_incremental_update(&bundle_components([(
                "runtime.toml",
                r#"
id = "runtime.container"
version = "2.0.0"
"#,
            )]))
            .unwrap();

        assert!(output.consistent);
        assert_eq!(
            output
                .components
                .iter()
                .map(|component| component.component.id.as_str())
                .collect::<Vec<_>>(),
            ["app.foo", "runtime.container"]
        );
        assert!(matches!(
            output.components[1].source.kind,
            ComponentSourceKindOutput::Bundle
        ));
    }

    #[test]
    fn app_update_candidate_replaces_touched_app_components() {
        let components = InstalledComponents {
            roots: Vec::new(),
            components: vec![
                LoadedComponent {
                    source: ComponentLocation {
                        kind: ComponentSourceKindOutput::App,
                        path: PathBuf::from(
                            "/data/apps/foo/generations/1/.rugix/components/app.toml",
                        ),
                        app: Some("foo".to_owned()),
                        generation: Some(1),
                    },
                    component: Component::new("app.foo"),
                },
                LoadedComponent {
                    source: ComponentLocation {
                        kind: ComponentSourceKindOutput::App,
                        path: PathBuf::from(
                            "/data/apps/bar/generations/1/.rugix/components/app.toml",
                        ),
                        app: Some("bar".to_owned()),
                        generation: Some(1),
                    },
                    component: Component::new("app.bar"),
                },
            ],
        };

        let output = components
            .check_app_update(
                &["foo".to_owned()],
                Some(&bundle_components([(
                    "app.toml",
                    r#"
id = "app.foo"
version = "2.0.0"
"#,
                )])),
            )
            .unwrap();

        assert!(output.consistent);
        assert_eq!(
            output
                .components
                .iter()
                .map(|component| component.component.id.as_str())
                .collect::<Vec<_>>(),
            ["app.bar", "app.foo"]
        );
        assert!(matches!(
            output.components[1].source.kind,
            ComponentSourceKindOutput::Bundle
        ));
    }

    #[test]
    fn app_update_without_bundle_components_removes_touched_app_components() {
        let components = InstalledComponents {
            roots: Vec::new(),
            components: vec![
                LoadedComponent {
                    source: ComponentLocation {
                        kind: ComponentSourceKindOutput::App,
                        path: PathBuf::from(
                            "/data/apps/foo/generations/1/.rugix/components/app.toml",
                        ),
                        app: Some("foo".to_owned()),
                        generation: Some(1),
                    },
                    component: Component::new("app.foo"),
                },
                LoadedComponent {
                    source: ComponentLocation {
                        kind: ComponentSourceKindOutput::App,
                        path: PathBuf::from(
                            "/data/apps/bar/generations/1/.rugix/components/app.toml",
                        ),
                        app: Some("bar".to_owned()),
                        generation: Some(1),
                    },
                    component: Component::new("app.bar"),
                },
            ],
        };

        let output = components
            .check_app_update(&["foo".to_owned()], None)
            .unwrap();

        assert!(output.consistent);
        assert_eq!(output.components.len(), 1);
        assert_eq!(output.components[0].component.id, "app.bar");
    }

    #[test]
    fn app_removal_candidate_removes_active_app_components() {
        let components = InstalledComponents {
            roots: Vec::new(),
            components: vec![
                LoadedComponent {
                    source: ComponentLocation {
                        kind: ComponentSourceKindOutput::App,
                        path: PathBuf::from(
                            "/data/apps/foo/generations/1/.rugix/components/app.toml",
                        ),
                        app: Some("foo".to_owned()),
                        generation: Some(1),
                    },
                    component: Component::new("app.foo"),
                },
                LoadedComponent {
                    source: ComponentLocation {
                        kind: ComponentSourceKindOutput::App,
                        path: PathBuf::from(
                            "/data/apps/bar/generations/1/.rugix/components/app.toml",
                        ),
                        app: Some("bar".to_owned()),
                        generation: Some(1),
                    },
                    component: Component::new("app.bar"),
                },
            ],
        };

        let output = components.check_app_removal("foo");

        assert!(output.consistent);
        assert_eq!(output.components.len(), 1);
        assert_eq!(output.components[0].component.id, "app.bar");
    }

    #[test]
    fn app_generation_candidate_replaces_active_app_components() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join(".rugix/components");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("app.toml"),
            r#"
id = "app.foo"
version = "2.0.0"
"#,
        )
        .unwrap();
        let components = InstalledComponents {
            roots: Vec::new(),
            components: vec![
                LoadedComponent {
                    source: ComponentLocation {
                        kind: ComponentSourceKindOutput::App,
                        path: PathBuf::from(
                            "/data/apps/foo/generations/1/.rugix/components/app.toml",
                        ),
                        app: Some("foo".to_owned()),
                        generation: Some(1),
                    },
                    component: Component::new("app.foo"),
                },
                LoadedComponent {
                    source: ComponentLocation {
                        kind: ComponentSourceKindOutput::App,
                        path: PathBuf::from(
                            "/data/apps/bar/generations/1/.rugix/components/app.toml",
                        ),
                        app: Some("bar".to_owned()),
                        generation: Some(1),
                    },
                    component: Component::new("app.bar"),
                },
            ],
        };

        let output = components.check_app_generation("foo", 2, root).unwrap();

        assert!(output.consistent);
        assert_eq!(
            output
                .components
                .iter()
                .map(|component| component.component.id.as_str())
                .collect::<Vec<_>>(),
            ["app.bar", "app.foo"]
        );
        assert!(matches!(
            output.components[1].source.kind,
            ComponentSourceKindOutput::App
        ));
        assert_eq!(output.components[1].source.generation, Some(2));
    }

    #[test]
    fn synthetic_host_component_provides_basic_host_facts() {
        let component = synthetic_host_component();
        assert_eq!(component.id().as_str(), "rugix.host");
        assert!(component.provides().iter().any(|capability| {
            capability.id().as_str() == "host.arch"
                && capability.value_str() == Some(std::env::consts::ARCH)
        }));
        assert!(component.provides().iter().any(|capability| {
            capability.id().as_str() == "rugix.ctrl"
                && (capability.version().is_some() || capability.value_str().is_some())
        }));
    }

    #[test]
    fn rugix_ctrl_capability_prefers_parseable_versions() {
        let capability = rugix_ctrl_capability("1.2.3");
        assert_eq!(capability.id().as_str(), "rugix.ctrl");
        assert_eq!(
            capability.version().map(ToString::to_string).as_deref(),
            Some("1.2.3")
        );
        assert_eq!(capability.value_str(), None);
    }

    #[test]
    fn rugix_ctrl_capability_strips_tag_version_prefix() {
        let capability = rugix_ctrl_capability("v1.2.3");
        assert_eq!(capability.id().as_str(), "rugix.ctrl");
        assert_eq!(
            capability.version().map(ToString::to_string).as_deref(),
            Some("1.2.3")
        );
        assert_eq!(capability.value_str(), None);
    }

    #[test]
    fn rugix_ctrl_capability_falls_back_to_value_for_unparseable_versions() {
        let capability = rugix_ctrl_capability("unknown");
        assert_eq!(capability.id().as_str(), "rugix.ctrl");
        assert_eq!(capability.version(), None);
        assert_eq!(capability.value_str(), Some("unknown"));
    }

    #[test]
    fn synthetic_components_are_reported_with_synthetic_source() {
        let mut components = InstalledComponents {
            roots: Vec::new(),
            components: Vec::new(),
        };
        components.load_synthetic_components();

        let output = components.output();
        assert_eq!(output.roots.len(), 1);
        assert!(matches!(
            output.roots[0].kind,
            ComponentSourceKindOutput::Synthetic
        ));
        assert_eq!(output.components.len(), 1);
        assert!(matches!(
            output.components[0].source.kind,
            ComponentSourceKindOutput::Synthetic
        ));
    }

    #[test]
    fn writes_bundle_components_to_component_root() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join(".rugix/components");

        write_bundle_components(
            &bundle_components([("nested/app.toml", "id = \"app.foo\"\n")]),
            &root,
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(root.join("nested/app.toml")).unwrap(),
            "id = \"app.foo\"\n"
        );
    }

    #[test]
    fn rejects_duplicate_bundle_component_paths_when_writing() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join(".rugix/components");
        let error = write_bundle_components(
            &bundle_components([
                ("app.toml", "id = \"app.foo\"\n"),
                ("app.toml", "id = \"app.bar\"\n"),
            ]),
            &root,
        )
        .unwrap_err();

        assert!(format!("{error:?}").contains("duplicate bundle component"));
    }

    #[test]
    fn failed_bundle_component_validation_does_not_remove_existing_root() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join(".rugix/components");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("existing.toml"), "id = \"existing\"\n").unwrap();

        let error = write_bundle_components(
            &bundle_components([("../invalid.toml", "id = \"invalid\"\n")]),
            &root,
        )
        .unwrap_err();

        assert!(format!("{error:?}").contains("invalid bundle component path"));
        assert_eq!(
            fs::read_to_string(root.join("existing.toml")).unwrap(),
            "id = \"existing\"\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bundle_component_writer_replaces_symlinked_parent_directory() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().unwrap();
        let generation_dir = tempdir.path().join("generation");
        let symlink_target = tempdir.path().join("outside");
        fs::create_dir_all(&generation_dir).unwrap();
        fs::create_dir_all(symlink_target.join("components")).unwrap();
        fs::write(
            symlink_target.join("components/outside.toml"),
            "id = \"outside\"\n",
        )
        .unwrap();
        symlink(&symlink_target, generation_dir.join(".rugix")).unwrap();

        let root = generation_dir.join(".rugix/components");
        write_bundle_components(
            &bundle_components([("app.toml", "id = \"app.foo\"\n")]),
            &root,
        )
        .unwrap();

        let rugix_metadata = fs::symlink_metadata(generation_dir.join(".rugix")).unwrap();
        assert!(rugix_metadata.is_dir());
        assert!(!rugix_metadata.file_type().is_symlink());
        assert_eq!(
            fs::read_to_string(root.join("app.toml")).unwrap(),
            "id = \"app.foo\"\n"
        );
        assert_eq!(
            fs::read_to_string(symlink_target.join("components/outside.toml")).unwrap(),
            "id = \"outside\"\n"
        );
    }

    fn bundle_components<const N: usize>(files: [(&str, &str); N]) -> BundleComponents {
        BundleComponents::new(
            files
                .into_iter()
                .map(|(path, data)| BundleComponentFile::new(path, data.as_bytes().to_vec()))
                .collect(),
        )
    }
}
