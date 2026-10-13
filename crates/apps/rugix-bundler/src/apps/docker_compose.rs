//! Package Compose apps and their container images into self-contained Rugix bundles.
//!
//! [`pack`] resolves image sources, packages archives, and rewrites Compose services
//! to use the bundled images.

use std::collections::BTreeMap;
use std::fs::File;
use std::fs::{self};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use reportify::bail;
use reportify::ResultExt;
use rugix_bundle::manifest::compose::ImageMetadata;
use rugix_bundle::manifest::compose::ImageMetadataEntry;
use rugix_bundle::manifest::compose::ImageOptions as RugixImageOptions;
use rugix_bundle::manifest::compose::ImageSourceKind;
use rugix_bundle::manifest::is_valid_environment_variable_name;
use rugix_bundle::manifest::is_valid_json_pointer;
use rugix_bundle::manifest::AppArchiveDeliveryConfig;
use rugix_bundle::manifest::AppFileDeliveryConfig;
use rugix_bundle::manifest::AppHealthCheckConfig;
use rugix_bundle::manifest::AppManifest;
use rugix_bundle::manifest::DeliveryConfig;
use rugix_bundle::manifest::DockerComposeConfig;
use rugix_bundle::manifest::Payload;
use rugix_bundle::BundleResult;
use serde::Deserialize;
use tracing::info;

use super::app_block_encoding;
use super::finalize_bundle;
use super::stage_component_files;
use super::tar_append_app_toml;
use super::tar_append_bytes;
use super::tar_append_includes;
use super::tar_append_metadata;

/// Pack a Docker Compose app into an app bundle.
///
/// Creates a bundle with:
/// - An `app-archive` payload containing `app.toml`, a rewritten `docker-compose.yml`,
///   image metadata, and any extra included files/directories. Bundled services are
///   rewritten to Rugix-owned bundle-local image tags with `pull_policy: never`.
/// - An `app-file` payload per Docker image, placed at `images/image-N.tar` inside the
///   generation directory.
#[tracing::instrument(skip_all, fields(app = %cmd.app))]
pub fn pack(cmd: &crate::PackDockerComposeCmd) -> BundleResult<()> {
    rugix_bundle::manifest::validate_app_name(&cmd.app)?;
    let bundle_dir = tempfile::TempDir::new().whatever("unable to create temp directory")?;
    let payloads_dir = bundle_dir.path().join("payloads");
    fs::create_dir_all(&payloads_dir).whatever("unable to create payloads directory")?;

    let block_encoding = app_block_encoding();

    let (compose_content, images) = if cmd.disable_image_bundling {
        (
            fs::read_to_string(&cmd.compose_file).whatever("unable to read Docker Compose file")?,
            Vec::new(),
        )
    } else {
        let mut compose = load_compose(&cmd.compose_file)?;
        let mut images = plan_compose_images(&compose, &cmd.compose_file, &cmd.app)?;
        package_images(&mut images, cmd, &payloads_dir)?;
        if !images.is_empty() {
            rewrite_compose_images(&mut compose, &images, cmd.disable_pinning)?;
        }
        (serialize_compose(&compose)?, images)
    };
    let image_metadata = if !images.is_empty() {
        Some(image_metadata(&images, cmd.platform.as_deref())?)
    } else {
        None
    };

    let archive_path = payloads_dir.join("base.tar");
    {
        let archive_file = File::create(&archive_path).whatever("unable to create base.tar")?;
        let mut archive = tar::Builder::new(archive_file);
        let manifest = {
            let mut m = AppManifest::new("docker-compose".to_owned());
            if let Some(timeout) = cmd.health_check_timeout {
                m = m.with_health_check(Some(
                    AppHealthCheckConfig::new().with_timeout(Some(timeout)),
                ));
            }
            m = super::append_configuration(&mut archive, m, &cmd.configuration)?;
            let environment = parse_configuration_environment(&cmd.configuration_environment)?;
            if !environment.is_empty() {
                m = m.with_docker_compose(Some(
                    DockerComposeConfig::new().with_environment(Some(
                        environment
                            .into_iter()
                            .map(|(key, value)| (key.into(), value.into()))
                            .collect::<BTreeMap<_, _>>(),
                    )),
                ));
            }
            m
        };
        tar_append_app_toml(&mut archive, &manifest)?;
        tar_append_bytes(
            &mut archive,
            "docker-compose.yml",
            compose_content.as_bytes(),
        )?;
        if let Some(image_metadata) = &image_metadata {
            let metadata = serde_json::to_vec_pretty(image_metadata)
                .whatever("unable to serialize image metadata")?;
            tar_append_bytes(&mut archive, "images/rugix-images.json", &metadata)?;
        }
        tar_append_includes(&mut archive, &cmd.includes)?;
        tar_append_metadata(&mut archive, cmd.metadata_file.as_deref())?;
        archive.finish().whatever("unable to finish archive")?;
    }
    stage_component_files(bundle_dir.path(), &cmd.components)?;

    let mut payloads = vec![Payload {
        delivery: DeliveryConfig::AppArchive(AppArchiveDeliveryConfig::new(cmd.app.clone())),
        filename: "base.tar".to_owned().into(),
        block_encoding: block_encoding.clone(),
        delta_encoding: None,
    }];

    for image in &images {
        payloads.push(Payload {
            delivery: DeliveryConfig::AppFile(AppFileDeliveryConfig::new(
                cmd.app.clone(),
                image.app_path.clone(),
            )),
            filename: image.payload_filename.clone().into(),
            block_encoding: block_encoding.clone(),
            delta_encoding: None,
        });
    }

    finalize_bundle(bundle_dir.path(), &cmd.output, &cmd.app, payloads)
}

/// Parse Compose environment projections from `NAME=JSON_POINTER` arguments.
fn parse_configuration_environment(mappings: &[String]) -> BundleResult<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    for mapping in mappings {
        let Some((name, pointer)) = mapping.split_once('=') else {
            bail!("configuration environment mapping must use NAME=JSON_POINTER syntax");
        };
        validate_environment_name(name)?;
        if !is_valid_json_pointer(pointer) {
            bail!("configuration environment mapping for {name} is not a JSON Pointer");
        }
        if environment
            .insert(name.to_owned(), pointer.to_owned())
            .is_some()
        {
            bail!("duplicate configuration environment mapping for {name}");
        }
    }
    Ok(environment)
}

/// Validate a Compose environment variable name.
fn validate_environment_name(name: &str) -> BundleResult<()> {
    if name.is_empty() {
        bail!("configuration environment variable name must not be empty");
    }
    if name.starts_with("RUGIX_") {
        bail!("configuration environment variable name {name:?} is reserved");
    }
    if !is_valid_environment_variable_name(name) {
        bail!("invalid configuration environment variable name {name:?}");
    }
    Ok(())
}
#[derive(Debug, Clone)]
struct PlannedImage {
    service: String,
    source: ImageSourceKind,
    source_ref: String,
    original_image: Option<String>,
    build: Option<BuildConfig>,
    app_path: String,
    payload_filename: String,
    bundle_tag: Option<String>,
    source_digest: Option<String>,
    image_id: Option<String>,
}

#[derive(Debug, Clone)]
struct BuildConfig {
    context: PathBuf,
    dockerfile: Option<PathBuf>,
    target: Option<String>,
    args: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodmanStoreInfo {
    graph_driver_name: String,
    graph_root: String,
    run_root: String,
}

/// Export each planned image and record its packaged tag and provenance.
#[tracing::instrument(level = "debug", skip_all, fields(image_count = images.len()))]
fn package_images(
    images: &mut [PlannedImage],
    cmd: &crate::PackDockerComposeCmd,
    payloads_dir: &Path,
) -> BundleResult<()> {
    if images.is_empty() {
        return Ok(());
    }
    if !has_skopeo() {
        bail!("skopeo is required to bundle Docker Compose images; install skopeo or pass --disable-image-bundling");
    }
    for (index, image) in images.iter_mut().enumerate() {
        let output = payloads_dir.join(&image.payload_filename);
        match image.source {
            ImageSourceKind::Registry => {
                let (repository, digest) =
                    resolve_registry_digest(&image.source_ref, cmd.platform.as_deref())?;
                let bundle_tag =
                    packaged_image_tag(&cmd.app, index, 'm', &digest, image, cmd.disable_pinning);
                let source = format!("docker://{repository}@{digest}");
                skopeo_copy_to_docker_archive(
                    &source,
                    &output,
                    &bundle_tag,
                    cmd.platform.as_deref(),
                )?;
                image.bundle_tag = Some(bundle_tag);
                image.source_digest = Some(digest);
            }
            ImageSourceKind::DockerArchive => {
                if cmd.disable_pinning && image.original_image.is_none() {
                    bail!("archive source requires a Compose image tag when pinning is disabled");
                }
                let source = format!("docker-archive:{}", image.source_ref);
                let digest = inspect_image_digest(&source, cmd.platform.as_deref())?;
                let bundle_tag =
                    packaged_image_tag(&cmd.app, index, 'm', &digest, image, cmd.disable_pinning);
                skopeo_copy_to_docker_archive(
                    &source,
                    &output,
                    &bundle_tag,
                    cmd.platform.as_deref(),
                )?;
                image.bundle_tag = Some(bundle_tag);
                image.source_digest = Some(digest);
            }
            ImageSourceKind::Build => {
                let Some(build) = image.build.clone() else {
                    bail!("build image is missing its build configuration");
                };
                let local_source = build_compose_image(
                    image,
                    &build,
                    cmd.builder,
                    cmd.platform.as_deref(),
                    cmd.pull,
                )?;
                let image_id = inspect_local_image_id(local_source, &image.source_ref)?;
                let bundle_tag =
                    packaged_image_tag(&cmd.app, index, 'c', &image_id, image, cmd.disable_pinning);
                let source = local_skopeo_source_ref(local_source, &image.source_ref)?;
                skopeo_copy_to_docker_archive(
                    &source,
                    &output,
                    &bundle_tag,
                    cmd.platform.as_deref(),
                )?;
                image.bundle_tag = Some(bundle_tag);
                image.image_id = Some(image_id);
            }
            ImageSourceKind::ContainersStorage | ImageSourceKind::DockerDaemon => {
                let image_id = inspect_local_image_id(image.source, &image.source_ref)?;
                let bundle_tag =
                    packaged_image_tag(&cmd.app, index, 'c', &image_id, image, cmd.disable_pinning);
                let source = local_skopeo_source_ref(image.source, &image.source_ref)?;
                skopeo_copy_to_docker_archive(
                    &source,
                    &output,
                    &bundle_tag,
                    cmd.platform.as_deref(),
                )?;
                image.bundle_tag = Some(bundle_tag);
                image.image_id = Some(image_id);
            }
        }
    }
    Ok(())
}

fn plan_compose_images(
    compose: &serde_yaml_ng::Value,
    compose_path: &Path,
    app: &str,
) -> BundleResult<Vec<PlannedImage>> {
    let serde_yaml_ng::Value::Mapping(root) = compose else {
        bail!("Docker Compose file must contain a YAML mapping");
    };
    let Some(serde_yaml_ng::Value::Mapping(services)) = mapping_get(root, "services") else {
        bail!("Docker Compose file must contain a `services` mapping");
    };
    let base_dir = compose_base_dir(compose_path);
    let mut images = Vec::new();
    for (service_name, service) in services {
        let service_name = yaml_string(service_name, "service name")?.to_owned();
        let serde_yaml_ng::Value::Mapping(service) = service else {
            bail!("service `{service_name}` must be a mapping");
        };
        let original_image = optional_yaml_string(mapping_get(service, "image"), "service image")?;
        let build = mapping_get(service, "build")
            .map(|build| parse_build_config(build, base_dir, &service_name))
            .transpose()?;
        let rugix_options = parse_x_rugix_options(&service_name, service)?;
        let (source, source_ref, build) = if let Some(build) = build {
            if let Some(options) = &rugix_options {
                if options.source.is_some() || options.source_ref.is_some() {
                    bail!("service `{service_name}` uses `build:`; remove x-rugix.image overrides");
                }
            }
            let source_ref = original_image
                .clone()
                .unwrap_or_else(|| generated_build_ref(app, &service_name));
            (ImageSourceKind::Build, source_ref, Some(build))
        } else {
            let source = rugix_options
                .as_ref()
                .and_then(|options| options.source)
                .unwrap_or(ImageSourceKind::Registry);
            let archive_ref = rugix_options
                .as_ref()
                .and_then(|options| options.source_ref.clone());
            let source_ref = if source == ImageSourceKind::DockerArchive {
                let Some(path) = archive_ref else {
                    bail!("service `{service_name}` requires x-rugix.image.ref for docker-archive");
                };
                if path.is_empty() || path.contains(':') {
                    bail!("archive path for service `{service_name}` must be nonempty and contain no colon");
                }
                Some(
                    resolve_compose_path(base_dir, &path)
                        .to_string_lossy()
                        .into_owned(),
                )
            } else {
                archive_ref
                    .or_else(|| original_image.clone().map(Into::into))
                    .map(Into::into)
            };
            let Some(source_ref) = source_ref else {
                bail!("service `{service_name}` needs an `image` or x-rugix.image.ref to bundle");
            };
            (source, source_ref, None)
        };
        let payload_filename = image_payload_filename(images.len());
        images.push(PlannedImage {
            service: service_name,
            source,
            source_ref,
            original_image,
            build,
            app_path: format!("images/{payload_filename}"),
            payload_filename,
            bundle_tag: None,
            source_digest: None,
            image_id: None,
        });
    }
    Ok(images)
}

fn build_compose_image(
    image: &PlannedImage,
    build: &BuildConfig,
    builder: crate::ImageBuilder,
    platform: Option<&str>,
    pull: bool,
) -> BundleResult<ImageSourceKind> {
    let (builder_name, local_source) = match builder {
        crate::ImageBuilder::Podman => ("podman", ImageSourceKind::ContainersStorage),
        crate::ImageBuilder::Docker => ("docker", ImageSourceKind::DockerDaemon),
    };
    let mut cmd = Command::new(builder_name);
    cmd.arg("build");
    if let Some(platform) = platform {
        cmd.arg("--platform").arg(platform);
    }
    if pull {
        cmd.arg("--pull");
    }
    cmd.arg("-t").arg(&image.source_ref);
    if let Some(dockerfile) = &build.dockerfile {
        cmd.arg("-f").arg(dockerfile);
    }
    if let Some(target) = &build.target {
        cmd.arg("--target").arg(target);
    }
    for arg in &build.args {
        cmd.arg("--build-arg").arg(arg);
    }
    cmd.arg(&build.context);
    info!(
        service = %image.service,
        source_ref = %image.source_ref,
        builder = builder_name,
        context = ?build.context,
        ?platform,
        "building Compose image"
    );
    command_status(cmd, &format!("{builder_name} build {}", image.source_ref))?;
    Ok(local_source)
}

fn rewrite_compose_images(
    compose: &mut serde_yaml_ng::Value,
    images: &[PlannedImage],
    disable_pinning: bool,
) -> BundleResult<()> {
    let serde_yaml_ng::Value::Mapping(root) = compose else {
        bail!("Docker Compose file must contain a YAML mapping");
    };
    let Some(serde_yaml_ng::Value::Mapping(services)) = mapping_get_mut(root, "services") else {
        bail!("Docker Compose file must contain a `services` mapping");
    };
    for image in images {
        let Some(bundle_tag) = image.bundle_tag.as_ref() else {
            bail!("image was not packaged before Compose rewrite");
        };
        let service_key = yaml_key(&image.service);
        let Some(serde_yaml_ng::Value::Mapping(service)) = services.get_mut(&service_key) else {
            bail!(
                "service `{}` disappeared during Compose rewrite",
                image.service
            );
        };
        if disable_pinning {
            let image_ref = image.original_image.as_ref().unwrap_or(bundle_tag);
            mapping_insert_string(service, "image", image_ref);
        } else {
            mapping_insert_string(service, "image", bundle_tag);
        }
        mapping_insert_string(service, "pull_policy", "never");
        mapping_remove(service, "build");
        mapping_remove(service, "x-rugix");
    }
    Ok(())
}

fn image_metadata(images: &[PlannedImage], platform: Option<&str>) -> BundleResult<ImageMetadata> {
    let mut entries = Vec::new();
    for image in images {
        let Some(bundle_tag) = image.bundle_tag.clone() else {
            bail!("image was not packaged before metadata generation");
        };
        entries.push(ImageMetadataEntry {
            service: image.service.clone().into(),
            source: image.source,
            source_ref: image.source_ref.clone().into(),
            original_image: image.original_image.clone().map(Into::into),
            bundle_tag: bundle_tag.into(),
            source_digest: image.source_digest.clone().map(Into::into),
            image_id: image.image_id.clone().map(Into::into),
            payload: image.app_path.clone().into(),
            platform: platform.map(str::to_owned).map(Into::into),
        });
    }
    Ok(ImageMetadata {
        schema_version: 1,
        images: entries.into(),
    })
}

fn resolve_registry_digest(image: &str, platform: Option<&str>) -> BundleResult<(String, String)> {
    if let Some((repository, digest)) = image.split_once('@') {
        if !digest.starts_with("sha256:") {
            bail!("only sha256 registry digests are supported for {image}");
        }
        return Ok((image_repository(repository).to_owned(), digest.to_owned()));
    }
    let digest = inspect_image_digest(&format!("docker://{image}"), platform)?;
    Ok((image_repository(image).to_owned(), digest))
}

/// Inspect a registry or archive manifest without requiring a container daemon.
#[tracing::instrument(level = "debug", skip_all, fields(platform))]
fn inspect_image_digest(source: &str, platform: Option<&str>) -> BundleResult<String> {
    let mut cmd = skopeo_command();
    cmd.args(["inspect", "--format", "{{.Digest}}"]);
    add_platform_overrides(&mut cmd, platform);
    cmd.arg(source);
    let digest = command_output(cmd, &format!("skopeo inspect {source}"))?;
    if !digest.starts_with("sha256:") {
        bail!("skopeo inspect did not return a valid digest for {source}: {digest}");
    }
    Ok(digest)
}

/// Honor the caller's temporary directory, including Nix build sandboxes.
fn skopeo_command() -> Command {
    let mut cmd = Command::new("skopeo");
    cmd.arg("--tmpdir").arg(std::env::temp_dir());
    cmd
}

/// Export an image under the tag used by the packaged Compose service.
#[tracing::instrument(level = "debug", skip_all, fields(platform))]
fn skopeo_copy_to_docker_archive(
    source: &str,
    output: &Path,
    bundle_tag: &str,
    platform: Option<&str>,
) -> BundleResult<()> {
    let mut cmd = skopeo_command();
    cmd.arg("copy");
    // App pack commands reserve stdout for the bundle hash.
    cmd.stdout(Stdio::from(std::io::stderr()));
    add_platform_overrides(&mut cmd, platform);
    cmd.arg(source);
    cmd.arg(format!("docker-archive:{}:{bundle_tag}", output.display()));
    info!(source, output = ?output, bundle_tag, ?platform, "copying image with skopeo");
    command_status(cmd, &format!("skopeo copy {source}"))
}

fn inspect_local_image_id(source: ImageSourceKind, image: &str) -> BundleResult<String> {
    let mut cmd = match source {
        ImageSourceKind::ContainersStorage => {
            let mut cmd = Command::new("podman");
            cmd.args(["image", "inspect", "--format", "{{.Id}}"]);
            cmd
        }
        ImageSourceKind::DockerDaemon => {
            let mut cmd = Command::new("docker");
            cmd.args(["image", "inspect", "--format", "{{.Id}}"]);
            cmd
        }
        ImageSourceKind::Registry | ImageSourceKind::Build | ImageSourceKind::DockerArchive => {
            bail!("cannot inspect local image id for {:?}", source)
        }
    };
    cmd.arg(image);
    let image_id = command_output(cmd, &format!("inspect image {image}"))?;
    if image_id.is_empty() {
        bail!("image inspect returned an empty image id for {image}");
    }
    Ok(image_id)
}

fn local_skopeo_source_ref(source: ImageSourceKind, image: &str) -> BundleResult<String> {
    match source {
        ImageSourceKind::ContainersStorage => containers_storage_source_ref(image),
        ImageSourceKind::DockerDaemon => Ok(format!("docker-daemon:{image}")),
        ImageSourceKind::Registry | ImageSourceKind::Build | ImageSourceKind::DockerArchive => {
            bail!("image source {:?} is not a local image transport", source)
        }
    }
}

fn containers_storage_source_ref(image: &str) -> BundleResult<String> {
    let info = podman_store_info()?;
    Ok(format!(
        "containers-storage:[{}@{}+{}]{}",
        info.graph_driver_name, info.graph_root, info.run_root, image
    ))
}

fn parse_build_config(
    value: &serde_yaml_ng::Value,
    base_dir: &Path,
    service: &str,
) -> BundleResult<BuildConfig> {
    match value {
        serde_yaml_ng::Value::String(context) => Ok(BuildConfig {
            context: resolve_compose_path(base_dir, context),
            dockerfile: None,
            target: None,
            args: Vec::new(),
        }),
        serde_yaml_ng::Value::Mapping(mapping) => {
            let context = optional_yaml_string(
                mapping_get(mapping, "context"),
                &format!("build context for service `{service}`"),
            )?
            .unwrap_or_else(|| ".".to_owned());
            let context = resolve_compose_path(base_dir, &context);
            let dockerfile = optional_yaml_string(
                mapping_get(mapping, "dockerfile"),
                &format!("build dockerfile for service `{service}`"),
            )?
            .map(|dockerfile| {
                let dockerfile = PathBuf::from(dockerfile);
                if dockerfile.is_absolute() {
                    dockerfile
                } else {
                    context.join(dockerfile)
                }
            });
            Ok(BuildConfig {
                context,
                dockerfile,
                target: optional_yaml_string(
                    mapping_get(mapping, "target"),
                    &format!("build target for service `{service}`"),
                )?,
                args: parse_build_args(mapping_get(mapping, "args"))?,
            })
        }
        _ => bail!("build config for service `{service}` must be a string or mapping"),
    }
}

/// Parse source names while preserving the existing underscore aliases.
fn parse_image_source(value: &str) -> BundleResult<ImageSourceKind> {
    match value {
        "registry" => Ok(ImageSourceKind::Registry),
        "containers-storage" | "containers_storage" => Ok(ImageSourceKind::ContainersStorage),
        "docker-daemon" | "docker_daemon" => Ok(ImageSourceKind::DockerDaemon),
        "docker-archive" => Ok(ImageSourceKind::DockerArchive),
        "build" => bail!("Compose builds are inferred from service `build:` entries"),
        _ => bail!("unsupported Rugix image source `{value}`"),
    }
}

fn parse_x_rugix_options(
    service: &str,
    service_mapping: &serde_yaml_ng::Mapping,
) -> BundleResult<Option<RugixImageOptions>> {
    let Some(x_rugix) = mapping_get(service_mapping, "x-rugix") else {
        return Ok(None);
    };
    let serde_yaml_ng::Value::Mapping(x_rugix) = x_rugix else {
        bail!("x-rugix for service `{service}` must be a mapping");
    };
    let Some(image) = mapping_get(x_rugix, "image") else {
        return Ok(None);
    };
    let serde_yaml_ng::Value::Mapping(image) = image else {
        bail!("x-rugix.image for service `{service}` must be a mapping");
    };
    let source = optional_yaml_string(
        mapping_get(image, "source"),
        &format!("x-rugix.image.source for service `{service}`"),
    )?
    .map(|source| parse_image_source(&source))
    .transpose()?;
    let source_ref = optional_yaml_string(
        mapping_get(image, "ref"),
        &format!("x-rugix.image.ref for service `{service}`"),
    )?;
    Ok(Some(RugixImageOptions {
        source,
        source_ref: source_ref.map(Into::into),
    }))
}

fn parse_build_args(value: Option<&serde_yaml_ng::Value>) -> BundleResult<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    match value {
        serde_yaml_ng::Value::Mapping(mapping) => {
            let mut args = Vec::new();
            for (key, value) in mapping {
                let key = yaml_string(key, "build arg key")?;
                if matches!(value, serde_yaml_ng::Value::Null) {
                    args.push(key.to_owned());
                } else {
                    args.push(format!(
                        "{key}={}",
                        yaml_scalar_to_string(value, "build arg value")?
                    ));
                }
            }
            Ok(args)
        }
        serde_yaml_ng::Value::Sequence(sequence) => {
            let mut args = Vec::new();
            for value in sequence {
                args.push(yaml_string(value, "build arg")?.to_owned());
            }
            Ok(args)
        }
        _ => bail!("build args must be a mapping or sequence"),
    }
}

fn podman_store_info() -> BundleResult<PodmanStoreInfo> {
    let mut cmd = Command::new("podman");
    cmd.args(["info", "--format", "{{json .Store}}"]);
    let output = command_output(cmd, "podman info")?;
    let info: PodmanStoreInfo =
        serde_json::from_str(&output).whatever("unable to parse podman storage info")?;
    if info.graph_driver_name.is_empty() || info.graph_root.is_empty() || info.run_root.is_empty() {
        bail!("podman storage info is incomplete");
    }
    Ok(info)
}

fn load_compose(compose_path: &Path) -> BundleResult<serde_yaml_ng::Value> {
    let content =
        fs::read_to_string(compose_path).whatever("unable to read Docker Compose file")?;
    serde_yaml_ng::from_str(&content).whatever("unable to parse Docker Compose file")
}

fn serialize_compose(compose: &serde_yaml_ng::Value) -> BundleResult<String> {
    serde_yaml_ng::to_string(compose).whatever("unable to serialize Docker Compose file")
}

fn has_skopeo() -> bool {
    Command::new("skopeo")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn command_output(mut cmd: Command, action: &str) -> BundleResult<String> {
    let output = cmd
        .output()
        .whatever_with(|_| format!("unable to run {action}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{action} failed: {}", stderr.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn command_status(mut cmd: Command, action: &str) -> BundleResult<()> {
    let status = cmd
        .status()
        .whatever_with(|_| format!("unable to run {action}"))?;
    if !status.success() {
        bail!("{action} failed");
    }
    Ok(())
}

fn packaged_image_tag(
    app: &str,
    index: usize,
    prefix: char,
    content_id: &str,
    image: &PlannedImage,
    disable_pinning: bool,
) -> String {
    if disable_pinning {
        unpinned_archive_tag(image)
    } else {
        bundle_local_tag(app, index, prefix, content_id)
    }
}

fn bundle_local_tag(app: &str, index: usize, prefix: char, content_id: &str) -> String {
    format!(
        "localhost/rugix-apps/{app}/image-{index}:{prefix}-{}",
        digest_hex(content_id)
    )
}

fn unpinned_archive_tag(image: &PlannedImage) -> String {
    image
        .original_image
        .clone()
        .unwrap_or_else(|| image.source_ref.clone())
}

fn generated_build_ref(app: &str, service: &str) -> String {
    format!(
        "localhost/rugix-build/{app}/{}:latest",
        service_slug(service)
    )
}

fn image_payload_filename(index: usize) -> String {
    format!("image-{index}.tar")
}

fn image_repository(image: &str) -> &str {
    let image = image.split_once('@').map(|(repo, _)| repo).unwrap_or(image);
    let after_slash = image.rfind('/').map(|i| i + 1).unwrap_or(0);
    match image[after_slash..].rfind(':') {
        Some(pos) => &image[..after_slash + pos],
        None => image,
    }
}

fn digest_hex(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

fn service_slug(service: &str) -> String {
    let mut slug = String::new();
    let mut previous_separator = false;
    for ch in service.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            previous_separator = false;
        } else if !previous_separator {
            slug.push('-');
            previous_separator = true;
        }
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "service".to_owned()
    } else {
        slug.to_owned()
    }
}

fn compose_base_dir(compose_path: &Path) -> &Path {
    compose_path.parent().unwrap_or_else(|| Path::new("."))
}

fn resolve_compose_path(base_dir: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn add_platform_overrides(cmd: &mut Command, platform: Option<&str>) {
    if let Some(platform) = platform {
        let mut parts = platform.split('/');
        if let (Some(os), Some(arch)) = (parts.next(), parts.next()) {
            cmd.arg("--override-os").arg(os);
            cmd.arg("--override-arch").arg(arch);
            if let Some(variant) = parts.next() {
                cmd.arg("--override-variant").arg(variant);
            }
        }
    }
}

fn yaml_key(key: &str) -> serde_yaml_ng::Value {
    serde_yaml_ng::Value::String(key.to_owned())
}

fn mapping_get<'a>(
    mapping: &'a serde_yaml_ng::Mapping,
    key: &str,
) -> Option<&'a serde_yaml_ng::Value> {
    mapping.get(&yaml_key(key))
}

fn mapping_get_mut<'a>(
    mapping: &'a mut serde_yaml_ng::Mapping,
    key: &str,
) -> Option<&'a mut serde_yaml_ng::Value> {
    mapping.get_mut(&yaml_key(key))
}

fn mapping_insert_string(
    mapping: &mut serde_yaml_ng::Mapping,
    key: &str,
    value: impl Into<String>,
) {
    mapping.insert(yaml_key(key), serde_yaml_ng::Value::String(value.into()));
}

fn mapping_remove(mapping: &mut serde_yaml_ng::Mapping, key: &str) {
    mapping.remove(&yaml_key(key));
}

fn yaml_string<'a>(value: &'a serde_yaml_ng::Value, context: &str) -> BundleResult<&'a str> {
    match value {
        serde_yaml_ng::Value::String(value) => Ok(value),
        _ => bail!("{context} must be a string"),
    }
}

fn optional_yaml_string(
    value: Option<&serde_yaml_ng::Value>,
    context: &str,
) -> BundleResult<Option<String>> {
    value
        .map(|value| yaml_string(value, context).map(str::to_owned))
        .transpose()
}

fn yaml_scalar_to_string(value: &serde_yaml_ng::Value, context: &str) -> BundleResult<String> {
    match value {
        serde_yaml_ng::Value::String(value) => Ok(value.clone()),
        serde_yaml_ng::Value::Bool(value) => Ok(value.to_string()),
        serde_yaml_ng::Value::Number(value) => Ok(value.to_string()),
        _ => bail!("{context} must be a scalar"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn load_test_compose(content: &str) -> serde_yaml_ng::Value {
        serde_yaml_ng::from_str(content).expect("test compose should parse")
    }

    #[test]
    fn plans_registry_and_local_sources() {
        let compose = load_test_compose(
            r#"
services:
  influxdb:
    image: docker.io/library/influxdb:2.7
  local:
    image: localhost/example/local:latest
    x-rugix:
      image:
        source: docker-daemon
        ref: localhost/example/local:latest
"#,
        );
        let images = plan_compose_images(&compose, Path::new("/tmp/app/docker-compose.yml"), "app")
            .expect("image plan should succeed");
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].service, "influxdb");
        assert_eq!(images[0].source, ImageSourceKind::Registry);
        assert_eq!(images[0].source_ref, "docker.io/library/influxdb:2.7");
        assert_eq!(images[1].service, "local");
        assert_eq!(images[1].source, ImageSourceKind::DockerDaemon);
        assert_eq!(images[1].source_ref, "localhost/example/local:latest");
    }

    #[test]
    fn plans_builds_from_compose_and_rewrites_packaged_services() {
        let mut compose = load_test_compose(
            r#"
services:
  api:
    image: localhost/example/api:dev
    build:
      context: ./service
      dockerfile: Containerfile
      target: runtime
      args:
        FOO: bar
        ENABLED: true
        EMPTY:
    x-rugix:
      unrelated: value
"#,
        );
        let mut images =
            plan_compose_images(&compose, Path::new("/tmp/app/docker-compose.yml"), "app")
                .expect("image plan should succeed");
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].source, ImageSourceKind::Build);
        assert_eq!(images[0].source_ref, "localhost/example/api:dev");
        assert_eq!(
            images[0].build.as_ref().unwrap().context,
            Path::new("/tmp/app/service")
        );
        assert_eq!(
            images[0].build.as_ref().unwrap().dockerfile.as_deref(),
            Some(Path::new("/tmp/app/service/Containerfile"))
        );
        assert_eq!(
            images[0].build.as_ref().unwrap().target.as_deref(),
            Some("runtime")
        );
        assert_eq!(
            images[0].build.as_ref().unwrap().args,
            vec!["FOO=bar", "ENABLED=true", "EMPTY"]
        );
        images[0].bundle_tag = Some("localhost/rugix-apps/app/image-0:c-deadbeef".to_owned());
        rewrite_compose_images(&mut compose, &images, false)
            .expect("Compose rewrite should succeed");
        let rendered = serialize_compose(&compose).expect("Compose should serialize");
        assert!(rendered.contains("image: localhost/rugix-apps/app/image-0:c-deadbeef"));
        assert!(rendered.contains("pull_policy: never"));
        assert!(!rendered.contains("build:"));
        assert!(!rendered.contains("x-rugix:"));
    }

    #[test]
    fn disable_pinning_keeps_original_image_reference() {
        let mut compose = load_test_compose(
            r#"
services:
  api:
    image: localhost/example/api:dev
    build: ./service
"#,
        );
        let mut images =
            plan_compose_images(&compose, Path::new("/tmp/app/docker-compose.yml"), "app")
                .expect("image plan should succeed");
        images[0].bundle_tag = Some("localhost/example/api:dev".to_owned());
        rewrite_compose_images(&mut compose, &images, true)
            .expect("Compose rewrite should succeed");
        let rendered = serialize_compose(&compose).expect("Compose should serialize");
        assert!(rendered.contains("image: localhost/example/api:dev"));
        assert!(rendered.contains("pull_policy: never"));
        assert!(!rendered.contains("build:"));
    }

    /// Archive sources require explicit paths and resolve them beside the Compose file.
    #[test]
    fn plans_archive_sources_and_rejects_missing_paths() {
        let compose = load_test_compose(
            r#"
services:
  worker:
    image: example/worker:dev
    x-rugix:
      image:
        source: docker-archive
        ref: images/worker.tar
"#,
        );
        let images = plan_compose_images(&compose, Path::new("/tmp/app/compose.yml"), "app")
            .expect("archive source should be accepted");
        assert_eq!(images[0].source, ImageSourceKind::DockerArchive);
        assert_eq!(images[0].source_ref, "/tmp/app/images/worker.tar");
        let missing_path = load_test_compose(
            r#"
services:
  worker:
    image: example/worker:dev
    x-rugix:
      image:
        source: docker-archive
"#,
        );
        assert!(plan_compose_images(&missing_path, Path::new("compose.yml"), "app").is_err());
    }

    /// Verifies configuration projections reject malformed and duplicate mappings.
    #[test]
    fn configuration_environment_mappings_are_explicit_and_validated() {
        let mappings = vec![
            "ECHECKER_URL=/echeckerUrl".to_owned(),
            "UI_PORT=/ui/port".to_owned(),
        ];
        let parsed = parse_configuration_environment(&mappings).unwrap();
        assert_eq!(parsed.get("ECHECKER_URL").unwrap(), "/echeckerUrl");
        assert_eq!(parsed.get("UI_PORT").unwrap(), "/ui/port");

        assert!(parse_configuration_environment(&["MISSING_POINTER".to_owned()]).is_err());
        assert!(parse_configuration_environment(&["RUGIX_APP_NAME=/name".to_owned()]).is_err());
        assert!(parse_configuration_environment(&["INVALID=/not-a-pointer".to_owned()]).is_ok());
        assert!(parse_configuration_environment(&["INVALID=not-a-pointer".to_owned()]).is_err());
        assert!(parse_configuration_environment(&["INVALID=/bad~2escape".to_owned()]).is_err());
        assert!(parse_configuration_environment(&[
            "DUPLICATE=/first".to_owned(),
            "DUPLICATE=/second".to_owned(),
        ])
        .is_err());
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, content: &str) {
        fs::write(path, content).expect("fake tool should be written");
        let mut permissions = fs::metadata(path)
            .expect("fake tool metadata should be readable")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("fake tool should be executable");
    }

    #[cfg(unix)]
    #[test]
    fn packs_compose_with_fake_image_tools() {
        let _lock = ENV_LOCK.lock().expect("env lock should not be poisoned");
        let temp = tempfile::TempDir::new().expect("temp dir should be created");
        let bin_dir = temp.path().join("bin");
        fs::create_dir(&bin_dir).expect("bin dir should be created");
        write_executable(
            &bin_dir.join("skopeo"),
            r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
    echo "skopeo version 0.0-test"
    exit 0
fi
if [[ "${1:-}" == "--tmpdir" ]]; then
    shift 2
fi
if [[ "${1:-}" == "inspect" ]]; then
    echo "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    exit 0
fi
if [[ "${1:-}" == "copy" ]]; then
    dest="${@: -1}"
    dest="${dest#docker-archive:}"
    path="${dest%%:*}"
    printf 'fake image\n' >"${path}"
    exit 0
fi
exit 1
"#,
        );
        write_executable(
            &bin_dir.join("podman"),
            r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "build" ]]; then
    exit 0
fi
if [[ "${1:-}" == "image" && "${2:-}" == "inspect" ]]; then
    echo "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    exit 0
fi
if [[ "${1:-}" == "info" ]]; then
    echo '{"graphDriverName":"overlay","graphRoot":"/tmp/fake-storage","runRoot":"/tmp/fake-run"}'
    exit 0
fi
exit 1
"#,
        );

        let compose = temp.path().join("docker-compose.yml");
        let service_dir = temp.path().join("service");
        fs::create_dir(&service_dir).expect("service dir should be created");
        fs::write(service_dir.join("Dockerfile"), "FROM scratch\n")
            .expect("Dockerfile should be written");
        fs::write(
            &compose,
            r#"
services:
  db:
    image: docker.io/library/busybox:1.36
  api:
    image: localhost/example/api:dev
    build: ./service
"#,
        )
        .expect("compose should be written");

        let original_path = std::env::var_os("PATH").expect("PATH should be set");
        let new_path = format!("{}:{}", bin_dir.display(), original_path.to_string_lossy());
        std::env::set_var("PATH", new_path);
        let output = temp.path().join("app.rugixb");
        let cmd = crate::PackDockerComposeCmd {
            app: "test-app".to_owned(),
            platform: Some("linux/arm64".to_owned()),
            pull: true,
            builder: crate::ImageBuilder::Podman,
            disable_pinning: false,
            disable_image_bundling: false,
            includes: Vec::new(),
            components: Vec::new(),
            health_check_timeout: None,
            configuration: crate::PackConfigurationArgs {
                schema: None,
                default: None,
            },
            configuration_environment: Vec::new(),
            metadata_file: None,
            compose_file: compose,
            output: output.clone(),
        };
        let result = pack(&cmd);
        std::env::set_var("PATH", original_path);

        result.expect("compose app should be packed with fake image tools");
        assert!(output.is_file());
    }
}
