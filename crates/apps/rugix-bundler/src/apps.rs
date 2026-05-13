//! App bundle packing logic for Docker Compose, binary, and generic orchestrators.

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use reportify::{bail, ResultExt};
use rugix_bundle::manifest::{
    AppArchiveDeliveryConfig, AppFileDeliveryConfig, BlockEncoding, BundleManifest, Compression,
    DeliveryConfig, Payload, UpdateType, XzCompression,
};
use rugix_bundle::{bundle_hash, BundleResult};
use rugix_chunker::ChunkerAlgorithm;
use tracing::info;

/// Normalize non-deterministic tar header fields (timestamps, ownership) for
/// reproducible builds while preserving permission bits.
fn normalize_tar_header(header: &mut tar::Header) {
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_username("").ok();
    header.set_groupname("").ok();
    header.set_cksum();
}

/// Append raw bytes to a tar archive with normalized metadata.
fn tar_append_bytes(archive: &mut tar::Builder<File>, name: &str, data: &[u8]) -> BundleResult<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    normalize_tar_header(&mut header);
    archive
        .append_data(&mut header, name, data)
        .whatever_with(|_| format!("unable to add {name} to archive"))?;
    Ok(())
}

/// Append a file to a tar archive with normalized metadata for reproducibility,
/// preserving the file's permission bits.
fn tar_append_file(archive: &mut tar::Builder<File>, path: &Path, name: &str) -> BundleResult<()> {
    let mut file =
        File::open(path).whatever_with(|_| format!("unable to open {}", path.display()))?;
    let metadata = file
        .metadata()
        .whatever_with(|_| format!("unable to read metadata of {}", path.display()))?;
    let mut header = tar::Header::new_gnu();
    header.set_size(metadata.len());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let is_executable = metadata.permissions().mode() & 0o111 != 0;
        header.set_mode(if is_executable { 0o755 } else { 0o644 });
    }
    #[cfg(not(unix))]
    {
        header.set_mode(0o644);
    }
    normalize_tar_header(&mut header);
    archive
        .append_data(&mut header, name, &mut file)
        .whatever_with(|_| format!("unable to add {} to archive", name))?;
    Ok(())
}

/// Append a directory tree to a tar archive with normalized metadata for
/// reproducibility, preserving permission bits and sorting entries for
/// deterministic ordering.
fn tar_append_dir(archive: &mut tar::Builder<File>, name: &str, src: &Path) -> BundleResult<()> {
    fn walk(archive: &mut tar::Builder<File>, prefix: &str, dir: &Path) -> BundleResult<()> {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .whatever_with(|_| format!("unable to read directory {}", dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .whatever("unable to read directory entry")?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let file_name = entry.file_name();
            let Some(file_name_str) = file_name.to_str() else {
                bail!("non-UTF-8 filename in directory {}", dir.display());
            };
            let entry_name = format!("{}/{}", prefix, file_name_str);
            if path.is_dir() {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
                normalize_tar_header(&mut header);
                archive
                    .append_data(&mut header, &entry_name, &[][..])
                    .whatever("unable to add directory entry to archive")?;
                walk(archive, &entry_name, &path)?;
            } else {
                tar_append_file(archive, &path, &entry_name)?;
            }
        }
        Ok(())
    }
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    normalize_tar_header(&mut header);
    archive
        .append_data(&mut header, name, &[][..])
        .whatever("unable to add directory entry to archive")?;
    walk(archive, name, src)
}

/// Write an `app.toml` entry into a tar archive.
fn tar_append_app_toml(
    archive: &mut tar::Builder<File>,
    manifest: &rugix_bundle::manifest::AppManifest,
) -> BundleResult<()> {
    let content = toml::to_string_pretty(manifest).whatever("unable to serialize app.toml")?;
    let bytes = content.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    normalize_tar_header(&mut header);
    archive
        .append_data(&mut header, "app.toml", bytes)
        .whatever("unable to add app.toml to archive")?;
    Ok(())
}

/// Append included files/directories to a tar archive.
fn tar_append_includes(archive: &mut tar::Builder<File>, includes: &[PathBuf]) -> BundleResult<()> {
    for include in includes {
        let Some(name) = include.file_name().and_then(|n| n.to_str()) else {
            bail!(
                "unable to determine name for include path: {}",
                include.display()
            );
        };
        if include.is_dir() {
            tar_append_dir(archive, name, include)?;
        } else {
            tar_append_file(archive, include, name)?;
        }
    }
    Ok(())
}

/// Append a metadata file to the archive if provided.
fn tar_append_metadata(
    archive: &mut tar::Builder<File>,
    metadata_file: Option<&Path>,
) -> BundleResult<()> {
    if let Some(path) = metadata_file {
        // Validate that it's valid JSON before including it.
        let content = fs::read_to_string(path)
            .whatever_with(|_| format!("unable to read metadata file {}", path.display()))?;
        let _: serde_json::Value = serde_json::from_str(&content)
            .whatever_with(|_| format!("metadata file {} is not valid JSON", path.display()))?;
        tar_append_bytes(archive, "app-meta.json", content.as_bytes())?;
    }
    Ok(())
}

/// Common block encoding configuration for app bundles.
fn app_block_encoding() -> Option<BlockEncoding> {
    Some(
        BlockEncoding::new(ChunkerAlgorithm::Casync {
            avg_block_size_kib: 64,
        })
        .with_compression(Some(Compression::Xz(XzCompression::new()))),
    )
}

/// Write a manifest, pack the bundle, and print the hash.
fn finalize_bundle(
    bundle_dir: &Path,
    output: &Path,
    app: &str,
    payloads: Vec<Payload>,
) -> BundleResult<()> {
    let manifest = BundleManifest::new(UpdateType::Full, payloads);
    fs::write(
        bundle_dir.join("rugix-bundle.toml"),
        toml::to_string_pretty(&manifest).whatever("unable to serialize manifest")?,
    )
    .whatever("unable to write manifest")?;
    rugix_bundle::builder::pack(bundle_dir, output)?;
    let hash = bundle_hash(output)?;
    info!(app = %app, output = ?output, "packed app bundle");
    println!("{hash}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Container image helpers
// ---------------------------------------------------------------------------

/// Extract the string representation from a saphyr YAML node.
fn yaml_as_str<'a>(node: &'a saphyr::Yaml<'a>) -> Option<&'a str> {
    match node {
        saphyr::Yaml::Representation(cow, _, _) => Some(cow.as_ref()),
        saphyr::Yaml::Value(saphyr::Scalar::String(cow)) => Some(cow.as_ref()),
        _ => None,
    }
}

/// Look up a key in a saphyr YAML mapping node.
fn yaml_mapping_get<'a, 'b>(node: &'a saphyr::Yaml<'b>, key: &str) -> Option<&'a saphyr::Yaml<'b>> {
    if let saphyr::Yaml::Mapping(mapping) = node {
        for (k, v) in mapping.iter() {
            if yaml_as_str(k) == Some(key) {
                return Some(v);
            }
        }
    }
    None
}

/// Rewrite image references in a Docker Compose file to use pinned digests.
///
/// For each saved image, replaces occurrences of the original reference (e.g.,
/// `nginx:latest`) with the digest-pinned version (e.g., `nginx@sha256:abc...`).
fn pin_compose_images(compose_content: &str, saved: &[SavedImage]) -> String {
    // We currently do simple string replacement. This has the risk of matching unrelated
    // strings, however, it trivially preserves the formatting and any comments.
    let mut content = compose_content.to_owned();
    for image in saved {
        content = content.replace(&image.original, &image.pinned);
    }
    content
}

/// Extract image references from a Docker Compose file.
fn extract_compose_images(compose_path: &Path) -> BundleResult<Vec<String>> {
    let content =
        fs::read_to_string(compose_path).whatever("unable to read Docker Compose file")?;
    use saphyr::LoadableYamlNode;
    let docs =
        saphyr::Yaml::load_from_str(&content).whatever("unable to parse Docker Compose file")?;
    let mut images = Vec::new();
    if let Some(doc) = docs.first() {
        if let Some(saphyr::Yaml::Mapping(services)) = yaml_mapping_get(doc, "services") {
            for (_key, service) in services.iter() {
                if let Some(image_node) = yaml_mapping_get(service, "image") {
                    if let Some(image) = yaml_as_str(image_node) {
                        images.push(image.to_owned());
                    }
                }
            }
        }
    }
    Ok(images)
}

/// Check whether skopeo is available on the system.
fn has_skopeo() -> bool {
    std::process::Command::new("skopeo")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Derive a stable payload filename for a container image by index.
///
/// Uses an index-based name (`image-0.tar`, `image-1.tar`, ...) so that
/// filenames remain stable across version bumps of the same image, enabling
/// effective delta updates between bundles.
fn image_payload_filename(index: usize) -> String {
    format!("image-{index}.tar")
}

/// A saved container image with its payload filename and resolved digest.
struct SavedImage {
    /// The original image reference from the compose file.
    original: String,
    /// The image reference pinned to a digest (e.g., `nginx@sha256:abc...`).
    pinned: String,
    /// Path inside the generation directory (e.g., `images/image-0.tar`).
    app_path: String,
    /// Filename of the payload file inside the payloads directory.
    payload_filename: String,
}

/// Strip the tag from an image reference, returning the repository part.
///
/// `nginx:latest` → `nginx`, `registry.io/app:v1` → `registry.io/app`.
/// References that already use a digest (`@sha256:...`) are returned as-is.
fn image_repo(image: &str) -> &str {
    if image.contains('@') {
        return image;
    }
    // The tag starts at the last colon, but only if it comes after any `/`
    // (to avoid splitting on the port in `registry:5000/image`).
    let after_slash = image.rfind('/').map(|i| i + 1).unwrap_or(0);
    match image[after_slash..].rfind(':') {
        Some(pos) => &image[..after_slash + pos],
        None => image,
    }
}

/// Resolve the digest of a pulled Docker image via `docker inspect`.
fn resolve_digest_docker(image: &str) -> BundleResult<String> {
    let output = std::process::Command::new("docker")
        .args(["inspect", "--format", "{{index .RepoDigests 0}}", image])
        .output()
        .whatever("unable to run docker inspect")?;
    if !output.status.success() {
        bail!("docker inspect failed for {image}");
    }
    let pinned = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !pinned.contains('@') {
        bail!("docker inspect did not return a digest for {image}: {pinned}");
    }
    Ok(pinned)
}

/// Resolve the digest of a remote image via `skopeo inspect`.
fn resolve_digest_skopeo(image: &str, platform: Option<&str>) -> BundleResult<String> {
    let mut cmd = std::process::Command::new("skopeo");
    cmd.args(["inspect", "--format", "{{.Digest}}"]);
    if let Some(platform) = platform {
        let parts: Vec<&str> = platform.splitn(2, '/').collect();
        if parts.len() == 2 {
            cmd.arg("--override-os").arg(parts[0]);
            cmd.arg("--override-arch").arg(parts[1]);
        }
    }
    cmd.arg(format!("docker://{image}"));
    let output = cmd.output().whatever("unable to run skopeo inspect")?;
    if !output.status.success() {
        bail!("skopeo inspect failed for {image}");
    }
    let digest = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !digest.starts_with("sha256:") {
        bail!("skopeo inspect did not return a valid digest for {image}: {digest}");
    }
    Ok(format!("{}@{}", image_repo(image), digest))
}

/// Save container images using skopeo (one tar per image, pulled from registry).
fn save_images_skopeo(
    images: &[String],
    platform: Option<&str>,
    disable_pinning: bool,
    payloads_dir: &Path,
) -> BundleResult<Vec<SavedImage>> {
    let mut saved = Vec::new();
    for (index, image) in images.iter().enumerate() {
        let filename = image_payload_filename(index);
        let output = payloads_dir.join(&filename);
        let mut cmd = std::process::Command::new("skopeo");
        cmd.arg("copy");
        if let Some(platform) = platform {
            // Parse platform string like "linux/arm64" into os and arch.
            let parts: Vec<&str> = platform.splitn(2, '/').collect();
            if parts.len() == 2 {
                cmd.arg("--override-os").arg(parts[0]);
                cmd.arg("--override-arch").arg(parts[1]);
            }
        }
        cmd.arg(format!("docker://{image}"));
        cmd.arg(format!("docker-archive:{}", output.display()));
        info!(image, ?platform, "pulling image with skopeo");
        let status = cmd.status().whatever("unable to run skopeo")?;
        if !status.success() {
            bail!("skopeo copy failed for {image}");
        }
        let pinned = if disable_pinning {
            info!(image, "image pinning disabled, skipping digest resolution");
            image.clone()
        } else {
            let p = resolve_digest_skopeo(image, platform)?;
            info!(image, pinned = %p, "resolved image digest");
            p
        };
        saved.push(SavedImage {
            original: image.clone(),
            pinned,
            app_path: format!("images/{filename}"),
            payload_filename: filename,
        });
    }
    Ok(saved)
}

/// Save container images using `docker pull` + `docker save` (one tar per image).
fn save_images_docker(
    images: &[String],
    platform: Option<&str>,
    pull: bool,
    disable_pinning: bool,
    payloads_dir: &Path,
) -> BundleResult<Vec<SavedImage>> {
    if pull {
        for image in images {
            let mut cmd = std::process::Command::new("docker");
            cmd.arg("pull");
            if let Some(platform) = platform {
                cmd.arg("--platform").arg(platform);
            }
            cmd.arg(image);
            info!(image, ?platform, "pulling docker image");
            let status = cmd.status().whatever("unable to run docker pull")?;
            if !status.success() {
                bail!("docker pull failed for {image}");
            }
        }
    }

    let mut saved = Vec::new();
    for (index, image) in images.iter().enumerate() {
        let filename = image_payload_filename(index);
        let output = payloads_dir.join(&filename);
        info!(image, "saving docker image");
        let mut save_cmd = std::process::Command::new("docker");
        save_cmd.arg("save").arg("-o").arg(&output);
        if let Some(platform) = platform {
            save_cmd.arg("--platform").arg(platform);
        }
        save_cmd.arg(image);
        let status = save_cmd.status().whatever("unable to run docker save")?;
        if !status.success() {
            bail!("docker save failed for {image}");
        }
        let pinned = if disable_pinning {
            info!(image, "image pinning disabled, skipping digest resolution");
            image.clone()
        } else {
            let p = resolve_digest_docker(image)?;
            info!(image, pinned = %p, "resolved image digest");
            p
        };
        saved.push(SavedImage {
            original: image.clone(),
            pinned,
            app_path: format!("images/{filename}"),
            payload_filename: filename,
        });
    }
    Ok(saved)
}

/// Save container images to the payloads directory.
///
/// When `pull` is true and skopeo is available, uses skopeo to pull images
/// directly from the registry (one tar per image, no Docker daemon required).
/// Otherwise, falls back to `docker pull` + `docker save`.
fn save_images(
    images: &[String],
    platform: Option<&str>,
    pull: bool,
    disable_pinning: bool,
    payloads_dir: &Path,
) -> BundleResult<Vec<SavedImage>> {
    if pull && has_skopeo() {
        save_images_skopeo(images, platform, disable_pinning, payloads_dir)
    } else {
        save_images_docker(images, platform, pull, disable_pinning, payloads_dir)
    }
}

/// Pack a Docker Compose app into an app bundle.
///
/// Creates a bundle with:
/// - An `app-archive` payload containing `app.toml`, `docker-compose.yml`, and any extra
///   included files/directories. Image references in the compose file are pinned to their
///   digest so the deployed stack always uses the exact images that were bundled.
/// - An `app-file` payload per Docker image, placed at `images/image-N.tar` inside the
///   generation directory.
pub fn pack_docker_compose(cmd: &super::PackDockerComposeCmd) -> BundleResult<()> {
    rugix_bundle::manifest::validate_app_name(&cmd.app)?;
    let bundle_dir = tempfile::TempDir::new().whatever("unable to create temp directory")?;
    let payloads_dir = bundle_dir.path().join("payloads");
    fs::create_dir_all(&payloads_dir).whatever("unable to create payloads directory")?;

    let block_encoding = app_block_encoding();

    // Save Docker images first so we can pin digests in the compose file.
    let saved_images = if !cmd.disable_image_bundling {
        let images = extract_compose_images(&cmd.compose_file)?;
        if !images.is_empty() {
            save_images(
                &images,
                cmd.platform.as_deref(),
                cmd.pull,
                cmd.disable_pinning,
                &payloads_dir,
            )?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Read the compose file and pin image references to their digests.
    let compose_content =
        fs::read_to_string(&cmd.compose_file).whatever("unable to read Docker Compose file")?;
    let compose_content = if !cmd.disable_pinning && !saved_images.is_empty() {
        pin_compose_images(&compose_content, &saved_images)
    } else {
        compose_content
    };

    // Build the base tar archive: app.toml + (pinned) docker-compose.yml + includes.
    let archive_path = payloads_dir.join("base.tar");
    {
        let archive_file = File::create(&archive_path).whatever("unable to create base.tar")?;
        let mut archive = tar::Builder::new(archive_file);
        let manifest = {
            use rugix_bundle::manifest::{AppHealthCheckConfig, AppManifest};
            let mut m = AppManifest::new("docker-compose".to_owned());
            if let Some(timeout) = cmd.health_check_timeout {
                m = m.with_health_check(Some(
                    AppHealthCheckConfig::new().with_timeout(Some(timeout)),
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
        tar_append_includes(&mut archive, &cmd.includes)?;
        tar_append_metadata(&mut archive, cmd.metadata_file.as_deref())?;
        archive.finish().whatever("unable to finish archive")?;
    }

    let mut payloads = vec![Payload {
        delivery: DeliveryConfig::AppArchive(AppArchiveDeliveryConfig::new(cmd.app.clone())),
        filename: "base.tar".to_owned(),
        block_encoding: block_encoding.clone(),
        delta_encoding: None,
    }];

    for image in &saved_images {
        payloads.push(Payload {
            delivery: DeliveryConfig::AppFile(AppFileDeliveryConfig::new(
                cmd.app.clone(),
                image.app_path.clone(),
            )),
            filename: image.payload_filename.clone(),
            block_encoding: block_encoding.clone(),
            delta_encoding: None,
        });
    }

    finalize_bundle(bundle_dir.path(), &cmd.output, &cmd.app, payloads)
}

/// Pack a binary app into an app bundle.
///
/// Creates a bundle with:
/// - An `app-archive` payload containing `app.toml`, `systemd.service`, and any extra
///   included files/directories.
/// - An `app-file` payload for the binary executable.
pub fn pack_binary(cmd: &super::PackBinaryCmd) -> BundleResult<()> {
    rugix_bundle::manifest::validate_app_name(&cmd.app)?;
    let bundle_dir = tempfile::TempDir::new().whatever("unable to create temp directory")?;
    let payloads_dir = bundle_dir.path().join("payloads");
    fs::create_dir_all(&payloads_dir).whatever("unable to create payloads directory")?;

    let block_encoding = app_block_encoding();

    // Build the base tar archive: app.toml + systemd.service + includes.
    let archive_path = payloads_dir.join("base.tar");
    {
        let archive_file = File::create(&archive_path).whatever("unable to create base.tar")?;
        let mut archive = tar::Builder::new(archive_file);
        let manifest = rugix_bundle::manifest::AppManifest::new("binary".to_owned());
        tar_append_app_toml(&mut archive, &manifest)?;
        tar_append_file(&mut archive, &cmd.service, "systemd.service")?;
        tar_append_includes(&mut archive, &cmd.includes)?;
        tar_append_metadata(&mut archive, cmd.metadata_file.as_deref())?;
        archive.finish().whatever("unable to finish archive")?;
    }

    // The binary goes as a separate app-file payload for optimal delta updates.
    let Some(binary_name) = cmd.binary.file_name().and_then(|n| n.to_str()) else {
        bail!(
            "unable to determine binary filename: {}",
            cmd.binary.display()
        );
    };
    fs::copy(&cmd.binary, payloads_dir.join("binary")).whatever("unable to copy binary")?;

    let payloads = vec![
        Payload {
            delivery: DeliveryConfig::AppArchive(AppArchiveDeliveryConfig::new(cmd.app.clone())),
            filename: "base.tar".to_owned(),
            block_encoding: block_encoding.clone(),
            delta_encoding: None,
        },
        Payload {
            delivery: DeliveryConfig::AppFile(
                AppFileDeliveryConfig::new(cmd.app.clone(), binary_name.to_owned())
                    .with_mode(Some(0o755)),
            ),
            filename: "binary".to_owned(),
            block_encoding: block_encoding.clone(),
            delta_encoding: None,
        },
    ];

    finalize_bundle(bundle_dir.path(), &cmd.output, &cmd.app, payloads)
}

/// Pack a generic app into an app bundle.
///
/// Creates a bundle with:
/// - An `app-archive` payload containing `app.toml`, the `orchestrator` script, and any
///   extra included files/directories.
pub fn pack_generic(cmd: &super::PackGenericCmd) -> BundleResult<()> {
    rugix_bundle::manifest::validate_app_name(&cmd.app)?;
    let bundle_dir = tempfile::TempDir::new().whatever("unable to create temp directory")?;
    let payloads_dir = bundle_dir.path().join("payloads");
    fs::create_dir_all(&payloads_dir).whatever("unable to create payloads directory")?;

    let block_encoding = app_block_encoding();

    // Build the base tar archive: app.toml + orchestrator + includes.
    let archive_path = payloads_dir.join("base.tar");
    {
        let archive_file = File::create(&archive_path).whatever("unable to create base.tar")?;
        let mut archive = tar::Builder::new(archive_file);
        let manifest = rugix_bundle::manifest::AppManifest::new("generic".to_owned());
        tar_append_app_toml(&mut archive, &manifest)?;
        tar_append_file(&mut archive, &cmd.orchestrator, "orchestrator")?;
        tar_append_includes(&mut archive, &cmd.includes)?;
        tar_append_metadata(&mut archive, cmd.metadata_file.as_deref())?;
        archive.finish().whatever("unable to finish archive")?;
    }

    let payloads = vec![Payload {
        delivery: DeliveryConfig::AppArchive(AppArchiveDeliveryConfig::new(cmd.app.clone())),
        filename: "base.tar".to_owned(),
        block_encoding,
        delta_encoding: None,
    }];

    finalize_bundle(bundle_dir.path(), &cmd.output, &cmd.app, payloads)
}
