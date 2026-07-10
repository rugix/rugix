//! App bundle packing logic for Docker Compose, binary, and generic orchestrators.

use std::collections::HashSet;
use std::fs::File;
use std::fs::{self};
use std::path::Component as PathComponent;
use std::path::Path;
use std::path::PathBuf;

use reportify::bail;
use reportify::whatever;
use reportify::ResultExt;
use rugix_bundle::bundle_hash;
use rugix_bundle::manifest::AppArchiveDeliveryConfig;
use rugix_bundle::manifest::AppFileDeliveryConfig;
use rugix_bundle::manifest::BlockEncoding;
use rugix_bundle::manifest::BundleManifest;
use rugix_bundle::manifest::Compression;
use rugix_bundle::manifest::DeliveryConfig;
use rugix_bundle::manifest::Payload;
use rugix_bundle::manifest::UpdateType;
use rugix_bundle::manifest::XzCompression;
use rugix_bundle::BundleResult;
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

/// Stage app component metadata so the low-level bundle builder embeds it in
/// the bundle header.
fn stage_component_files(bundle_dir: &Path, components: &[PathBuf]) -> BundleResult<()> {
    if components.is_empty() {
        return Ok(());
    }

    let component_root = bundle_dir.join("components");
    fs::create_dir_all(&component_root).whatever("unable to create components directory")?;
    let mut staged = HashSet::new();
    for component in components {
        stage_component_path(component, &component_root, &mut staged)?;
    }
    if staged.is_empty() {
        bail!("no component files found");
    }
    Ok(())
}

fn stage_component_path(
    path: &Path,
    dst_root: &Path,
    staged: &mut HashSet<String>,
) -> BundleResult<()> {
    let metadata = fs::symlink_metadata(path)
        .whatever("unable to inspect component path")
        .field("path", path)?;
    if metadata.file_type().is_symlink() {
        bail!("component path must not be a symlink: {}", path.display());
    }
    if metadata.is_dir() {
        stage_component_dir(path, path, dst_root, staged)?;
    } else if metadata.is_file() {
        let Some(file_name) = path.file_name() else {
            bail!("unable to determine component filename: {}", path.display());
        };
        let relative_path = component_path_string(Path::new(file_name))?;
        stage_component_file(path, dst_root, relative_path, staged)?;
    } else {
        bail!(
            "component path is not a regular file or directory: {}",
            path.display()
        );
    }
    Ok(())
}

fn stage_component_dir(
    root: &Path,
    dir: &Path,
    dst_root: &Path,
    staged: &mut HashSet<String>,
) -> BundleResult<()> {
    let mut entries = fs::read_dir(dir)
        .whatever("unable to read component directory")
        .field("path", dir)?
        .collect::<Result<Vec<_>, _>>()
        .whatever("unable to read component directory entry")?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .whatever("unable to inspect component directory entry")
            .field("path", path.as_path())?;
        if file_type.is_symlink() {
            bail!("component path must not be a symlink: {}", path.display());
        }
        if file_type.is_dir() {
            stage_component_dir(root, &path, dst_root, staged)?;
            continue;
        }
        if !file_type.is_file() {
            bail!("component path is not a regular file: {}", path.display());
        }
        let relative_path = component_path_string(
            path.strip_prefix(root)
                .whatever("unable to resolve component path")?,
        )?;
        stage_component_file(&path, dst_root, relative_path, staged)?;
    }
    Ok(())
}

fn stage_component_file(
    src: &Path,
    dst_root: &Path,
    relative_path: String,
    staged: &mut HashSet<String>,
) -> BundleResult<()> {
    if !is_component_file(Path::new(&relative_path)) {
        bail!("unsupported component file extension: {}", src.display());
    }
    if !staged.insert(relative_path.clone()) {
        bail!("duplicate component path: {relative_path}");
    }
    let dst = dst_root.join(relative_path);
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).whatever("unable to create component parent directory")?;
    }
    fs::copy(src, &dst)
        .whatever("unable to copy component file")
        .field("source", src)
        .field("destination", dst.as_path())?;
    Ok(())
}

fn component_path_string(path: &Path) -> BundleResult<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let PathComponent::Normal(part) = component else {
            bail!("invalid component path: {}", path.display());
        };
        let part = part
            .to_str()
            .ok_or_else(|| whatever!("component path is not UTF-8: {}", path.display()))?;
        if part.is_empty() {
            bail!("invalid component path: {}", path.display());
        }
        parts.push(part);
    }
    if parts.is_empty() {
        bail!("invalid component path: {}", path.display());
    }
    Ok(parts.join("/"))
}

fn is_component_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("toml") || extension.eq_ignore_ascii_case("json")
        })
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
// Docker Compose apps
// ---------------------------------------------------------------------------

mod docker_compose;

pub fn pack_docker_compose(cmd: &super::PackDockerComposeCmd) -> BundleResult<()> {
    docker_compose::pack(cmd)
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
    stage_component_files(bundle_dir.path(), &cmd.components)?;

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
    stage_component_files(bundle_dir.path(), &cmd.components)?;

    let payloads = vec![Payload {
        delivery: DeliveryConfig::AppArchive(AppArchiveDeliveryConfig::new(cmd.app.clone())),
        filename: "base.tar".to_owned(),
        block_encoding,
        delta_encoding: None,
    }];

    finalize_bundle(bundle_dir.path(), &cmd.output, &cmd.app, payloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rugix_bundle::reader::BundleReader;
    use rugix_bundle::source::ReaderSource;
    use rugix_bundle::source::SkipSeek;

    #[test]
    fn app_bundle_includes_component_files() {
        let tempdir = tempfile::tempdir().unwrap();
        let app_dir = tempdir.path().join("app");
        fs::create_dir_all(app_dir.join("components/nested")).unwrap();
        fs::write(app_dir.join("orchestrator"), b"#!/bin/sh\n").unwrap();
        fs::write(app_dir.join("components/app.toml"), b"id = \"app.test\"\n").unwrap();
        fs::write(
            app_dir.join("components/nested/runtime.json"),
            br#"{"id":"app.test.runtime"}"#,
        )
        .unwrap();

        let output = tempdir.path().join("app.rugixb");
        let cmd = crate::PackGenericCmd {
            app: "test_app".to_owned(),
            orchestrator: app_dir.join("orchestrator"),
            includes: Vec::new(),
            components: vec![app_dir.join("components")],
            metadata_file: None,
            output: output.clone(),
        };

        pack_generic(&cmd).unwrap();

        let bundle_file = File::open(output).unwrap();
        let source = ReaderSource::<_, SkipSeek>::from_unbuffered(bundle_file);
        let reader = BundleReader::start(source, None).unwrap();
        let components = reader.header().components.as_ref().unwrap();

        assert_eq!(components.files.len(), 2);
        assert_eq!(components.files[0].path, "app.toml");
        assert_eq!(components.files[0].data.raw, b"id = \"app.test\"\n");
        assert_eq!(components.files[1].path, "nested/runtime.json");
        assert_eq!(
            components.files[1].data.raw,
            br#"{"id":"app.test.runtime"}"#
        );
    }
}
