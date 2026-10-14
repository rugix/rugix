//! Pack manifest directories, payload files, and component metadata into bundles.
//!
//! [`pack`] encodes payloads, assembles their hashes and delivery metadata, and writes
//! the completed bundle atomically, returning its header hash.

use std::io::BufRead;
use std::io::BufReader;
use std::path::Component as PathComponent;
use std::path::Path;
use std::path::PathBuf;

use byte_calc::NumBytes;
use reportify::ErrorExt;
use reportify::ResultExt;
use reportify::bail;
use reportify::whatever;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;
use sidex::serde::Serde;

use crate::BUNDLE_HEADER_SIZE_LIMIT;
use crate::BundleResult;
use crate::atomic_output;
use crate::block_encoding::encode_payload_file;
use crate::format::BundleComponentFile;
use crate::format::Bytes;
use crate::format::PayloadEntry;
use crate::format::PayloadHeader;
use crate::format::stlv::write_atom_head;
use crate::format::stlv::write_segment_end;
use crate::format::stlv::write_segment_start;
use crate::format::{self};
use crate::manifest::BundleManifest;
use crate::manifest::UpdateType;
use crate::manifest::{self};
use crate::paths_refer_to_same_file;

const COMPONENTS_DIR: &str = "components";
const COMPONENTS_SIZE_LIMIT: u64 = 64 * 1024;

/// Pack `rugix-bundle.toml` and its referenced files from `path` into `dst`.
///
/// Payload paths are relative to `path/payloads`. Component declarations under
/// `path/components` are embedded in the header. The returned hash identifies that
/// header; the destination is replaced only after encoding completes successfully.
pub fn pack(path: &Path, dst: &Path) -> BundleResult<HashDigest> {
    let manifest = toml::from_str::<BundleManifest>(
        &std::fs::read_to_string(path.join("rugix-bundle.toml"))
            .whatever("unable to read bundle manifest")?,
    )
    .whatever("unable to parse bundle manifest")?;
    manifest::validate_manifest_paths(&manifest)?;
    let hash_algorithm = manifest.hash_algorithm.map_or(
        si_crypto_hashes::HashAlgorithm::Sha512_256,
        Serde::into_inner,
    );
    let mut bundle_header = format::BundleHeader {
        manifest: Some(
            serde_json::to_string(&manifest).whatever("unable to serialize bundle manifest")?,
        ),
        is_incremental: matches!(manifest.update_type, UpdateType::Incremental),
        hash_algorithm,
        components: load_bundle_components(path)?,
        payload_index: Vec::new(),
    };
    let mut prepared_payloads = Vec::new();
    let mut prepared_tempfiles = Vec::new();
    for payload in &manifest.payloads {
        let payload_file = path.join("payloads").join(&payload.filename);
        if paths_refer_to_same_file(&payload_file, dst)? {
            bail!("bundle output must not overwrite an input payload");
        }
        let payload_file_hash =
            hash_file(hash_algorithm, &payload_file).whatever("unable to hash payload file")?;
        let mut payload_data = payload_file.clone();
        let mut payload_header = PayloadHeader {
            block_encoding: None,
        };
        if let Some(block_encoding) = &payload.block_encoding {
            let temporary = tempfile::NamedTempFile::new()
                .whatever("unable to create temporary encoded payload file")?;
            payload_data = temporary.path().to_owned();
            payload_header.block_encoding = Some(encode_payload_file(
                block_encoding,
                &payload_file,
                &payload_data,
            )?);
            prepared_tempfiles.push(temporary);
        }
        let payload_header = format::encode::to_vec(&payload_header, format::tags::PAYLOAD_HEADER);
        bundle_header.payload_index.push(PayloadEntry {
            type_slot: if let manifest::DeliveryConfig::Slot(slot_config) = &payload.delivery {
                Some(format::SlotPayloadType {
                    slot: slot_config.slot.to_string(),
                })
            } else {
                None
            },
            type_execute: if let manifest::DeliveryConfig::Execute(execute_delivery_config) =
                &payload.delivery
            {
                Some(format::ExecutePayloadType {
                    handler: execute_delivery_config
                        .handler
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                })
            } else {
                None
            },
            type_app_file: if let manifest::DeliveryConfig::AppFile(config) = &payload.delivery {
                Some(format::AppFilePayloadType {
                    app: config.app.to_string(),
                    path: config.path.to_string(),
                    mode: config.mode,
                })
            } else {
                None
            },
            type_app_archive: if let manifest::DeliveryConfig::AppArchive(config) =
                &payload.delivery
            {
                Some(format::AppArchivePayloadType {
                    app: config.app.to_string(),
                })
            } else {
                None
            },
            header_hash: Bytes {
                raw: hash_algorithm
                    .hash::<Box<[u8]>>(&payload_header)
                    .raw()
                    .to_vec(),
            },
            file_hash: Bytes {
                raw: payload_file_hash.raw().to_vec(),
            },
            delta_encoding: payload
                .delta_encoding
                .as_ref()
                .map(|encoding| format::DeltaEncoding {
                    format: encoding.format.clone(),
                    inputs: encoding
                        .inputs
                        .iter()
                        .map(|input| format::DeltaEncodingInput {
                            hashes: input.hashes.iter().map(|hash| hash.0.clone()).collect(),
                        })
                        .collect(),
                    original_hash: encoding.original_hash.0.clone(),
                }),
        });
        prepared_payloads.push(PreparedPayload {
            payload_header,
            payload_data,
        })
    }
    let bundle_header = format::encode::to_vec(&bundle_header, format::tags::BUNDLE_HEADER);
    if bundle_header.len() as u64 > BUNDLE_HEADER_SIZE_LIMIT.raw {
        bail!(
            "bundle header exceeds size limit: {} > {} bytes",
            bundle_header.len(),
            BUNDLE_HEADER_SIZE_LIMIT.raw
        );
    }
    let header_hash = hash_algorithm.hash(&bundle_header);
    atomic_output(dst, |bundle_file| {
        write_segment_start(bundle_file, format::tags::BUNDLE)
            .whatever("unable to write bundle root")?;
        bundle_file
            .write_all(&bundle_header)
            .whatever("unable to write bundle header")?;
        write_segment_start(bundle_file, format::tags::PAYLOADS)
            .whatever("unable to write payload section")?;
        for prepared in prepared_payloads {
            write_segment_start(bundle_file, format::tags::PAYLOAD)
                .whatever("unable to write payload segment")?;
            bundle_file
                .write_all(&prepared.payload_header)
                .whatever("unable to write payload header")?;
            let data_size = std::fs::metadata(&prepared.payload_data)
                .whatever("unable to inspect prepared payload")?
                .len();
            write_atom_head(
                bundle_file,
                format::stlv::AtomHead::Value {
                    tag: format::tags::PAYLOAD_DATA,
                    length: NumBytes::new(data_size),
                },
            )
            .whatever("unable to write payload data header")?;
            let mut payload_data = std::fs::File::open(&prepared.payload_data)
                .whatever("unable to open prepared payload")?;
            std::io::copy(&mut payload_data, bundle_file)
                .whatever("unable to write payload data")?;
            write_segment_end(bundle_file, format::tags::PAYLOAD)
                .whatever("unable to finish payload segment")?;
        }
        write_segment_end(bundle_file, format::tags::PAYLOADS)
            .whatever("unable to finish payload section")?;
        write_segment_end(bundle_file, format::tags::BUNDLE).whatever("unable to finish bundle")?;
        Ok(header_hash)
    })
}

struct PreparedPayload {
    payload_header: Vec<u8>,
    payload_data: PathBuf,
}

fn load_bundle_components(path: &Path) -> BundleResult<Option<format::BundleComponents>> {
    let root = path.join(COMPONENTS_DIR);
    let metadata = match std::fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error
                .whatever("unable to inspect bundle components directory")
                .field_debug("path", &root));
        }
    };
    if metadata.file_type().is_symlink() {
        bail!("bundle components directory must not be a symlink");
    }
    if !metadata.is_dir() {
        bail!("bundle components path is not a directory");
    }

    let mut total_size = 0;
    let mut files = Vec::new();
    collect_bundle_component_files(&root, &root, &mut total_size, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(Some(format::BundleComponents::new(files)))
}

fn collect_bundle_component_files(
    root: &Path,
    path: &Path,
    total_size: &mut u64,
    files: &mut Vec<BundleComponentFile>,
) -> BundleResult<()> {
    let entries = std::fs::read_dir(path)
        .whatever("unable to read bundle components directory")
        .field_debug("path", path)?;
    for entry in entries {
        let entry = entry
            .whatever("unable to read bundle components directory entry")
            .field_debug("path", path)?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .whatever("unable to inspect bundle component path")
            .field_debug("path", &path)?;
        if file_type.is_symlink() {
            bail!("bundle component path must not be a symlink: {path:?}");
        }
        if file_type.is_dir() {
            collect_bundle_component_files(root, &path, total_size, files)?;
            continue;
        }
        if !file_type.is_file() {
            bail!("bundle component path is not a regular file: {path:?}");
        }
        if !is_component_file(&path) {
            bail!("unsupported bundle component file extension: {path:?}");
        }

        let relative_path = normalize_bundle_component_path(root, &path)?;
        let data = std::fs::read(&path)
            .whatever("unable to read bundle component file")
            .field_debug("path", &path)?;
        *total_size += data.len() as u64 + relative_path.len() as u64;
        if *total_size > COMPONENTS_SIZE_LIMIT {
            bail!(
                "bundle component metadata exceeds size limit: {} > {} bytes",
                *total_size,
                COMPONENTS_SIZE_LIMIT
            );
        }
        files.push(BundleComponentFile::new(relative_path, data));
    }
    Ok(())
}

fn hash_file(algorithm: HashAlgorithm, path: &Path) -> std::io::Result<HashDigest> {
    let mut hasher = algorithm.hasher();
    let mut reader = BufReader::new(std::fs::File::open(path)?);
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            break Ok(hasher.finalize());
        }
        hasher.update(buffer);
        let consumed = buffer.len();
        reader.consume(consumed);
    }
}

fn normalize_bundle_component_path(root: &Path, path: &Path) -> BundleResult<String> {
    let relative = path
        .strip_prefix(root)
        .whatever("unable to resolve bundle component path")?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let PathComponent::Normal(part) = component else {
            bail!("invalid bundle component path: {path:?}");
        };
        let part = part
            .to_str()
            .ok_or_else(|| whatever!("bundle component path is not UTF-8: {path:?}"))?;
        if part.is_empty() {
            bail!("invalid bundle component path: {path:?}");
        }
        parts.push(part);
    }
    if parts.is_empty() {
        bail!("invalid bundle component path: {path:?}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_encoding::block_index::BlockIndexConfig;
    use crate::block_encoding::block_index::compute_block_index;
    use crate::manifest::ChunkerAlgorithm;
    use crate::reader::BundleReader;
    use crate::reader::BundleSource;

    #[test]
    fn pack_embeds_bundle_components_in_header() {
        let tempdir = tempfile::tempdir().unwrap();
        let bundle_dir = tempdir.path().join("bundle");
        let components_dir = bundle_dir.join("components");
        std::fs::create_dir_all(components_dir.join("nested")).unwrap();
        std::fs::write(
            bundle_dir.join("rugix-bundle.toml"),
            r#"
update-type = "full"
payloads = []
"#,
        )
        .unwrap();
        std::fs::write(components_dir.join("z.toml"), b"id = \"component.z\"\n").unwrap();
        std::fs::write(
            components_dir.join("nested/a.json"),
            br#"{"id": "component.a"}"#,
        )
        .unwrap();

        let bundle_path = tempdir.path().join("bundle.rugixb");
        let hash = pack(&bundle_dir, &bundle_path).unwrap();
        let bundle_file = std::fs::File::open(&bundle_path).unwrap();
        let bundle_source = BundleSource::from_seekable(bundle_file).unwrap();
        let bundle_reader = BundleReader::start(bundle_source, Some(hash)).unwrap();
        let components = bundle_reader.header().components.as_ref().unwrap();

        assert_eq!(components.files.len(), 2);
        assert_eq!(components.files[0].path, "nested/a.json");
        assert_eq!(components.files[0].data.raw, br#"{"id": "component.a"}"#);
        assert_eq!(components.files[1].path, "z.toml");
        assert_eq!(components.files[1].data.raw, b"id = \"component.z\"\n");
    }

    /// Verifies that decoding exposes the verified index of the installed payload data.
    #[test]
    fn decoded_payload_includes_its_block_index() {
        let tempdir = tempfile::tempdir().unwrap();
        let bundle_dir = tempdir.path().join("bundle");
        std::fs::create_dir_all(bundle_dir.join("payloads")).unwrap();
        std::fs::write(
            bundle_dir.join("rugix-bundle.toml"),
            r#"
update-type = "full"

[[payloads]]
filename = "system.img"
[payloads.delivery]
type = "slot"
slot = "system"
[payloads.block-encoding]
chunker = "casync-64"
"#,
        )
        .unwrap();
        let payload_path = bundle_dir.join("payloads/system.img");
        let payload_data = (0..256 * 1024)
            .map(|offset| (offset % 251) as u8)
            .collect::<Vec<_>>();
        std::fs::write(&payload_path, &payload_data).unwrap();

        let bundle_path = tempdir.path().join("bundle.rugixb");
        let hash = pack(&bundle_dir, &bundle_path).unwrap();
        let source =
            BundleSource::from_seekable(std::fs::File::open(&bundle_path).unwrap()).unwrap();
        let mut reader = BundleReader::start(source, Some(hash)).unwrap();
        let payload = reader.next_payload().unwrap().unwrap();
        let decoded_path = tempdir.path().join("decoded.img");
        let target = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&decoded_path)
            .unwrap();
        let decoded = payload.decode_into(target, None, &mut |_| {}).unwrap();
        let decoded_index = decoded.block_index.unwrap();
        let expected_index = compute_block_index(
            BlockIndexConfig {
                hash_algorithm: si_crypto_hashes::HashAlgorithm::Sha512_256,
                chunker: ChunkerAlgorithm::Casync {
                    avg_block_size_kib: 64,
                },
            },
            &payload_path,
        )
        .unwrap();

        assert_eq!(std::fs::read(decoded_path).unwrap(), payload_data);
        assert_eq!(
            format::encode::to_vec(&decoded_index, format::tags::BLOCK_INDEX),
            expected_index.encode()
        );
    }
}
