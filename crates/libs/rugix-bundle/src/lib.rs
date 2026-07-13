#![forbid(unsafe_code)]

//! Implementation of Rugix Ctrl's update bundle format.

use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;

use byte_calc::NumBytes;
use format::BundleHeader;
use format::decode::decode_slice;
use reader::expect_start;
use reader::read_into_vec;
use reportify::Report;
use reportify::ResultExt;
use si_crypto_hashes::HashDigest;
use source::FileSource;

use crate::format::Bytes;
use crate::format::SignedMetadata;
use crate::format::encode::Encode;
use crate::format::stlv::write_segment_start;
use crate::reader::read_optional_metadata;

pub mod block_encoding;
pub mod builder;
pub mod format;
pub mod manifest;
pub mod reader;
pub mod source;
pub mod xdelta;

/// Start sequence of an update bundle.
pub const BUNDLE_MAGIC: &[u8] = &[
    0x6b, 0x50, 0x74, 0x1c, 0x40, // Start bundle.
    0x49, 0xaf, 0x64, 0x33, 0x40, // Start bundle header.
];

reportify::new_whatever_type! {
    /// Error reading or writing a bundle.
    pub BundleError
}

/// Result with [`BundleError`] as error type.
pub type BundleResult<T> = Result<T, Report<BundleError>>;

const BUNDLE_HEADER_SIZE_LIMIT: NumBytes = NumBytes::kibibytes(128);
// We need a large limit here as the payload header may contain a block index.
const PAYLOAD_HEADER_SIZE_LIMIT: NumBytes = NumBytes::mebibytes(32);

// Limit size of signatures to 32 MiB.
const SIGNATURES_SIZE_LIMIT: NumBytes = NumBytes::mebibytes(32);

/// Compute and return the hash for the given bundle.
pub fn bundle_hash(bundle: &Path) -> BundleResult<HashDigest> {
    let bundle_file =
        BufReader::new(std::fs::File::open(bundle).whatever("unable to open bundle file")?);
    let mut source = FileSource::new(bundle_file);
    let _ = expect_start(&mut source, format::tags::BUNDLE)?;
    let mut header_bytes = Vec::new();
    let start = expect_start(&mut source, format::tags::BUNDLE_HEADER)?;
    read_into_vec(
        &mut source,
        &mut header_bytes,
        start,
        BUNDLE_HEADER_SIZE_LIMIT,
    )?;
    let bundle_header = decode_slice::<BundleHeader>(&header_bytes)?;
    let hash_algorithm = bundle_header.hash_algorithm;
    Ok(hash_algorithm.hash(&header_bytes))
}

pub fn signed_metadata(bundle: &Path) -> BundleResult<Vec<u8>> {
    let hash = bundle_hash(bundle)?;
    let metadata = SignedMetadata { header_hash: hash };
    Ok(format::encode::to_vec(
        &metadata,
        format::tags::SIGNED_METADATA,
    ))
}

pub fn add_bundle_signature(bundle: &Path, signature: Vec<u8>, out: &Path) -> BundleResult<()> {
    if paths_refer_to_same_file(bundle, out)? {
        reportify::bail!("input and output bundle must be different files");
    }
    let bundle_file =
        BufReader::new(std::fs::File::open(bundle).whatever("unable to open bundle file")?);
    let mut source = FileSource::new(bundle_file);
    let _ = expect_start(&mut source, format::tags::BUNDLE)?;
    // Copy the header as is.
    let mut header_bytes = Vec::new();
    let start = expect_start(&mut source, format::tags::BUNDLE_HEADER)?;
    read_into_vec(
        &mut source,
        &mut header_bytes,
        start,
        BUNDLE_HEADER_SIZE_LIMIT,
    )?;
    // Read existing signatures.
    let mut signatures = read_optional_metadata(&mut source)?.unwrap_or_default();
    signatures.cms_signatures.push(Bytes { raw: signature });
    atomic_output(out, |bundle_file| {
        write_segment_start(bundle_file, format::tags::BUNDLE)
            .whatever("unable to write bundle root")?;
        bundle_file
            .write_all(&header_bytes)
            .whatever("unable to write bundle header")?;
        signatures
            .encode(bundle_file, format::tags::SIGNATURES)
            .whatever("unable to write signatures")?;
        // At this point, we are in the payloads section in the source file.
        write_segment_start(bundle_file, format::tags::PAYLOADS)
            .whatever("unable to write payload section")?;
        // Closing tags are copied as well.
        std::io::copy(&mut source.into_inner(), bundle_file)
            .whatever("unable to copy bundle data")?;
        Ok(())
    })
}

pub(crate) fn atomic_output<T>(
    dst: &Path,
    write: impl FnOnce(&mut dyn Write) -> BundleResult<T>,
) -> BundleResult<T> {
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".rugix-bundle-")
        .tempfile_in(parent)
        .whatever("unable to create temporary bundle file")?;
    let result = {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        let result = write(&mut writer)?;
        writer.flush().whatever("unable to flush bundle output")?;
        result
    };
    temporary
        .as_file()
        .sync_all()
        .whatever("unable to synchronize bundle output")?;
    temporary
        .persist(dst)
        .map_err(|error| error.error)
        .whatever("unable to install completed bundle")?;
    std::fs::File::open(parent)
        .whatever("unable to open bundle output directory")?
        .sync_all()
        .whatever("unable to synchronize bundle output directory")?;
    Ok(result)
}

pub(crate) fn paths_refer_to_same_file(input: &Path, output: &Path) -> BundleResult<bool> {
    if input == output {
        return Ok(true);
    }
    let input = std::fs::canonicalize(input).whatever("unable to resolve input bundle path")?;
    match std::fs::canonicalize(output) {
        Ok(output) => Ok(input == output),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).whatever("unable to resolve output bundle path"),
    }
}

#[cfg(test)]
mod tests {
    use super::atomic_output;
    use super::paths_refer_to_same_file;
    use crate::BundleResult;

    #[test]
    fn failed_atomic_output_preserves_existing_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let output = tempdir.path().join("bundle.rugixb");
        std::fs::write(&output, b"existing").unwrap();

        let result = atomic_output(&output, |writer| -> BundleResult<()> {
            writer.write_all(b"partial").unwrap();
            reportify::bail!("injected output failure")
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"existing");
        assert!(paths_refer_to_same_file(&output, &output).unwrap());
    }
}
