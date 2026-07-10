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
    let hash = bundle_hash(bundle).unwrap();
    let metadata = SignedMetadata { header_hash: hash };
    Ok(format::encode::to_vec(
        &metadata,
        format::tags::SIGNED_METADATA,
    ))
}

pub fn add_bundle_signature(bundle: &Path, signature: Vec<u8>, out: &Path) -> BundleResult<()> {
    let bundle_file =
        BufReader::new(std::fs::File::open(bundle).whatever("unable to open bundle file")?);
    let mut source = FileSource::new(bundle_file);
    let _ = expect_start(&mut source, format::tags::BUNDLE)?;
    // Create new bundle file.
    let mut bundle_file =
        BufWriter::new(std::fs::File::create(out).whatever("unable to create bundle file")?);
    write_segment_start(&mut bundle_file, format::tags::BUNDLE).unwrap();
    // Copy the header as is.
    let mut header_bytes = Vec::new();
    let start = expect_start(&mut source, format::tags::BUNDLE_HEADER)?;
    read_into_vec(
        &mut source,
        &mut header_bytes,
        start,
        BUNDLE_HEADER_SIZE_LIMIT,
    )?;
    bundle_file.write_all(&header_bytes).unwrap();
    // Read existing signatures.
    let mut signatures = read_optional_metadata(&mut source)?.unwrap_or_default();
    signatures.cms_signatures.push(Bytes { raw: signature });
    // Write signature section.
    signatures
        .encode(&mut bundle_file, format::tags::SIGNATURES)
        .whatever("unable to write signatures")?;
    // At this point, we are in the payloads section in the source file.
    write_segment_start(&mut bundle_file, format::tags::PAYLOADS).unwrap();
    // Closing tags are copied as well.
    std::io::copy(&mut source.into_inner(), &mut bundle_file)
        .whatever("unable to copy bundle data")?;
    Ok(())
}
