//! Utility functions.

use reportify::ResultExt;
use rugix_bundle::BundleResult;
use rugix_compression::ByteProcessor;

/// Compress the given bytes.
pub fn compress_bytes(bytes: &[u8]) -> BundleResult<Vec<u8>> {
    let mut compressor = rugix_compression::XzEncoder::new(6);
    let mut compressed = Vec::new();
    compressor
        .process(bytes, &mut compressed)
        .whatever("unable to compress simulation data")?;
    compressor
        .finalize(&mut compressed)
        .whatever("unable to finalize simulation compression")?;
    Ok(compressed)
}
