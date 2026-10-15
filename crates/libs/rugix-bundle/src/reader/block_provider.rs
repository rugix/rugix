//! Candidates for reusing decoded payload blocks from local storage.
//!
//! Providers index block hashes; the fetcher verifies every candidate before use.

use std::path::PathBuf;

use byte_calc::NumBytes;
use rugix_compression::CompressionFormat;

/// Locate candidate decoded blocks by their hash.
///
/// The payload's hash algorithm and chunker determine the index to query.
pub trait StoredBlockProvider {
    /// Return a candidate block with this decoded hash, if one is indexed.
    ///
    /// Unreadable or mismatching candidates fall back to the original bundle bytes.
    fn query(&self, hash: &[u8]) -> Option<StoredBlock>;
}

/// Location and stored length of one locally indexed block candidate.
#[derive(Debug, Clone)]
pub struct StoredBlock {
    /// File containing the block.
    pub file: PathBuf,
    /// Offset of the block in the file.
    pub offset: NumBytes,
    /// Size of the block in the file.
    pub size: NumBytes,
    /// Compression of the stored bytes, if the file holds the block compressed.
    pub compression: Option<CompressionFormat>,
}
