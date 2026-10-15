//! Stored chunks as local block candidates for bundle installation.

use std::collections::HashMap;
use std::fs;

use byte_calc::NumBytes;
use rugix_bundle::reader::StoredBlock;
use rugix_bundle::reader::StoredBlockProvider;
use rugix_compression::CompressionFormat;
use si_crypto_hashes::HashAlgorithm;

use crate::StoreResult;
use crate::layout::Layout;
use crate::layout::LockMode;
use crate::layout::StoreLock;

/// Offers the chunks of a store as candidates for blocks with the same hash.
///
/// Holds a shared lock, so garbage collection cannot delete offered chunks.
pub struct StoreBlockProvider {
    layout: Layout,
    algorithm: HashAlgorithm,
    /// Compression of each chunk, by hash.
    chunks: HashMap<Vec<u8>, Option<CompressionFormat>>,
    _lock: Option<StoreLock>,
}

impl StoreBlockProvider {
    pub(crate) fn new(layout: &Layout, algorithm: HashAlgorithm) -> StoreResult<Self> {
        let lock = layout.lock(LockMode::Shared)?;
        let chunks = layout
            .chunks()?
            .into_iter()
            .filter(|chunk| chunk.algorithm == algorithm)
            .map(|chunk| (chunk.hash, chunk.compression))
            .collect();
        Ok(Self {
            layout: layout.clone(),
            algorithm,
            chunks,
            _lock: lock,
        })
    }
}

impl StoredBlockProvider for StoreBlockProvider {
    fn query(&self, hash: &[u8]) -> Option<StoredBlock> {
        let compression = *self.chunks.get(hash)?;
        let file = self.layout.chunk_path(self.algorithm, hash, compression);
        let size = fs::metadata(&file).ok()?.len();
        Some(StoredBlock {
            file,
            offset: NumBytes::ZERO,
            size: NumBytes::new(size),
            compression,
        })
    }
}
