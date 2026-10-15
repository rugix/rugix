//! Stored chunks as local block candidates for bundle installation.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

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
    _lock: Option<StoreLock>,
    chunks: HashMap<Vec<u8>, (PathBuf, Option<CompressionFormat>)>,
}

impl StoreBlockProvider {
    pub(crate) fn new(layout: &Layout, algorithm: HashAlgorithm) -> StoreResult<Self> {
        let lock = layout.lock(LockMode::Shared)?;
        let chunks = layout
            .chunks()?
            .into_iter()
            .filter(|chunk| chunk.algorithm == algorithm)
            .map(|chunk| (chunk.hash, (chunk.path, chunk.compression)))
            .collect();
        Ok(Self {
            _lock: lock,
            chunks,
        })
    }
}

impl StoredBlockProvider for StoreBlockProvider {
    fn query(&self, hash: &[u8]) -> Option<StoredBlock> {
        let (path, compression) = self.chunks.get(hash)?;
        let size = fs::metadata(path).ok()?.len();
        Some(StoredBlock {
            file: path.clone(),
            offset: NumBytes::ZERO,
            size: NumBytes::new(size),
            compression: *compression,
        })
    }
}
