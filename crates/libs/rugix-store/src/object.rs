//! Objects: block indices describing the chunks of stored files.

use std::fs;

use byte_calc::NumBytes;
use reportify::ResultExt;
use reportify::bail;
use rugix_bundle::format;
use rugix_chunker::ChunkerAlgorithm;
use si_crypto_hashes::HashAlgorithm;

use crate::ObjectId;
use crate::StoreResult;
use crate::layout::Layout;

/// Stored file described by the hashes and sizes of its chunks.
#[derive(Debug, Clone)]
pub(crate) struct Object {
    index: format::BlockIndex,
}

impl Object {
    pub(crate) fn new(
        chunker: ChunkerAlgorithm,
        algorithm: HashAlgorithm,
        hashes: Vec<u8>,
        sizes: &[u32],
    ) -> Self {
        Self {
            index: format::BlockIndex::new(chunker, algorithm, hashes, sizes),
        }
    }

    /// Load and verify a committed object.
    pub(crate) fn load(layout: &Layout, id: &ObjectId) -> StoreResult<Self> {
        let path = layout.object_path(id);
        let bytes = fs::read(&path).whatever_with(|_| format!("unable to read object {id}"))?;
        if id.algorithm().hash::<Box<[u8]>>(&bytes).raw() != id.raw() {
            bail!("object {id} does not match its ID");
        }
        let index: format::BlockIndex = format::decode::decode_slice(&bytes)
            .whatever_with(|_| format!("unable to decode object {id}"))?;
        let hashes_length = index.block_hashes.raw.len();
        let sizes_length = index.block_sizes.raw.len();
        let hash_size = index.hash_algorithm.hash_size();
        if index.hash_algorithm != id.algorithm()
            || !hashes_length.is_multiple_of(hash_size)
            || !sizes_length.is_multiple_of(4)
            || hashes_length / hash_size != sizes_length / 4
        {
            bail!("object {id} is malformed");
        }
        Ok(Self { index })
    }

    /// Encode the object and compute its ID.
    pub(crate) fn encode(&self) -> (ObjectId, Vec<u8>) {
        let bytes = format::encode::to_vec(&self.index, format::tags::BLOCK_INDEX);
        (self.index.hash_algorithm.hash(&bytes), bytes)
    }

    pub(crate) fn algorithm(&self) -> HashAlgorithm {
        self.index.hash_algorithm
    }

    /// Hash and size of the chunk at `index` in content order.
    pub(crate) fn chunk(&self, index: usize) -> Option<(&[u8], u32)> {
        let hash_size = self.index.hash_algorithm.hash_size();
        let hash = self
            .index
            .block_hashes
            .raw
            .get(index * hash_size..(index + 1) * hash_size)?;
        let size = self.index.block_sizes.raw.get(index * 4..(index + 1) * 4)?;
        Some((
            hash,
            u32::from_be_bytes(size.try_into().expect("the slice has four bytes")),
        ))
    }

    /// Hashes and sizes of the object's chunks in content order.
    pub(crate) fn chunks(&self) -> impl Iterator<Item = (&[u8], u32)> {
        (0..).map_while(|index| self.chunk(index))
    }

    /// Size of the object's content.
    pub(crate) fn size(&self) -> NumBytes {
        NumBytes::new(self.chunks().map(|(_, size)| u64::from(size)).sum())
    }
}
