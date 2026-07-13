//! Payload database for block indices and payload state.

use std::hash::BuildHasher;
use std::path::Path;
use std::path::PathBuf;

use crate::system::SystemResult;
use byte_calc::NumBytes;
use hashbrown::DefaultHashBuilder;
use hashbrown::HashTable;
use reportify::whatever;
use reportify::ResultExt;
use rugix_bundle::block_encoding::block_index::compute_block_index;
use rugix_bundle::block_encoding::block_index::BlockIndexConfig;
use rugix_bundle::format::decode::Decode;
use rugix_bundle::format::decode::Decoder;
use rugix_bundle::format::BlockIndex;
use rugix_bundle::format::{self};
use rugix_bundle::manifest::ChunkerAlgorithm;
use rugix_bundle::reader::block_provider::StoredBlock;
use rugix_bundle::reader::block_provider::StoredBlockProvider;
use rugix_bundle::source::FileSource;
use rugix_common::slots::SlotState;
use si_crypto_hashes::HashAlgorithm;
use tracing::warn;

/// State of an installed payload (hashes, size, timestamp).
///
/// Currently identical to [`SlotState`] but separated so the two can diverge.
pub type PayloadState = SlotState;

/// Stored block index.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredBlockIndex {
    /// Chunker algorithm.
    pub chunker_algorithm: ChunkerAlgorithm,
    /// Hash algorithm.
    pub hash_algorithm: HashAlgorithm,
    /// Path to the file containing the index.
    pub index_file: PathBuf,
}

#[derive(Debug)]
pub struct BlockProvider {
    chunker_algorithm: ChunkerAlgorithm,
    hash_algorithm: HashAlgorithm,
    table: HashTable<(usize, usize)>,
    table_hasher: DefaultHashBuilder,
    hashes: Vec<u8>,
    dimensions: Vec<(NumBytes, NumBytes)>,
    files: Vec<PathBuf>,
}

impl BlockProvider {
    pub fn new(chunker_algorithm: ChunkerAlgorithm, hash_algorithm: HashAlgorithm) -> Self {
        Self {
            chunker_algorithm,
            hash_algorithm,
            table: HashTable::new(),
            table_hasher: DefaultHashBuilder::default(),
            hashes: Vec::new(),
            dimensions: Vec::new(),
            files: Vec::new(),
        }
    }

    pub fn add_slot(&mut self, slot_name: &str, slot_file: PathBuf) -> SystemResult<()> {
        self.add_indices(&get_stored_indices(slot_name)?, slot_file)
    }

    pub fn add_indices(
        &mut self,
        indices: &[StoredBlockIndex],
        data_file: PathBuf,
    ) -> SystemResult<()> {
        for index in indices {
            if index.hash_algorithm != self.hash_algorithm {
                continue;
            }
            if index.chunker_algorithm != self.chunker_algorithm {
                continue;
            }
            // Load the index.
            let source = FileSource::from_unbuffered(
                std::fs::File::open(&index.index_file).whatever("unable to open index file")?,
            );
            let mut decoder = Decoder::new(source, 16, NumBytes::new(u64::MAX));
            let atom = decoder
                .next_atom_head()
                .whatever("unable to decode bundle")?;
            if !atom.is_start() || atom.tag() != format::tags::BLOCK_INDEX {
                warn!("invalid block index file");
                continue;
            }
            let index =
                BlockIndex::decode(&mut decoder, atom).whatever("unable to decode block index")?;
            let file_idx = self.files.len();
            self.files.push(data_file);
            let first_block_idx = self.hashes.len() / self.hash_algorithm.hash_size();
            self.hashes.extend_from_slice(&index.block_hashes.raw);
            let mut current_offset = NumBytes::ZERO;
            for (block, size) in (first_block_idx..).zip(index.block_sizes.raw.as_chunks::<4>().0) {
                let size = NumBytes::new(u32::from_be_bytes(*size).into());
                self.dimensions.push((current_offset, size));
                current_offset += size;
                let table_hash = self.table_hasher.hash_one(self.get_hash(block));
                self.table
                    .entry(
                        table_hash,
                        |(other, _)| {
                            self.hashes[*other * self.hash_algorithm.hash_size()
                                ..(*other + 1) * self.hash_algorithm.hash_size()]
                                == self.hashes[block * self.hash_algorithm.hash_size()
                                    ..(block + 1) * self.hash_algorithm.hash_size()]
                        },
                        |(other, _)| {
                            self.table_hasher.hash_one(
                                &self.hashes[*other * self.hash_algorithm.hash_size()
                                    ..(*other + 1) * self.hash_algorithm.hash_size()],
                            )
                        },
                    )
                    .or_insert_with(|| (block, file_idx));
            }
            break;
        }
        Ok(())
    }

    fn get_hash(&self, block: usize) -> &[u8] {
        &self.hashes
            [block * self.hash_algorithm.hash_size()..(block + 1) * self.hash_algorithm.hash_size()]
    }
}

impl StoredBlockProvider for BlockProvider {
    fn query(&self, hash: &[u8]) -> Option<StoredBlock<'_>> {
        let table_hash = self.table_hasher.hash_one(hash);
        self.table
            .find(table_hash, |(block, _)| self.get_hash(*block) == hash)
            .map(|(block, file)| StoredBlock {
                file: &self.files[*file],
                offset: self.dimensions[*block].0,
                size: self.dimensions[*block].1,
            })
    }

    fn has_stored_blocks(&self) -> bool {
        !self.hashes.is_empty()
    }
}

pub fn erase(slot_name: &str) -> SystemResult<()> {
    std::fs::remove_dir_all(db_dir().join(slot_name)).or_else(|error| match error.kind() {
        std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(whatever!("unable to erase slot metadata")),
    })
}

pub fn add_index(
    slot_name: &str,
    slot_file: &Path,
    chunker_algorithm: &ChunkerAlgorithm,
    hash_algorithm: &HashAlgorithm,
) -> SystemResult<()> {
    let path = db_dir().join(format!(
        "{slot_name}/{chunker_algorithm}_{hash_algorithm:#}.rugix-block-index"
    ));
    std::fs::create_dir_all(path.parent().unwrap()).ok();
    let index_config = BlockIndexConfig {
        hash_algorithm: *hash_algorithm,
        chunker: chunker_algorithm.clone(),
    };
    let block_index =
        compute_block_index(index_config, slot_file).whatever("unable to compute block index")?;
    std::fs::write(path, &block_index.encode()).whatever("unable to write block index")?;
    Ok(())
}

/// Get the stored block indices.
pub fn get_stored_indices(slot: &str) -> SystemResult<Vec<StoredBlockIndex>> {
    let slot_dir = db_dir().join(slot);
    let mut indices = Vec::new();
    if slot_dir.exists() {
        for dir_entry in std::fs::read_dir(&slot_dir).whatever("unable to list index directory")? {
            let dir_entry = dir_entry.whatever("unable to list indices directory")?;
            let filename = dir_entry.file_name();
            let filename = filename.to_string_lossy();
            let Some(name) = filename.strip_suffix(".rugix-block-index") else {
                continue;
            };
            let Some((chunker_algorithm, hash_algorithm)) = name.split_once('_') else {
                warn!("invalid filename for block index: {filename:?}");
                continue;
            };
            let Ok(chunker_algorithm) = chunker_algorithm.parse() else {
                warn!("invalid chunker algorithm: {chunker_algorithm:?}");
                continue;
            };
            let Ok(hash_algorithm) = hash_algorithm.parse() else {
                warn!("invalid hash algorithm: {hash_algorithm:?}");
                continue;
            };
            indices.push(StoredBlockIndex {
                chunker_algorithm,
                hash_algorithm,
                index_file: dir_entry.path(),
            })
        }
    }
    Ok(indices)
}

/// Compute and save a block index for an app-file payload in a generation directory.
///
/// Indices are stored at:
/// `<gen_dir>/.rugix/block-indices/<payload_path>/<chunker>_<hash>.rugix-block-index`
pub fn add_app_file_index(
    gen_dir: &Path,
    payload_path: &str,
    data_file: &Path,
    chunker_algorithm: &ChunkerAlgorithm,
    hash_algorithm: &HashAlgorithm,
) -> SystemResult<()> {
    let path = gen_dir
        .join(".rugix/block-indices")
        .join(payload_path)
        .join(format!(
            "{chunker_algorithm}_{hash_algorithm:#}.rugix-block-index"
        ));
    std::fs::create_dir_all(path.parent().unwrap()).ok();
    let index_config = BlockIndexConfig {
        hash_algorithm: *hash_algorithm,
        chunker: chunker_algorithm.clone(),
    };
    let block_index =
        compute_block_index(index_config, data_file).whatever("unable to compute block index")?;
    std::fs::write(path, &block_index.encode()).whatever("unable to write block index")?;
    Ok(())
}

/// Get stored block indices for an app-file payload in a generation directory.
pub fn get_app_file_indices(
    gen_dir: &Path,
    payload_path: &str,
) -> SystemResult<Vec<StoredBlockIndex>> {
    let index_dir = gen_dir.join(".rugix/block-indices").join(payload_path);
    let mut indices = Vec::new();
    if !index_dir.exists() {
        return Ok(indices);
    }
    for dir_entry in
        std::fs::read_dir(&index_dir).whatever("unable to list block index directory")?
    {
        let dir_entry = dir_entry.whatever("unable to list block index directory")?;
        let filename = dir_entry.file_name();
        let filename = filename.to_string_lossy();
        let Some(name) = filename.strip_suffix(".rugix-block-index") else {
            continue;
        };
        let Some((chunker_algorithm, hash_algorithm)) = name.split_once('_') else {
            warn!("invalid filename for block index: {filename:?}");
            continue;
        };
        let Ok(chunker_algorithm) = chunker_algorithm.parse() else {
            warn!("invalid chunker algorithm: {chunker_algorithm:?}");
            continue;
        };
        let Ok(hash_algorithm) = hash_algorithm.parse() else {
            warn!("invalid hash algorithm: {hash_algorithm:?}");
            continue;
        };
        indices.push(StoredBlockIndex {
            chunker_algorithm,
            hash_algorithm,
            index_file: dir_entry.path(),
        });
    }
    Ok(indices)
}

/// Get the stored block state.
pub fn get_stored_state(slot: &str) -> SystemResult<Option<SlotState>> {
    let slot_dir = db_dir().join(slot);
    let state_file = slot_dir.join("state.json");
    if !state_file.exists() {
        return Ok(None);
    }
    let state_json =
        std::fs::read_to_string(&state_file).whatever("unable to read slot state file")?;
    Ok(Some(
        serde_json::from_str(&state_json).whatever("unable to decode slot state")?,
    ))
}

/// Save the slot state.
pub fn save_slot_state(slot: &str, state: &SlotState) -> SystemResult<()> {
    let state_json = serde_json::to_string(state).whatever("unable to encode slot state")?;
    rugix_common::fsutils::atomic_write(
        &db_dir().join(slot).join("state.json"),
        state_json.as_bytes(),
    )
    .whatever("unable to write slot state")?;
    Ok(())
}

/// Directory with the slot database.
pub fn db_dir() -> &'static Path {
    const DATA_PATH: &str = "/run/rugix/mounts/data/rugix/slots";
    const VAR_PATH: &str = "/var/lib/rugix/slots";
    if Path::new("/run/rugix/mounts/data").exists() {
        Path::new(DATA_PATH)
    } else {
        Path::new(VAR_PATH)
    }
}
