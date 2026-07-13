//! Prototypical file-based diffing and delta update implementation.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;

use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use reportify::bail;
use reportify::ResultExt;
use rugix_bundle::BundleResult;
use tar::EntryType;

use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;

use rugix_chunker::Chunker;
use rugix_chunker::ChunkerAlgorithm;

use super::utils::compress_bytes;

/// Deltar instruction.
#[derive(Debug, Clone)]
pub enum Instruction {
    /// Push a path fragment onto the stack.
    Push { path: OsString },
    /// Pop a path fragment from the stack.
    Pop,
    /// Set the owner to the given user and group.
    Owner { uid: u32, gid: u32 },
    /// Set the mode to the given mode.
    Mode { mode: u32 },
    /// Create a file.
    File {
        /// Chunks of the file.
        chunks: Vec<FileChunk>,
    },
    /// Create a directory.
    Directory,
    /// Create a character device.
    CharacterDevice {
        /// Device major number.
        major: u32,
        /// Device minor number.
        minor: u32,
    },
    /// Create a block device.
    BlockDevice {
        /// Device major number.
        major: u32,
        /// Device minor number.
        minor: u32,
    },
    /// Create a symbolic link.
    Link { target: PathBuf },
}

/// Chunk of a file.
#[derive(Debug, Clone)]
pub struct FileChunk {
    /// Hash of the chunk.
    pub hash: HashDigest,
    /// Chunk address.
    pub address: ChunkAddress,
}

/// Chunk address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkAddress {
    /// Group the chunk is located in.
    pub group_number: u32,
    /// Chunk number in the group.
    pub chunk_number: u16,
}

/// Collects chunks into a contiguous stream of bytes.
#[derive(Debug)]
pub struct ChunkCollector {
    /// Lookup table for chunks.
    table: HashMap<HashDigest, ChunkAddress>,
    /// Individually compressed chunk groups.
    groups: Vec<ChunkGroup>,
    /// Pending data for the current group.
    pending_data: Vec<u8>,
    /// Number of chunks in the current group.
    current_chunks: u16,
    /// Maximum size of a chunk group.
    group_size_limit: usize,
}

/// Compressed group of chunks.
#[derive(Debug)]
pub struct ChunkGroup {
    /// Raw, uncompressed data.
    #[expect(unused)]
    pub data: Vec<u8>,
    /// Compressed data.
    pub compressed: Vec<u8>,
}

impl ChunkCollector {
    /// Constructs a new chunk collector.
    pub fn new(group_size_limit: usize) -> Self {
        Self {
            table: HashMap::new(),
            groups: Vec::new(),
            pending_data: Vec::new(),
            current_chunks: 0,
            group_size_limit,
        }
    }

    /// Flushes the current group.
    pub fn flush(&mut self) -> BundleResult<()> {
        if !self.pending_data.is_empty() {
            let data = std::mem::take(&mut self.pending_data);
            let compressed = compress_bytes(&data)?;
            self.groups.push(ChunkGroup { data, compressed });
            self.current_chunks = 0;
        }
        Ok(())
    }

    /// Add a chunk.
    pub fn add_chunk(&mut self, hash: &HashDigest, chunk: &[u8]) -> BundleResult<ChunkAddress> {
        if let Some(addr) = self.table.get(hash) {
            return Ok(*addr);
        }
        let group_number = u32::try_from(self.groups.len())
            .whatever("simulation produced too many chunk groups")?;
        let chunk_number = self.current_chunks;
        // We write the size of the chunk into the group such that we can later identify
        // the individual chunks after decoding the group.
        self.pending_data.extend_from_slice(
            &u32::try_from(chunk.len())
                .whatever("simulation chunk is larger than 4 GiB")?
                .to_be_bytes(),
        );
        self.pending_data.extend_from_slice(chunk);
        self.current_chunks = self
            .current_chunks
            .checked_add(1)
            .ok_or_else(|| reportify::whatever!("simulation chunk group has too many chunks"))?;
        if self.pending_data.len() > self.group_size_limit {
            self.flush()?;
        }
        let addr = ChunkAddress {
            group_number,
            chunk_number,
        };
        self.table.insert(hash.clone(), addr);
        Ok(addr)
    }

    /// Finalize the chunk collector and return the individual chunk groups.
    pub fn finalize(mut self) -> BundleResult<Vec<ChunkGroup>> {
        self.flush()?;
        Ok(self.groups)
    }
}

/// Compute a plan from the given input tar archive.
pub fn compute_plan<R: Read>(
    group_size_limit: usize,
    chunker_algorithm: &ChunkerAlgorithm,
    mut archive: tar::Archive<R>,
) -> BundleResult<(Vec<Instruction>, Vec<ChunkGroup>)> {
    let mut chunk_collector = ChunkCollector::new(group_size_limit);
    let mut plan = Vec::new();
    let mut current_path = PathBuf::new();
    let mut current_mode = None;
    let mut current_owner = None;
    for entry in archive.entries().whatever("unable to read tar archive")? {
        let mut entry = entry.whatever("unable to read tar entry")?;
        if !matches!(
            entry.header().entry_type(),
            EntryType::Regular
                | EntryType::Symlink
                | EntryType::Char
                | EntryType::Block
                | EntryType::Directory
        ) {
            continue;
        }
        let path = entry.path().whatever("invalid tar entry path")?;
        let mut path = path.as_ref();
        if path.is_absolute() {
            path = path
                .strip_prefix("/")
                .whatever("unable to normalize absolute tar entry path")?;
        }
        let path = loop {
            if let Ok(path) = path.strip_prefix(&current_path) {
                break path;
            }
            current_path.pop();
            plan.push(Instruction::Pop);
        };
        current_path.push(path);
        plan.push(Instruction::Push { path: path.into() });
        let entry_owner = (
            u32::try_from(entry.header().uid().whatever("invalid tar entry uid")?)
                .whatever("tar entry uid does not fit into u32")?,
            u32::try_from(entry.header().gid().whatever("invalid tar entry gid")?)
                .whatever("tar entry gid does not fit into u32")?,
        );
        if Some(entry_owner) != current_owner {
            current_owner = Some(entry_owner);
            plan.push(Instruction::Owner {
                uid: entry_owner.0,
                gid: entry_owner.1,
            });
        }
        let entry_mode = entry.header().mode().whatever("invalid tar entry mode")?;
        if Some(entry_mode) != current_mode {
            current_mode = Some(entry_mode);
            plan.push(Instruction::Mode { mode: entry_mode });
        }
        match entry.header().entry_type() {
            EntryType::Regular => {
                let mut data = Vec::new();
                entry
                    .read_to_end(&mut data)
                    .whatever("unable to read tar file entry")?;
                let mut chunks = Vec::new();
                for chunk in chunker_algorithm
                    .chunker()
                    .whatever("invalid chunker configuration")?
                    .chunks(&data)
                {
                    let hash = HashAlgorithm::Sha256.hash(chunk);
                    let address = chunk_collector.add_chunk(&hash, chunk)?;
                    chunks.push(FileChunk { hash, address })
                }
                plan.push(Instruction::File { chunks })
            }
            EntryType::Symlink => {
                let target = entry
                    .link_name()
                    .whatever("invalid tar link target")?
                    .ok_or_else(|| reportify::whatever!("tar symbolic link has no target"))?;
                plan.push(Instruction::Link {
                    target: target.into(),
                })
            }
            EntryType::Char => {
                let major = entry
                    .header()
                    .device_major()
                    .whatever("invalid character device major number")?
                    .ok_or_else(|| reportify::whatever!("character device has no major number"))?;
                let minor = entry
                    .header()
                    .device_minor()
                    .whatever("invalid character device minor number")?
                    .ok_or_else(|| reportify::whatever!("character device has no minor number"))?;
                plan.push(Instruction::CharacterDevice { major, minor });
            }
            EntryType::Block => {
                let major = entry
                    .header()
                    .device_major()
                    .whatever("invalid block device major number")?
                    .ok_or_else(|| reportify::whatever!("block device has no major number"))?;
                let minor = entry
                    .header()
                    .device_minor()
                    .whatever("invalid block device minor number")?
                    .ok_or_else(|| reportify::whatever!("block device has no minor number"))?;
                plan.push(Instruction::BlockDevice { major, minor });
            }
            EntryType::Directory => {
                plan.push(Instruction::Directory);
            }
            _ => bail!("unsupported tar entry type after validation"),
        }
    }
    Ok((plan, chunk_collector.finalize()?))
}

/// Serialize a plan into a byte vector.
pub fn serialize_plan(plan: &[Instruction]) -> BundleResult<Bytes> {
    let mut serialized = BytesMut::new();
    for instr in plan {
        match instr {
            Instruction::Push { path } => {
                serialized.put_u8(1);
                let path = path.as_encoded_bytes();
                serialized
                    .put_u8(u8::try_from(path.len()).whatever("plan path fragment is too long")?);
                serialized.extend_from_slice(path);
            }
            Instruction::Pop => {
                serialized.put_u8(2);
            }
            Instruction::Owner { uid, gid } => {
                serialized.put_u8(3);
                serialized.put_u32(*uid);
                serialized.put_u32(*gid);
            }
            Instruction::Mode { mode } => {
                serialized.put_u32(4);
                serialized.extend_from_slice(&mode.to_be_bytes());
            }
            Instruction::File { chunks, .. } => {
                serialized.put_u8(5);
                serialized.put_u16(
                    u16::try_from(chunks.len()).whatever("plan file has too many chunks")?,
                );
                for chunk in chunks {
                    serialized.extend_from_slice(chunk.hash.as_ref());
                    serialized.put_u32(chunk.address.group_number);
                    serialized.put_u16(chunk.address.chunk_number);
                }
            }
            Instruction::Directory => {
                serialized.put_u8(6);
            }
            Instruction::CharacterDevice { major, minor } => {
                serialized.put_u8(7);
                serialized.put_u32(*major);
                serialized.put_u32(*minor);
            }
            Instruction::BlockDevice { major, minor } => {
                serialized.put_u8(8);
                serialized.put_u32(*major);
                serialized.put_u32(*minor);
            }
            Instruction::Link { target } => {
                serialized.put_u8(9);
                let target = target.as_os_str().as_encoded_bytes();
                serialized
                    .put_u16(u16::try_from(target.len()).whatever("plan link target is too long")?);
                serialized.extend_from_slice(target);
            }
        }
    }
    Ok(serialized.freeze())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::compute_plan;
    use super::serialize_plan;
    use super::Instruction;
    use rugix_chunker::ChunkerAlgorithm;

    #[test]
    fn malformed_archives_and_oversized_plan_fields_return_errors() {
        let archive = tar::Archive::new(b"not a tar archive".as_slice());
        assert!(compute_plan(
            32 * 1024,
            &ChunkerAlgorithm::Fixed { block_size_kib: 4 },
            archive,
        )
        .is_err());

        let oversized_path = OsString::from("x".repeat(256));
        assert!(serialize_plan(&[Instruction::Push {
            path: oversized_path
        }])
        .is_err());
    }
}
