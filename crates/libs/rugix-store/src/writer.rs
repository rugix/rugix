//! Adding files to the store.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use byte_calc::NumBytes;
use reportify::ResultExt;
use reportify::bail;
use reportify::whatever;
use rugix_bundle::BundleResult;
use rugix_bundle::reader::PayloadTarget;
use rugix_bundle::reader::VerifiedBlock;
use rugix_chunker::AnyChunker;
use rugix_chunker::Chunker;
use rugix_chunker::ChunkerAlgorithm;
use rugix_compression::CompressionFormat;
use si_crypto_hashes::HashAlgorithm;
use tempfile::TempDir;
use tracing::debug;

use crate::ObjectId;
use crate::RefName;
use crate::StoreResult;
use crate::chunk;
use crate::layout::CHUNK_COMPRESSIONS;
use crate::layout::Layout;
use crate::layout::LockMode;
use crate::layout::StoreLock;
use crate::object::Object;

/// Adds one file to the store.
///
/// Write the content either as bundle blocks, through the [`PayloadTarget`]
/// implementation, or as a byte stream, through [`Write`]. Do not mix both. The
/// stream is split with the writer's chunker. [`ObjectWriter::commit`] makes the
/// file durable and names it with a ref. Dropping the writer without committing
/// discards staged data.
pub struct ObjectWriter {
    layout: Layout,
    staging: TempDir,
    chunker_algorithm: ChunkerAlgorithm,
    chunker: AnyChunker,
    algorithm: HashAlgorithm,
    /// Bytes of the current stream chunk.
    pending: Vec<u8>,
    hashes: Vec<u8>,
    sizes: Vec<u32>,
    /// Offset of each chunk in the content, for reading back duplicate blocks.
    offsets: Vec<u64>,
    size: u64,
    /// Chunks staged by this writer, by hash.
    staged: HashMap<Vec<u8>, StagedChunk>,
    // Fields are dropped in order, so the lock is released only after the staging
    // directory is removed, which garbage collection would otherwise race.
    _lock: StoreLock,
}

/// Chunk written to the staging directory.
struct StagedChunk {
    path: PathBuf,
    compression: Option<CompressionFormat>,
}

impl ObjectWriter {
    pub(crate) fn new(
        layout: Layout,
        chunker_algorithm: ChunkerAlgorithm,
        algorithm: HashAlgorithm,
    ) -> StoreResult<Self> {
        let lock = layout.create_and_lock(LockMode::Shared)?;
        let tmp_dir = layout.tmp_dir();
        fs::create_dir_all(&tmp_dir).whatever("unable to create store staging directory")?;
        let staging = tempfile::Builder::new()
            .prefix("write-")
            .tempdir_in(&tmp_dir)
            .whatever("unable to create store staging directory")?;
        let chunker = chunker_algorithm
            .chunker()
            .whatever("invalid chunker configuration")?;
        Ok(Self {
            layout,
            staging,
            chunker_algorithm,
            chunker,
            algorithm,
            pending: Vec::new(),
            hashes: Vec::new(),
            sizes: Vec::new(),
            offsets: Vec::new(),
            size: 0,
            staged: HashMap::new(),
            _lock: lock,
        })
    }

    /// Make the file durable, point the ref `name` at it, and return its object ID.
    ///
    /// Replaces an existing ref of the same name.
    #[tracing::instrument(level = "debug", skip(self), fields(name = %name))]
    pub fn commit(mut self, name: &RefName) -> StoreResult<ObjectId> {
        if !self.pending.is_empty() {
            self.add_pending_chunk()?;
        }
        let object = Object::new(
            self.chunker_algorithm.clone(),
            self.algorithm,
            std::mem::take(&mut self.hashes),
            &self.sizes,
        );
        let (id, encoded) = object.encode();
        let staged_object = self.staging.path().join("object");
        fs::write(&staged_object, &encoded).whatever("unable to stage object")?;
        self.layout.sync()?;
        for (hash, staged) in &self.staged {
            let path = self
                .layout
                .chunk_path(self.algorithm, hash, staged.compression);
            move_into_place(&staged.path, &path).whatever("unable to commit chunk")?;
        }
        move_into_place(&staged_object, &self.layout.object_path(&id))
            .whatever("unable to commit object")?;
        self.layout.sync()?;
        self.layout.write_ref(name, &id, self.staging.path())?;
        debug!(object = %id, chunks = self.sizes.len(), new_chunks = self.staged.len(), "committed object");
        Ok(id)
    }

    /// Record the pending bytes of the stream as a chunk.
    fn add_pending_chunk(&mut self) -> StoreResult<()> {
        let data = std::mem::take(&mut self.pending);
        let hash = self.algorithm.hash::<Box<[u8]>>(&data);
        self.add_chunk(hash.raw(), &data, None)
    }

    /// Record a chunk of the content and stage it unless the store has it already.
    fn add_chunk(
        &mut self,
        hash: &[u8],
        data: &[u8],
        compressed: Option<(CompressionFormat, &[u8])>,
    ) -> StoreResult<()> {
        let size = u32::try_from(data.len()).whatever("chunk is larger than 4 GiB")?;
        self.hashes.extend_from_slice(hash);
        self.sizes.push(size);
        self.offsets.push(self.size);
        self.size += u64::from(size);
        if self.staged.contains_key(hash) || self.layout.find_chunk(self.algorithm, hash).is_some()
        {
            return Ok(());
        }
        let (bytes, compression) = match compressed {
            Some((format, bytes))
                if CHUNK_COMPRESSIONS.contains(&Some(format)) && bytes.len() < data.len() =>
            {
                (bytes.to_vec(), Some(format))
            }
            _ => chunk::compress(data)?,
        };
        let mut path = self.staging.path().join(hex::encode(hash));
        if let Some(compression) = compression {
            path.set_extension(compression.as_str());
        }
        fs::write(&path, bytes).whatever("unable to stage chunk")?;
        self.staged
            .insert(hash.to_vec(), StagedChunk { path, compression });
        Ok(())
    }

    /// Read back the content of the chunk at `offset`.
    fn read_chunk_at(&self, offset: u64) -> StoreResult<Vec<u8>> {
        let Ok(chunk) = self.offsets.binary_search(&offset) else {
            bail!("no chunk starts at offset {offset}");
        };
        let size = self.algorithm.hash_size();
        let hash = &self.hashes[chunk * size..(chunk + 1) * size];
        let (path, compression) = match self.staged.get(hash) {
            Some(staged) => (staged.path.clone(), staged.compression),
            None => self
                .layout
                .find_chunk(self.algorithm, hash)
                .ok_or_else(|| whatever!("chunk at offset {offset} is missing"))?,
        };
        chunk::read(&path, compression, self.algorithm, hash)
    }
}

impl Write for ObjectWriter {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let written = bytes.len();
        while !bytes.is_empty() {
            let boundary = self.chunker.scan(bytes);
            let end = boundary.unwrap_or(bytes.len());
            self.pending.extend_from_slice(&bytes[..end]);
            bytes = &bytes[end..];
            if boundary.is_some() {
                self.add_pending_chunk()
                    .map_err(|error| io::Error::other(format!("{error:?}")))?;
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PayloadTarget for &mut ObjectWriter {
    fn write(&mut self, bytes: &[u8]) -> BundleResult<()> {
        self.write_all(bytes).whatever("unable to write to store")
    }

    fn write_block(&mut self, block: &VerifiedBlock<'_>) -> BundleResult<()> {
        self.add_chunk(
            block.hash,
            block.data,
            block
                .compressed
                .map(|compressed| (compressed.format, compressed.bytes)),
        )
        .whatever("unable to write block to store")
    }

    fn read_block(
        &mut self,
        offset: NumBytes,
        size: NumBytes,
        buffer: &mut Vec<u8>,
    ) -> BundleResult<()> {
        *buffer = self
            .read_chunk_at(offset.raw)
            .whatever("unable to read block from store")?;
        if buffer.len() as u64 != size.raw {
            bail!("stored block at offset {offset} has an unexpected size");
        }
        Ok(())
    }
}

/// Rename a file into place, creating its parent directory.
fn move_into_place(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to.parent().expect("store files are in subdirectories"))?;
    fs::rename(from, to)
}
