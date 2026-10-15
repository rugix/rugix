//! Content-addressed file store that deduplicates and compresses chunks.
//!
//! A [`Store`] keeps files as lists of chunks. Chunks are named after the hash of
//! their content, so a chunk shared by several files, generations, or owners is
//! stored once. Each chunk is compressed on its own, which keeps random access to a
//! stored file cheap.
//!
//! - [`Store::writer`] creates an [`ObjectWriter`] that adds a file to the store and
//!   names it with a ref. The writer is also a bundle [`PayloadTarget`], so it keeps
//!   compressed bundle blocks as they arrive.
//! - [`Store::open`] reads a stored file through an [`ObjectReader`].
//! - [`Store::block_provider`] offers stored chunks as local block candidates when
//!   installing a bundle.
//! - [`Store::remove`] removes refs and [`Store::gc`] deletes everything that no ref
//!   reaches.
//!
//! # Layout
//!
//! ```text
//! <root>/
//!   lock
//!   tmp/
//!   chunks/<hash-algorithm>/<xx>/<hash>[.xz]
//!   objects/<hash-algorithm>/<xx>/<hash>
//!   refs/<name>
//! ```
//!
//! `<xx>` is the first byte of the hash in hex.
//!
//! - A **chunk** holds a block of file content, named after the hash of its uncompressed
//!   bytes. The suffix records its compression.
//! - An **object** describes one stored file as a [block index]: how the file was chunked
//!   and the hashes and sizes of its chunks. Its name, the [`ObjectId`], is the hash of
//!   the encoded index.
//! - A **ref** is a file containing an object ID. Owners name their files with refs in
//!   their own namespace, for example `apps/<app>/<generation>/<path>`.
//!
//! # Consistency
//!
//! Writers stage new chunks and the object in a private directory under `tmp/`.
//! Committing synchronizes the file system, moves chunks and the object into place,
//! synchronizes again, and then writes the ref atomically. A chunk or object in
//! place therefore always has durable content, and a crash leaves at most
//! unreferenced data behind.
//!
//! Writers, readers, and block providers hold a shared lock on `lock`. Garbage
//! collection holds it exclusively, so it never deletes data in use and can empty
//! `tmp/`. Everything reachable from a ref survives garbage collection.
//!
//! [`PayloadTarget`]: rugix_bundle::reader::PayloadTarget
//! [block index]: rugix_bundle::format::BlockIndex

use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;

use byte_calc::NumBytes;
use reportify::Report;
use reportify::ResultExt;
use rugix_chunker::ChunkerAlgorithm;
use rugix_common::path::ValidatedRelativePath;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;

use crate::layout::Layout;
use crate::layout::LockMode;
use crate::object::Object;

mod chunk;
mod gc;
mod layout;
mod object;
mod provider;
mod reader;
mod writer;

pub use gc::GcSummary;
pub use gc::StoreInfo;
pub use provider::StoreBlockProvider;
pub use reader::ObjectReader;
pub use writer::ObjectWriter;

reportify::new_whatever_type! {
    /// Error accessing a store.
    pub StoreError
}

/// Result with [`StoreError`] as error type.
pub type StoreResult<T> = Result<T, Report<StoreError>>;

/// Name of a stored object: the hash of its encoded block index.
pub type ObjectId = HashDigest;

/// Name of a ref, a relative path below `refs/`.
pub type RefName = ValidatedRelativePath;

/// Chunker used for files that do not arrive as blocks of a bundle.
pub const DEFAULT_CHUNKER: ChunkerAlgorithm = ChunkerAlgorithm::Casync {
    avg_block_size_kib: 64,
};

/// Hash algorithm used for files that do not arrive as blocks of a bundle.
pub const DEFAULT_HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha512_256;

/// Content-addressed file store rooted at a directory.
///
/// Creating a store does not touch the file system. Directories are created when
/// the store is first locked.
#[derive(Debug, Clone)]
pub struct Store {
    layout: Layout,
}

impl Store {
    /// Create a handle for the store at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            layout: Layout::new(root.into()),
        }
    }

    /// Root directory of the store.
    pub fn root(&self) -> &Path {
        self.layout.root()
    }

    /// Start adding a file that is split with `chunker` and hashed with `hash_algorithm`.
    ///
    /// Use the chunker and hash algorithm of a bundle payload when writing its blocks
    /// with [`ObjectWriter::write_block`](rugix_bundle::reader::PayloadTarget).
    pub fn writer(
        &self,
        chunker: ChunkerAlgorithm,
        hash_algorithm: HashAlgorithm,
    ) -> StoreResult<ObjectWriter> {
        ObjectWriter::new(self.layout.clone(), chunker, hash_algorithm)
    }

    /// Open a stored object for reading.
    pub fn open(&self, object: &ObjectId) -> StoreResult<ObjectReader> {
        let lock = self.layout.lock(LockMode::Shared)?;
        let object = Object::load(&self.layout, object)?;
        Ok(ObjectReader::new(self.layout.clone(), lock, object))
    }

    /// Offer stored chunks hashed with `hash_algorithm` as local block candidates.
    pub fn block_provider(&self, hash_algorithm: HashAlgorithm) -> StoreResult<StoreBlockProvider> {
        StoreBlockProvider::new(&self.layout, hash_algorithm)
    }

    /// Resolve a ref to the object it names.
    pub fn resolve(&self, name: &RefName) -> StoreResult<Option<ObjectId>> {
        match fs::read_to_string(self.layout.ref_path(name)) {
            Ok(content) => Ok(Some(layout::parse_ref(&content)?)),
            Err(error)
                if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) =>
            {
                Ok(None)
            }
            Err(error) => Err(error).whatever("unable to read ref"),
        }
    }

    /// List the refs at or below `prefix`, or all refs, ordered by name.
    pub fn list(&self, prefix: Option<&RefName>) -> StoreResult<Vec<StoreRef>> {
        Ok(self
            .layout
            .refs(prefix)?
            .into_iter()
            .map(|(name, object)| StoreRef { name, object })
            .collect())
    }

    /// Size of the content of a stored object.
    pub fn size(&self, object: &ObjectId) -> StoreResult<NumBytes> {
        Ok(Object::load(&self.layout, object)?.size())
    }

    /// Remove the ref `name` or all refs below it.
    ///
    /// The data stays in the store until the next [garbage collection](Self::gc).
    pub fn remove(&self, name: &RefName) -> StoreResult<()> {
        self.layout.remove_refs(name)
    }

    /// Delete all objects and chunks that no ref reaches and empty `tmp/`.
    pub fn gc(&self) -> StoreResult<GcSummary> {
        gc::collect(&self.layout)
    }

    /// Check that all referenced objects and their chunks are intact.
    ///
    /// Returns a description of every problem found.
    pub fn verify(&self) -> StoreResult<Vec<String>> {
        gc::verify(&self.layout)
    }

    /// Summarize the contents of the store.
    pub fn info(&self) -> StoreResult<StoreInfo> {
        gc::info(&self.layout)
    }
}

/// Ref together with the object it names.
#[derive(Debug, Clone)]
pub struct StoreRef {
    /// Name of the ref.
    pub name: String,
    /// Object the ref names.
    pub object: ObjectId,
}

/// Identity and size of a committed object.
#[derive(Debug, Clone)]
pub struct ObjectInfo {
    /// ID of the object.
    pub id: ObjectId,
    /// Size of the object's content.
    pub size: NumBytes,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Read;
    use std::io::Write;

    use rugix_bundle::reader::BundleReader;
    use rugix_bundle::reader::BundleSource;
    use rugix_bundle::reader::StoredBlockProvider;
    use rugix_compression::CompressionFormat;

    use super::DEFAULT_CHUNKER;
    use super::DEFAULT_HASH_ALGORITHM;
    use super::RefName;
    use super::Store;

    /// Deterministic bytes that do not compress.
    fn random_bytes(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect()
    }

    fn name(name: &str) -> RefName {
        RefName::new(name).unwrap()
    }

    fn write(store: &Store, ref_name: &str, data: &[u8]) {
        let mut writer = store
            .writer(DEFAULT_CHUNKER, DEFAULT_HASH_ALGORITHM)
            .unwrap();
        writer.write_all(data).unwrap();
        writer.commit(&name(ref_name)).unwrap();
    }

    fn read(store: &Store, ref_name: &str) -> Vec<u8> {
        let object = store.resolve(&name(ref_name)).unwrap().unwrap();
        let mut data = Vec::new();
        store.open(&object).unwrap().read_to_end(&mut data).unwrap();
        data
    }

    /// Verifies that files share stored chunks and read back intact, and that garbage
    /// collection deletes exactly the data no ref reaches.
    #[test]
    fn shared_chunks_are_stored_once_and_collected_when_unreferenced() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path().join("store"));
        let first = random_bytes(1, 1024 * 1024);
        let second = [first.as_slice(), &random_bytes(2, 256 * 1024)].concat();
        write(&store, "a/file", &first);
        write(&store, "b/file", &second);
        let mut uncommitted = store
            .writer(DEFAULT_CHUNKER, DEFAULT_HASH_ALGORITHM)
            .unwrap();
        uncommitted.write_all(&random_bytes(3, 256 * 1024)).unwrap();
        drop(uncommitted);

        let info = store.info().unwrap();
        assert_eq!(info.refs, 2);
        assert_eq!(
            info.referenced_size.raw,
            (first.len() + second.len()) as u64
        );
        // Random bytes do not compress, so only deduplication saves space. Only the
        // final chunk of the first file, at most 256 KiB, is not shared.
        assert!(info.stored_size.raw < (second.len() + 320 * 1024) as u64);
        assert_eq!(read(&store, "a/file"), first);
        assert_eq!(read(&store, "b/file"), second);

        store.remove(&name("a")).unwrap();
        assert_eq!(store.gc().unwrap().removed_objects, 1);
        assert_eq!(read(&store, "b/file"), second);
        assert!(store.verify().unwrap().is_empty());

        store.remove(&name("b/file")).unwrap();
        store.gc().unwrap();
        let info = store.info().unwrap();
        assert_eq!((info.refs, info.objects, info.chunks), (0, 0, 0));
        assert!(!directory.path().join("store/refs/b").exists());
    }

    /// Verifies that bundle blocks keep their compressed bundle bytes, that duplicate
    /// blocks are read back from the writer, and that stored chunks are offered as
    /// local block candidates.
    #[test]
    fn bundle_blocks_are_stored_compressed_and_offered_as_candidates() {
        let directory = tempfile::tempdir().unwrap();
        let bundle_dir = directory.path().join("bundle");
        fs::create_dir_all(bundle_dir.join("payloads")).unwrap();
        let text = (0..40_000)
            .map(|line| format!("line {line}\n"))
            .collect::<String>();
        let content = [text.as_bytes(), text.as_bytes()].concat();
        fs::write(bundle_dir.join("payloads/file"), &content).unwrap();
        fs::write(
            bundle_dir.join("rugix-bundle.toml"),
            r#"
            update-type = "full"
            [[payloads]]
            filename = "file"
            delivery = { type = "app-file", app = "example", path = "file", store = true }
            block-encoding = { chunker = "casync-64", deduplicate = true, compression = { type = "xz" } }
            "#,
        )
        .unwrap();
        let bundle = directory.path().join("bundle.rugixb");
        rugix_bundle::builder::pack(&bundle_dir, &bundle).unwrap();

        let source = BundleSource::from_seekable(File::open(&bundle).unwrap()).unwrap();
        let mut reader = BundleReader::start(source, None).unwrap();
        let payload = reader.next_payload().unwrap().unwrap();
        let encoding = payload.header().block_encoding.clone().unwrap();
        let store = Store::new(directory.path().join("store"));
        let mut writer = store
            .writer(encoding.chunker.clone(), encoding.hash_algorithm)
            .unwrap();
        payload.decode_into(&mut writer, None, &mut |_| {}).unwrap();
        writer.commit(&name("example/file")).unwrap();

        assert_eq!(read(&store, "example/file"), content);
        let chunks = store.layout.chunks().unwrap();
        assert!(!chunks.is_empty());
        let provider = store.block_provider(encoding.hash_algorithm).unwrap();
        for chunk in &chunks {
            assert_eq!(chunk.compression, Some(CompressionFormat::Xz));
            let block = provider.query(&chunk.hash).unwrap();
            assert_eq!(block.file, chunk.path);
            assert_eq!(block.compression, Some(CompressionFormat::Xz));
            assert_eq!(block.size.raw, fs::metadata(&chunk.path).unwrap().len());
        }
    }

    /// Verifies that a corrupted chunk is reported by verification and fails reading.
    #[test]
    fn corrupted_chunks_are_detected() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path().join("store"));
        write(&store, "file", &random_bytes(4, 256 * 1024));
        let chunk = store.layout.chunks().unwrap().remove(0);
        fs::write(&chunk.path, b"corrupted").unwrap();

        assert_eq!(store.verify().unwrap().len(), 1);
        let object = store.resolve(&name("file")).unwrap().unwrap();
        let mut data = Vec::new();
        assert!(store.open(&object).unwrap().read_to_end(&mut data).is_err());
    }
}
