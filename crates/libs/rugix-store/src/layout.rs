//! Paths, locking, and directory listings of the store layout.

use std::fs;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use nix::fcntl::Flock;
use nix::fcntl::FlockArg;
use reportify::ResultExt;
use reportify::whatever;
use rugix_compression::CompressionFormat;
use si_crypto_hashes::HashAlgorithm;
use tracing::warn;

use crate::ObjectId;
use crate::RefName;
use crate::StoreResult;

/// Lock held while accessing the store.
pub(crate) type StoreLock = Flock<File>;

/// Mode of a [`StoreLock`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum LockMode {
    /// Readers and writers that must not lose data to garbage collection.
    Shared,
    /// Garbage collection, which deletes unreachable data.
    Exclusive,
}

/// Paths of a store rooted at a directory.
#[derive(Debug, Clone)]
pub(crate) struct Layout {
    root: PathBuf,
}

impl Layout {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Lock the store, returning `None` if nothing has been written to it yet.
    ///
    /// Such a store is empty. The lock file is opened read-only, so reading never
    /// writes to the file system.
    pub(crate) fn lock(&self, mode: LockMode) -> StoreResult<Option<StoreLock>> {
        match File::open(self.lock_path()) {
            Ok(file) => lock_file(file, mode).map(Some),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).whatever("unable to open store lock"),
        }
    }

    /// Lock the store, creating it if necessary.
    ///
    /// The store is private to its owner, which also keeps other users from blocking
    /// garbage collection by locking the store.
    pub(crate) fn create_and_lock(&self, mode: LockMode) -> StoreResult<StoreLock> {
        if let Some(parent) = self.root.parent() {
            fs::create_dir_all(parent).whatever("unable to create store directory")?;
        }
        match fs::DirBuilder::new().mode(0o700).create(&self.root) {
            Err(error) if error.kind() != ErrorKind::AlreadyExists => {
                return Err(error).whatever("unable to create store directory");
            }
            _ => {}
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.lock_path())
            .whatever("unable to open store lock")?;
        lock_file(file, mode)
    }

    /// Flush all data on the store's file system to disk.
    pub(crate) fn sync(&self) -> StoreResult<()> {
        let root = File::open(&self.root).whatever("unable to open store directory")?;
        nix::unistd::syncfs(root.as_raw_fd()).whatever("unable to synchronize store")
    }

    /// Directory with staging directories of writers.
    pub(crate) fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Path of the ref `name`.
    pub(crate) fn ref_path(&self, name: &RefName) -> PathBuf {
        self.refs_dir().join(name.as_path())
    }

    /// Path of a chunk with the given hash and compression.
    pub(crate) fn chunk_path(
        &self,
        algorithm: HashAlgorithm,
        hash: &[u8],
        compression: Option<CompressionFormat>,
    ) -> PathBuf {
        let path = hashed_path(&self.root.join("chunks"), algorithm, hash);
        match compression {
            Some(compression) => path.with_extension(compression.as_str()),
            None => path,
        }
    }

    /// Find a committed chunk, returning its path and compression.
    pub(crate) fn find_chunk(
        &self,
        algorithm: HashAlgorithm,
        hash: &[u8],
    ) -> Option<(PathBuf, Option<CompressionFormat>)> {
        CHUNK_COMPRESSIONS
            .into_iter()
            .map(|compression| (self.chunk_path(algorithm, hash, compression), compression))
            .find(|(path, _)| path.exists())
    }

    /// Path of the object with the given ID.
    pub(crate) fn object_path(&self, object: &ObjectId) -> PathBuf {
        hashed_path(&self.root.join("objects"), object.algorithm(), object.raw())
    }

    /// List all committed chunks.
    pub(crate) fn chunks(&self) -> StoreResult<Vec<ChunkFile>> {
        let mut chunks = Vec::new();
        for (algorithm, name, path) in hashed_files(&self.root.join("chunks"))? {
            let (hex, compression) = match name.split_once('.') {
                Some((hex, extension)) => match CompressionFormat::from_str(extension) {
                    Ok(compression) => (hex, Some(compression)),
                    Err(_) => {
                        warn!(path = ?path, "ignoring chunk with unknown compression");
                        continue;
                    }
                },
                None => (name.as_str(), None),
            };
            match decode_hash(algorithm, hex) {
                Some(hash) => chunks.push(ChunkFile {
                    algorithm,
                    hash,
                    compression,
                    path,
                }),
                None => warn!(path = ?path, "ignoring chunk with invalid name"),
            }
        }
        Ok(chunks)
    }

    /// List all committed objects.
    pub(crate) fn objects(&self) -> StoreResult<Vec<(ObjectId, PathBuf)>> {
        let mut objects = Vec::new();
        for (algorithm, name, path) in hashed_files(&self.root.join("objects"))? {
            match decode_hash(algorithm, &name) {
                Some(hash) => objects.push((
                    ObjectId::new(algorithm, hash.into()).expect("hash has the algorithm's size"),
                    path,
                )),
                None => warn!(path = ?path, "ignoring object with invalid name"),
            }
        }
        Ok(objects)
    }

    /// List the refs at or below `prefix`, or all refs, ordered by name.
    pub(crate) fn refs(&self, prefix: Option<&RefName>) -> StoreResult<Vec<(String, ObjectId)>> {
        let (path, name) = match prefix {
            Some(prefix) => (self.ref_path(prefix), prefix.as_str().to_owned()),
            None => (self.refs_dir(), String::new()),
        };
        let mut refs = Vec::new();
        collect_refs(&path, name, &mut refs)?;
        Ok(refs)
    }

    /// Remove the ref `name` or all refs below it.
    ///
    /// Leaves empty directories behind, because a concurrent writer may be about to
    /// place a ref into them. Garbage collection prunes them.
    pub(crate) fn remove_refs(&self, name: &RefName) -> StoreResult<()> {
        let path = self.ref_path(name);
        let result = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&path),
            Ok(_) => fs::remove_file(&path),
            Err(error) => Err(error),
        };
        match result {
            Err(error)
                if !matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) =>
            {
                Err(error).whatever("unable to remove ref")
            }
            _ => Ok(()),
        }
    }

    /// Remove empty directories below `refs/`. Requires the exclusive lock.
    pub(crate) fn prune_refs(&self) -> StoreResult<()> {
        prune_empty_dirs(&self.refs_dir())
    }

    /// Atomically and durably point the ref `name` at `object`.
    ///
    /// The new ref content is written to `staging` first and then renamed into place.
    pub(crate) fn write_ref(
        &self,
        name: &RefName,
        object: &ObjectId,
        staging: &Path,
    ) -> StoreResult<()> {
        let staged = staging.join("ref");
        let mut file = File::create(&staged).whatever("unable to create ref")?;
        writeln!(file, "{object}").whatever("unable to write ref")?;
        file.sync_all().whatever("unable to synchronize ref")?;
        let path = self.ref_path(name);
        let parent = path
            .parent()
            .expect("ref paths are below the refs directory");
        fs::create_dir_all(parent).whatever("unable to create ref directory")?;
        fs::rename(&staged, &path).whatever("unable to move ref into place")?;
        // Synchronizing only the parent would not cover newly created directories.
        self.sync()
    }

    fn lock_path(&self) -> PathBuf {
        self.root.join("lock")
    }

    fn refs_dir(&self) -> PathBuf {
        self.root.join("refs")
    }
}

/// Compressions of chunks, in the order in which they are probed.
pub(crate) const CHUNK_COMPRESSIONS: [Option<CompressionFormat>; 2] =
    [Some(CompressionFormat::Xz), None];

/// Committed chunk file.
pub(crate) struct ChunkFile {
    pub(crate) algorithm: HashAlgorithm,
    pub(crate) hash: Vec<u8>,
    pub(crate) compression: Option<CompressionFormat>,
    pub(crate) path: PathBuf,
}

/// Lock an open lock file.
fn lock_file(file: File, mode: LockMode) -> StoreResult<StoreLock> {
    let arg = match mode {
        LockMode::Shared => FlockArg::LockShared,
        LockMode::Exclusive => FlockArg::LockExclusive,
    };
    Flock::lock(file, arg)
        .map_err(|(_, errno)| errno)
        .whatever("unable to lock store")
}

/// Parse the content of a ref.
pub(crate) fn parse_ref(content: &str) -> StoreResult<ObjectId> {
    content
        .trim()
        .parse()
        .map_err(|_| whatever!("ref does not contain an object ID"))
}

/// Path of a file named after `hash` below `<base>/<algorithm>/<xx>/`.
fn hashed_path(base: &Path, algorithm: HashAlgorithm, hash: &[u8]) -> PathBuf {
    let hex = hex::encode(hash);
    base.join(format!("{algorithm:#}"))
        .join(&hex[..2])
        .join(&hex)
}

/// List the files below `<base>/<algorithm>/<xx>/` with their algorithm and name.
fn hashed_files(base: &Path) -> StoreResult<Vec<(HashAlgorithm, String, PathBuf)>> {
    let mut files = Vec::new();
    for algorithm_entry in read_dir_if_exists(base)? {
        let name = algorithm_entry.file_name();
        let Ok(algorithm) = HashAlgorithm::from_str(&name.to_string_lossy()) else {
            warn!(path = ?algorithm_entry.path(), "ignoring unknown hash algorithm");
            continue;
        };
        for prefix_entry in read_dir_if_exists(&algorithm_entry.path())? {
            for entry in read_dir_if_exists(&prefix_entry.path())? {
                files.push((
                    algorithm,
                    entry.file_name().to_string_lossy().into_owned(),
                    entry.path(),
                ));
            }
        }
    }
    Ok(files)
}

/// List a directory, treating a missing directory as empty.
fn read_dir_if_exists(path: &Path) -> StoreResult<Vec<fs::DirEntry>> {
    match fs::read_dir(path) {
        Ok(entries) => entries
            .collect::<Result<Vec<_>, _>>()
            .whatever("unable to list store directory"),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).whatever("unable to list store directory"),
    }
}

/// Decode a hex-encoded hash of the given algorithm.
fn decode_hash(algorithm: HashAlgorithm, hex: &str) -> Option<Vec<u8>> {
    hex::decode(hex)
        .ok()
        .filter(|hash| hash.len() == algorithm.hash_size())
}

/// Collect the refs at or below `path`, which is the ref `name`.
///
/// Refs removed concurrently are skipped.
fn collect_refs(path: &Path, name: String, refs: &mut Vec<(String, ObjectId)>) -> StoreResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return Ok(());
        }
        Err(error) => return Err(error).whatever("unable to read ref"),
    };
    if !metadata.is_dir() {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).whatever("unable to read ref"),
        };
        let object = parse_ref(&content).whatever_with(|_| format!("invalid ref {name}"))?;
        refs.push((name, object));
        return Ok(());
    }
    let mut entries = read_dir_if_exists(path)?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let child = entry.file_name().to_string_lossy().into_owned();
        let child_name = if name.is_empty() {
            child
        } else {
            format!("{name}/{child}")
        };
        collect_refs(&entry.path(), child_name, refs)?;
    }
    Ok(())
}

/// Remove the empty directories below `path`, deepest first.
///
/// Removing refs needs no lock, so directories may disappear concurrently.
fn prune_empty_dirs(path: &Path) -> StoreResult<()> {
    for entry in read_dir_if_exists(path)? {
        match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => {}
            Ok(_) => continue,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error).whatever("unable to read ref directory entry"),
        }
        prune_empty_dirs(&entry.path())?;
        match fs::remove_dir(entry.path()) {
            Err(error)
                if !matches!(
                    error.kind(),
                    ErrorKind::DirectoryNotEmpty | ErrorKind::NotFound
                ) =>
            {
                return Err(error).whatever("unable to remove empty ref directory");
            }
            _ => {}
        }
    }
    Ok(())
}
