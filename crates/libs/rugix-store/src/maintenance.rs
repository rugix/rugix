//! Garbage collection, verification, and statistics of the whole store.

use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use byte_calc::NumBytes;
use reportify::ResultExt;
use si_crypto_hashes::HashAlgorithm;
use tracing::info;

use crate::ObjectId;
use crate::RefName;
use crate::StoreResult;
use crate::chunk;
use crate::layout::Layout;
use crate::layout::LockMode;
use crate::object::Object;

/// Result of a garbage collection.
#[derive(Debug, Clone)]
pub struct GcSummary {
    /// Number of removed refs.
    pub removed_refs: u64,
    /// Number of deleted objects.
    pub removed_objects: u64,
    /// Number of deleted chunks.
    pub removed_chunks: u64,
    /// Disk space of the deleted objects and chunks.
    pub freed_size: NumBytes,
}

/// Summary of the contents of a store.
#[derive(Debug, Clone)]
pub struct StoreInfo {
    /// Number of refs.
    pub refs: u64,
    /// Number of objects.
    pub objects: u64,
    /// Number of chunks.
    pub chunks: u64,
    /// Total content size of all refs, counting shared content once per ref.
    pub referenced_size: NumBytes,
    /// Disk space of all objects and chunks.
    pub stored_size: NumBytes,
}

#[tracing::instrument(level = "debug", skip_all)]
pub(crate) fn collect(layout: &Layout, retain: impl Fn(&str) -> bool) -> StoreResult<GcSummary> {
    let mut summary = GcSummary {
        removed_refs: 0,
        removed_objects: 0,
        removed_chunks: 0,
        freed_size: NumBytes::ZERO,
    };
    let Some(_lock) = layout.lock(LockMode::Exclusive)? else {
        return Ok(summary);
    };
    let mut live_objects = HashSet::<ObjectId>::new();
    for (name, object) in layout.refs(None)? {
        if retain(&name) {
            live_objects.insert(object);
        } else {
            layout.remove_refs(&RefName::new(name).whatever("invalid ref name")?)?;
            summary.removed_refs += 1;
        }
    }
    layout.prune_refs()?;
    // Removed refs must not reappear after a crash once their chunks are deleted.
    layout.sync()?;
    let mut live_chunks = HashSet::<(HashAlgorithm, Vec<u8>)>::new();
    for (id, path) in layout.objects()? {
        if live_objects.contains(&id) {
            let object = Object::load(layout, &id)?;
            live_chunks.extend(
                object
                    .chunks()
                    .map(|(hash, _)| (object.algorithm(), hash.to_vec())),
            );
        } else {
            summary.freed_size += remove(&path)?;
            summary.removed_objects += 1;
        }
    }
    for chunk in layout.chunks()? {
        if !live_chunks.contains(&(chunk.algorithm, chunk.hash)) {
            summary.freed_size += remove(&chunk.path)?;
            summary.removed_chunks += 1;
        }
    }
    match fs::read_dir(layout.tmp_dir()) {
        Ok(entries) => {
            for entry in entries {
                let path = entry
                    .whatever("unable to list store staging directory")?
                    .path();
                fs::remove_dir_all(&path).whatever("unable to remove staging directory")?;
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).whatever("unable to list store staging directory"),
    }
    info!(
        refs = summary.removed_refs,
        objects = summary.removed_objects,
        chunks = summary.removed_chunks,
        freed = %summary.freed_size,
        "collected store garbage"
    );
    Ok(summary)
}

#[tracing::instrument(level = "debug", skip_all)]
pub(crate) fn verify(layout: &Layout) -> StoreResult<Vec<String>> {
    let _lock = layout.lock(LockMode::Shared)?;
    let mut problems = Vec::new();
    let mut checked = HashSet::<(HashAlgorithm, Vec<u8>)>::new();
    for (name, id) in layout.refs(None)? {
        let object = match Object::load(layout, &id) {
            Ok(object) => object,
            Err(error) => {
                problems.push(format!("ref {name}: {error}"));
                continue;
            }
        };
        let algorithm = object.algorithm();
        for (hash, size) in object.chunks() {
            if !checked.insert((algorithm, hash.to_vec())) {
                continue;
            }
            let Some((path, compression)) = layout.find_chunk(algorithm, hash) else {
                problems.push(format!(
                    "ref {name}: chunk {} is missing",
                    hex::encode(hash)
                ));
                continue;
            };
            match chunk::read(&path, compression, algorithm, hash) {
                Ok(data) if data.len() as u64 == u64::from(size) => {}
                Ok(_) => problems.push(format!(
                    "ref {name}: chunk {} has an unexpected size",
                    hex::encode(hash)
                )),
                Err(error) => problems.push(format!("ref {name}: {error}")),
            }
        }
    }
    Ok(problems)
}

pub(crate) fn info(layout: &Layout) -> StoreResult<StoreInfo> {
    let _lock = layout.lock(LockMode::Shared)?;
    let mut info = StoreInfo {
        refs: 0,
        objects: 0,
        chunks: 0,
        referenced_size: NumBytes::ZERO,
        stored_size: NumBytes::ZERO,
    };
    for (_, id) in layout.refs(None)? {
        info.refs += 1;
        info.referenced_size += Object::load(layout, &id)?.size();
    }
    for (_, path) in layout.objects()? {
        info.objects += 1;
        info.stored_size += file_size(&path)?;
    }
    for chunk in layout.chunks()? {
        info.chunks += 1;
        info.stored_size += file_size(&chunk.path)?;
    }
    Ok(info)
}

/// Remove a file and return its size.
fn remove(path: &Path) -> StoreResult<NumBytes> {
    let size = file_size(path)?;
    fs::remove_file(path).whatever_with(|_| format!("unable to remove {path:?}"))?;
    Ok(size)
}

fn file_size(path: &Path) -> StoreResult<NumBytes> {
    Ok(NumBytes::new(
        fs::metadata(path)
            .whatever_with(|_| format!("unable to read metadata of {path:?}"))?
            .len(),
    ))
}
