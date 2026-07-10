//! Abortable, blocking filesystem APIs with good error reporting.

use std::fs::Metadata;
use std::io::Seek;
use std::io::Write;
use std::io::{self};
use std::os::fd::AsRawFd;
use std::os::raw::c_void;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use tracing::error;
use tracing::trace;

use byte_calc::ByteLen;
use byte_calc::NumBytes;
use reportify::new_whatever_type;
use reportify::whatever;
use reportify::ErrorExt;
use reportify::Report;
use reportify::ResultExt;

use rugix_tasks::check_canceled;
use rugix_tasks::spawn_blocking;

#[cfg(not(target_family = "unix"))]
compile_error!("only Unix-like systems are supported");

new_whatever_type! {
    /// Error carrying out a filesystem operation.
    pub FsError
}

/// Type alias for the result of filesystem APIs.
pub type FsResult<T> = Result<T, Report<FsError>>;

/// Slice of zeros.
static ZEROS: &[u8] = &[0; 4096];

/// File opened in a blocking context.
#[derive(Debug)]
pub struct File {
    /// Underlying owned file descriptor.
    file: std::fs::File,
}

impl File {
    /// Create and truncate the file.
    pub fn create(path: &Path) -> FsResult<Self> {
        check_canceled();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(path)
            .whatever("unable to create file")?;
        Ok(Self { file })
    }

    /// Open a file for reading.
    pub fn open_read(path: &Path) -> FsResult<Self> {
        check_canceled();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .whatever("unable to open file")?;
        Ok(Self { file })
    }

    /// Open a file for reading and writing.
    pub fn open_write(path: &Path) -> FsResult<Self> {
        check_canceled();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .whatever("unable to open file")?;
        Ok(Self { file })
    }

    /// Read the metadata of the file.
    pub fn read_metadata(&self) -> FsResult<Metadata> {
        check_canceled();
        self.file.metadata().whatever("unable to read metadata")
    }

    /// Get current position of the file.
    pub fn current_position(&mut self) -> FsResult<NumBytes> {
        check_canceled();
        self.file
            .stream_position()
            .whatever("unable to get file position")
            .map(NumBytes::new)
    }

    /// Set the current position of the file to the given position.
    pub fn set_current_position(&mut self, pos: NumBytes) -> FsResult<()> {
        check_canceled();
        trace!("set current position to {pos:#}");
        self.file
            .seek(std::io::SeekFrom::Start(pos.raw))
            .whatever("unable to seek to position")?;
        Ok(())
    }

    /// Read bytes into the provided vector starting at the current position.
    ///
    /// If no limit is provided, the file will be read until the end.
    ///
    /// The file will be read in chunks of at most 32 KiB. Between reading chunks, the
    /// blocking context will be checked for aborts.
    pub fn read_into_vec(&mut self, buffer: &mut Vec<u8>, limit: Option<NumBytes>) -> FsResult<()> {
        trace!(?limit, "reading bytes into vector");
        let raw_fd = self.file.as_raw_fd();
        let mut remaining = limit;
        loop {
            check_canceled();
            // Ensure that there is spare capacity in the buffer.
            buffer.reserve(4096);
            // Read into the vector without initializing the memory.
            let used = buffer.len();
            let free = buffer.capacity() - used;
            let ptr = buffer.as_mut_ptr().wrapping_add(used);
            let count = free.min(32768).min(
                usize::try_from(remaining.map(|remaining| remaining.raw).unwrap_or(u64::MAX))
                    .unwrap_or(usize::MAX),
            );
            let result = unsafe { nix::libc::read(raw_fd, ptr as *mut c_void, count) };
            match result.cmp(&0) {
                std::cmp::Ordering::Less => {
                    return Err(io::Error::last_os_error().whatever("unable to read from file"))
                }
                std::cmp::Ordering::Equal => {
                    // We reached the end of the file.
                    break;
                }
                std::cmp::Ordering::Greater => {
                    // SAFETY: The memory has been properly initialized by `read`.
                    unsafe { buffer.set_len(buffer.len() + result as usize) }
                    if let Some(remaining) = &mut remaining {
                        *remaining += u64::try_from(result).expect("must not overflow `u64`");
                    }
                }
            }
        }
        Ok(())
    }

    /// Read bytes into a vector starting at the current position.
    ///
    /// For details, see [`Self::read_into_vec`].
    pub fn read_to_vec(&mut self, limit: Option<NumBytes>) -> FsResult<Vec<u8>> {
        let mut buffer = Vec::new();
        self.read_into_vec(&mut buffer, limit)?;
        Ok(buffer)
    }

    /// Write the provided bytes to the file at the current position.
    ///
    /// Advances the current position by the number of bytes.
    pub fn write(&mut self, buf: &[u8]) -> FsResult<()> {
        check_canceled();
        trace!("writing {} bytes at current position", buf.len());
        self.file.write_all(buf).whatever("unable to write to file")
    }

    /// Write the provided bytes to the file at the given offset.
    ///
    /// Does not change the current position of the file.
    pub fn write_at(&mut self, offset: NumBytes, buf: &[u8]) -> FsResult<()> {
        check_canceled();
        trace!("writing {} bytes at offset {offset:#}", buf.len());
        self.file
            .write_all_at(buf, offset.raw)
            .whatever("unable to write to file")
    }

    /// Write zeros to the file at the given offset with the given length.
    ///
    /// Does not change the current position of the file.
    pub fn write_zeros(&mut self, mut offset: NumBytes, length: NumBytes) -> FsResult<()> {
        check_canceled();
        trace!("writing zeros at offset {offset:#} with length {length:#}");
        let mut remaining = length;
        while remaining > 0 {
            check_canceled();
            let write_len = remaining.min(ZEROS.byte_len());
            self.write_at(
                offset,
                &ZEROS[..usize::try_from(write_len.raw)
                    .expect("must fit into `usize` as it is bounded by `ZEROS.byte_len()`")],
            )?;
            remaining -= write_len;
            offset += write_len;
        }
        Ok(())
    }

    /// Punch a hole at the given offset and with the given size.
    ///
    /// Does not change the current position of the file.
    pub fn punch_hole(&mut self, offset: NumBytes, size: NumBytes) -> FsResult<()> {
        check_canceled();
        trace!("punching hole into file at offset {offset:#} with size {size:#}");
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            use std::os::linux::fs::MetadataExt;
            // spell:ignore FALLOC, blksize, ENOTSUP
            let metadata = self.read_metadata()?;
            // Ensure that the file is large enough for the hole.
            let file_size = NumBytes::new(metadata.len());
            if file_size < offset + size {
                self.allocate(offset, size)?;
            };
            // Holes can only be punched in multiples of the filesystem's block size. Hence,
            // we compute the start and end of the hole aligned to the block size.
            let block_size = NumBytes::new(metadata.st_blksize());
            let start_hole = offset.align_blocks_ceil(block_size);
            let end_hole = (offset + size).align_blocks_floor(block_size);
            let hole_size = end_hole - start_hole;
            if hole_size != 0 {
                if let Err(error) = nix::fcntl::fallocate(
                    self.file.as_raw_fd(),
                    nix::fcntl::FallocateFlags::FALLOC_FL_PUNCH_HOLE
                        | nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE,
                    start_hole
                        .raw
                        .try_into()
                        .expect("offset must not overflow `i64`"),
                    hole_size
                        .raw
                        .try_into()
                        .expect("offset must not overflow `i64`"),
                ) {
                    if error == nix::errno::Errno::ENOTSUP {
                        trace!("fallocate not supported, falling back to writing zeros");
                        return self.write_zeros(offset, size);
                    } else {
                        return Err(io::Error::from(error).whatever("unable to punch hole"));
                    }
                }
            };
            // We now fill the remaining loose ends of the hole with zeros.
            self.write_zeros(offset, start_hole - offset)?;
            self.write_zeros(end_hole, offset + size - end_hole)?;
            return Ok(());
        }
        #[cfg_attr(target_os = "linux", expect(unreachable_code))]
        self.write_zeros(offset, size)
    }

    /// Allocate blocks for the given size at the given offset.
    ///
    /// Does not change the current position of the file.
    pub fn allocate(&mut self, offset: NumBytes, size: NumBytes) -> FsResult<()> {
        check_canceled();
        trace!("allocating space at offset {offset:#} with size {size:#}");
        #[cfg(target_os = "linux")]
        match nix::fcntl::fallocate(
            self.file.as_raw_fd(),
            nix::fcntl::FallocateFlags::empty(),
            offset
                .raw
                .try_into()
                .expect("offset must not overflow `i64`"),
            size.raw.try_into().expect("size must not overflow `i64`"),
        ) {
            Err(nix::errno::Errno::ENOTSUP) => {
                trace!("fallocate not supported, falling back to `set_len`");
            }
            Err(error) => return Err(io::Error::from(error).whatever("unable to allocate")),
            Ok(()) => return Ok(()),
        };
        let metadata = self.read_metadata()?;
        let size = offset + size;
        if size > metadata.len() {
            self.file
                .set_len(size.raw)
                .whatever("unable to set file length")?;
        }
        Ok(())
    }
}

/// Create a directory.
pub fn create_dir(path: &Path) -> FsResult<()> {
    check_canceled();
    std::fs::create_dir(path).whatever("unable to create directory")
}

/// Create a directory recursively.
pub fn create_dir_recursive(path: &Path) -> FsResult<()> {
    check_canceled();
    std::fs::create_dir_all(path).whatever("unable to create directory")
}

/// Read metadata from path.
pub fn read_metadata(path: &Path) -> FsResult<Metadata> {
    check_canceled();
    std::fs::metadata(path).whatever("unable to read metadata")
}

/// Allocate a file with the given size.
///
/// If the file already exists, it will be truncated to the given size.
pub fn allocate_file(path: &Path, size: NumBytes) -> FsResult<()> {
    File::create(path)?.allocate(NumBytes::new(0), size)
}

/// Auxiliary data structure for copying files and directories.
#[derive(Debug, Clone)]
pub struct Copier {
    /// Buffer for copying.
    buffer: Vec<u8>,
    copy_permissions: bool,
    copy_ownership: bool,
}

impl Copier {
    /// Create a new [`Copier`] with default settings.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            copy_permissions: true,
            copy_ownership: true,
        }
    }

    pub fn copy_file(&mut self, src: &Path, dst: &Path) -> FsResult<()> {
        let metadata = read_metadata(src)?;
        if !metadata.is_file() {
            return Err(whatever!("not a file"));
        }
        self.copy_file_contents(src, dst)?;
        if self.copy_permissions {
            std::fs::set_permissions(&dst, metadata.permissions())
                .whatever("unable to set permissions")?;
        }
        if self.copy_ownership {
            let uid = metadata.uid();
            let gid = metadata.gid();
            std::os::unix::fs::chown(&dst, Some(uid), Some(gid))
                .whatever("unable to set ownership")?;
        }
        Ok(())
    }

    /// Copy a directory recursively.
    pub fn copy_dir(&mut self, src_dir: &Path, dst_dir: &Path) -> FsResult<()> {
        trace!("copy directory from {src_dir:?} to {dst_dir:?}");
        for entry in walkdir::WalkDir::new(src_dir).contents_first(true) {
            check_canceled();
            let entry = entry
                .whatever("unable to walk directory")
                .field_debug("dir", src_dir)?;
            let tail = entry
                .path()
                .strip_prefix(src_dir)
                .whatever("unable to strip path prefix from source path")
                .field_debug("path", entry.path())
                .field_debug("src", src_dir)?;
            let dst = dst_dir.join(tail);
            if let Some(parent) = dst.parent() {
                create_dir_recursive(parent)?;
            }
            if entry.file_type().is_dir() {
                if !dst.exists() {
                    create_dir(&dst)?;
                }
            } else if entry.file_type().is_file() {
                self.copy_file_contents(entry.path(), &dst)?;
            } else if entry.file_type().is_symlink() {
                let link_dst = entry
                    .path()
                    .read_link()
                    .whatever("unable to read symlink")?;
                std::os::unix::fs::symlink(&link_dst, &dst).whatever("unable to create symlink")?;
            } else if entry.file_type().is_block_device() {
                todo!("implement copy for block device");
            } else if entry.file_type().is_char_device() {
                todo!("implement copy for char device");
            } else {
                todo!("unknown file type");
            }
            let metadata = entry.metadata().whatever("unable to read metadata")?;
            if !entry.file_type().is_symlink() {
                if self.copy_permissions {
                    std::fs::set_permissions(&dst, metadata.permissions())
                        .whatever("unable to set permissions")?;
                }
                if self.copy_ownership {
                    let uid = metadata.uid();
                    let gid = metadata.gid();
                    std::os::unix::fs::chown(&dst, Some(uid), Some(gid))
                        .whatever("unable to set ownership")?;
                }
            }
        }
        Ok(())
    }

    /// Copy the contents of one file to the other, creating the destination if it does
    /// not exist.
    pub fn copy_file_contents(&mut self, src_file: &Path, dst_file: &Path) -> FsResult<()> {
        check_canceled();
        trace!("copy file contents from {src_file:?} to {dst_file:?}");
        let mut src = File::open_read(src_file)?;
        let mut dst = File::create(dst_file)?;
        let metadata = src.read_metadata()?;
        self.copy_file_range(
            &mut src,
            NumBytes::new(0),
            &mut dst,
            NumBytes::new(0),
            NumBytes::new(metadata.len()),
        )
    }

    /// Efficiently copy a range of data from one file to another.
    ///
    /// On Linux, this does a sparse copy, i.e., it punches holes in the destination file
    /// where the source file has holes.
    pub fn copy_file_range(
        &mut self,
        src: &mut File,
        src_position: NumBytes,
        dst: &mut File,
        dst_position: NumBytes,
        size: NumBytes,
    ) -> FsResult<()> {
        check_canceled();
        trace!(
            "copying range of size {size:#} from {src_position:#} (source) to {dst_position:#} (destination)"
        );
        #[cfg(target_os = "linux")]
        {
            use nix::unistd::lseek64;
            use nix::unistd::Whence;
            let mut src_offset = i64::try_from(src_position.raw).expect("offset must not overflow");
            let mut dst_offset = i64::try_from(dst_position.raw).expect("offset must not overflow");
            let src_raw_fd = src.file.as_raw_fd();
            let dst_raw_fd = dst.file.as_raw_fd();
            lseek64(src_raw_fd, src_offset, Whence::SeekSet)
                .whatever_with(|_| format!("unable to seek to {src_offset}"))?;
            lseek64(dst_raw_fd, dst_offset, Whence::SeekSet)
                .whatever_with(|_| format!("unable to seek to {dst_offset}"))?;
            let mut remaining = i64::try_from(size.raw).expect("size must not overflow `i64`");
            let mut use_copy_file_range = true;
            while remaining > 0 {
                // If there is no hole, then `next_hole` points to the end of the file as
                // there always is an implicit hole at the end of any file.
                let next_hole = lseek64(src_raw_fd, src_offset, Whence::SeekHole)
                    .whatever("unable to seek to next hole")?;
                lseek64(src.file.as_raw_fd(), src_offset, Whence::SeekSet)
                    .whatever("unable to set source offset")?;
                let chunk_size = next_hole - src_offset;
                let mut chunk_remaining = chunk_size.min(remaining);
                while chunk_remaining > 0 && remaining > 0 {
                    check_canceled();
                    let chunk_read = if use_copy_file_range {
                        match nix::fcntl::copy_file_range(
                            &mut src.file,
                            None,
                            &mut dst.file,
                            None,
                            chunk_remaining.min(32768) as usize,
                        ) {
                            Ok(chunk_read) => chunk_read,
                            Err(nix::errno::Errno::EXDEV) => {
                                use_copy_file_range = false;
                                continue;
                            }
                            result => result.whatever("unable to copy file range")?,
                        }
                    } else {
                        let chunk_read = chunk_remaining.min(8192);
                        src.read_into_vec(
                            &mut self.buffer,
                            Some(NumBytes::new(chunk_read as u64)),
                        )?;
                        dst.write(&self.buffer)?;
                        let chunk_read = self.buffer.len();
                        self.buffer.clear();
                        chunk_read
                    };
                    chunk_remaining -= chunk_read as i64;
                    remaining -= chunk_read as i64;
                    dst_offset += chunk_read as i64;
                    src_offset += chunk_read as i64;
                }
                if remaining > 0 {
                    src_offset = match lseek64(src_raw_fd, next_hole, Whence::SeekData) {
                        Ok(src_offset) => src_offset,
                        Err(nix::errno::Errno::ENXIO) => {
                            dst.punch_hole(
                                NumBytes::new(dst_offset as u64),
                                NumBytes::new(remaining as u64),
                            )?;
                            break;
                        }
                        error => error.whatever("unable to seek in src")?,
                    };
                    let hole_size = src_offset - next_hole;
                    dst.punch_hole(
                        NumBytes::new(dst_offset as u64),
                        NumBytes::new(hole_size as u64),
                    )?;
                    dst_offset += hole_size;
                    lseek64(dst_raw_fd, hole_size, Whence::SeekCur)
                        .whatever("unable to seek in dst")?;
                    remaining -= hole_size;
                }
            }
            return Ok(());
        }
        #[cfg_attr(target_os = "linux", expect(unreachable_code))]
        {
            src.set_current_position(src_position)?;
            dst.set_current_position(dst_position)?;
            let mut remaining = size;
            while remaining > 0 {
                check_canceled();
                const CHUNK_SIZE: NumBytes = NumBytes::kibibytes(8);
                src.read_into_vec(&mut self.buffer, Some(remaining.min(CHUNK_SIZE)))?;
                dst.write(&self.buffer)?;
                remaining -= self.buffer.byte_len();
                self.buffer.clear();
            }
            Ok(())
        }
    }
}

/// Temporary directory.
///
/// Cleanup will be scheduled in a separate thread when dropped.
pub struct TempDir {
    /// Underlying [`tempfile::TempDir`].
    ///
    /// We use [`Option`] here as we need to move it out in [`Drop`].
    tempdir: Option<tempfile::TempDir>,
}

impl TempDir {
    /// Create a new temporary directory.
    pub fn create() -> FsResult<Self> {
        Ok(Self {
            tempdir: Some(tempfile::tempdir().whatever("unable to create temporary directory")?),
        })
    }

    /// Path of the temporary directory.
    pub fn path(&self) -> &Path {
        self.tempdir.as_ref().unwrap().path()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // `TempDir` may be dropped from an asynchronous context, so let's
        // schedule the cleanup in a separate thread.
        let tempdir = self.tempdir.take().unwrap();
        spawn_blocking(move || {
            trace!("cleaning up temporary directory {:?}", tempdir.path());
            if let Err(error) = tempdir.close() {
                error!("error cleaning up temporary directory: {:?}", error);
            }
        })
        .detach();
    }
}
