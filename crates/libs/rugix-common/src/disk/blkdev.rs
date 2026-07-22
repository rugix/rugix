//! Functionality for working with Linux block devices.

// cspell:ignore IFMT, IFBLK, rdev

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::hash::Hash;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::path::PathBuf;

use nix::libc::dev_t;

/// Block device.
#[derive(Debug, Clone)]
pub struct BlockDevice {
    /// Number of the block device (uniquely identifies the device).
    dev: nix::libc::dev_t,
    /// UTF-8 path of the block device in `/dev`.
    ///
    /// We can always reconstruct this path via Sysfs. We store it here to avoid
    /// allocations.
    path: String,
}

impl BlockDevice {
    /// Create a block device from the given device path in `/dev`.
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        fn inner(path: &Path) -> io::Result<BlockDevice> {
            // Resolve any symlinks to get a canonical path in `/dev`.
            let path = path.canonicalize()?;
            if !path.starts_with("/dev") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{path:?} is not a path in `/dev`"),
                ));
            }
            let path =
                String::from_utf8(path.into_os_string().into_encoded_bytes()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "device path must be valid UTF-8".to_string(),
                    )
                })?;
            let stat = nix::sys::stat::stat(path.as_str())?;
            if stat.st_mode & nix::libc::S_IFMT != nix::libc::S_IFBLK {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{path:?} is not a block device"),
                ))
            } else {
                Ok(BlockDevice {
                    path,
                    dev: stat.st_rdev,
                })
            }
        }
        inner(path.as_ref())
    }

    /// Create a block device from the given device path in `/sys`.
    fn from_sysfs_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        fn inner(path: &Path) -> io::Result<BlockDevice> {
            sysfs_path_to_dev_path(path).and_then(BlockDevice::new)
        }
        inner(path.as_ref())
    }

    /// Path of the block device in `/dev`.
    pub fn path(&self) -> &Path {
        self.path.as_ref()
    }

    /// Name of the block device in `/dev`.
    pub fn name(&self) -> &str {
        self.path
            .strip_prefix("/dev/")
            .expect("device path must be in `/dev`")
    }

    /// Check whether the device is a partition and return its number, if it is.
    pub fn is_partition(&self) -> io::Result<Option<u32>> {
        let partition = self.sysfs_path()?.join("partition");
        if partition.exists() {
            Ok(Some(
                fs::read_to_string(&partition)?
                    .trim()
                    .parse()
                    .expect("partition attribute must be a number"),
            ))
        } else {
            Ok(None)
        }
    }

    /// Check whether the device is a whole disk, i.e., not a partition.
    pub fn is_whole_disk(&self) -> io::Result<bool> {
        self.is_partition().map(|partition| partition.is_none())
    }

    /// Query the size of the block device in bytes.
    pub fn size(&self) -> io::Result<u64> {
        use nix::ioctl_read_bad;
        use nix::libc::c_int;
        use nix::request_code_read;

        /// The `ioctl` request code for `BLKGETSIZE64`.
        const IOCTL_REQUEST_CODE: c_int =
            request_code_read!(0x12, 114, std::mem::size_of::<*mut u64>()) as c_int;

        // We have to use `ioctl_read_bad` here because the code is computed with
        // `*mut u64` but the actual type needs to be `u64`.
        ioctl_read_bad! {
            /// Get the size of the block device in bytes.
            ioctl_get_size64, IOCTL_REQUEST_CODE, u64
        }

        let file = fs::File::open(&self.path)?;
        let mut size = 0;
        unsafe {
            // SAFETY: The file points to a block device.
            ioctl_get_size64(file.as_raw_fd(), &mut size)?;
        }
        Ok(size)
    }

    /// Find the parent device of the block device, if any.
    pub fn find_parent(&self) -> io::Result<Option<Self>> {
        // This works by scanning the device hierarchy in `/sys` in accordance with the
        // Sysfs rules. Within `util-linux` this is done by simply looking at the parent
        // directory. However, according to the Sysfs rules, an application must scan the
        // hierarchy for a parent device with a matching subsystem as the Kernel is free
        // to insert devices at any point in the hierarchy.
        let sysfs_path = self.sysfs_path()?;
        let mut path = sysfs_path.parent();
        while let Some(parent) = path {
            path = parent.parent();
            let Ok(subsystem) = fs::read_link(parent.join("subsystem")) else {
                continue;
            };
            let Some(subsystem) = subsystem.file_name() else {
                continue;
            };
            if subsystem == OsStr::new("block") {
                return Self::from_sysfs_path(parent).map(Some);
            }
        }
        // Virtual block devices have no parent in the sysfs hierarchy. Continue the
        // parent lookup from each directly backing device instead.
        for backing_device in self.direct_backing_devices()? {
            if let Some(parent) = backing_device.find_parent()? {
                return Ok(Some(parent));
            }
        }
        Ok(None)
    }

    /// Find all block devices transitively backing this block device.
    ///
    /// The returned set does not include this block device itself.
    pub fn find_backing_devices(&self) -> io::Result<HashSet<Self>> {
        let mut backing_devices = HashSet::new();
        let mut pending_devices = self.direct_backing_devices()?;
        while let Some(device) = pending_devices.pop() {
            if device == *self || !backing_devices.insert(device.clone()) {
                continue;
            }
            pending_devices.extend(device.direct_backing_devices()?);
        }
        Ok(backing_devices)
    }

    /// Get a block device for the given partition of the device, if it exits.
    pub fn get_partition(&self, partition: u32) -> io::Result<Option<Self>> {
        // We take a simple approach and directly construct a path for the partition in
        // `/dev`. There may be some edge cases where this does not work. An alternative
        // would scan the device directory in `/sys` for partitions.
        let mut path = self.path.clone();
        if path.ends_with(|c: char| c.is_ascii_digit()) {
            path.push('p');
        }
        fmt::write(&mut path, format_args!("{}", partition))
            .expect("writing to `String` must not fail");
        if Path::new(path.as_str()).exists() {
            Ok(Some(BlockDevice::new(path)?))
        } else {
            Ok(None)
        }
    }

    /// Canonical path of the block device in `/sys`.
    fn sysfs_path(&self) -> io::Result<PathBuf> {
        sysfs_device_number_to_path(self.dev).canonicalize()
    }

    /// Find the block devices listed in this device's sysfs `slaves` directory.
    fn direct_backing_devices(&self) -> io::Result<Vec<Self>> {
        let slaves = self.sysfs_path()?.join("slaves");
        if !slaves.is_dir() {
            return Ok(Vec::new());
        }
        fs::read_dir(slaves)?
            .map(|entry| entry.and_then(|entry| Self::from_sysfs_path(entry.path())))
            .collect()
    }
}

impl PartialEq for BlockDevice {
    fn eq(&self, other: &Self) -> bool {
        // If the device number is identical, then the devices are the same.
        self.dev == other.dev
    }
}

impl Eq for BlockDevice {}

impl Hash for BlockDevice {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.dev.hash(state);
    }
}

// Allow the device to be used where a path is required.
impl AsRef<Path> for BlockDevice {
    fn as_ref(&self) -> &Path {
        self.path.as_ref()
    }
}

// Allow the device to be converted into a path.
impl From<BlockDevice> for PathBuf {
    fn from(value: BlockDevice) -> Self {
        value.path.into()
    }
}

/// Check wether the device at the given path is a block device.
///
/// If the path does not exist, [`false`] is returned.
pub fn is_block_device<P: AsRef<Path>>(path: P) -> io::Result<bool> {
    fn inner(path: &Path) -> io::Result<bool> {
        if path.exists() {
            Ok(path.metadata()?.file_type().is_block_device())
        } else {
            Ok(false)
        }
    }
    inner(path.as_ref())
}

/// Find the block device where a given path resides on.
///
/// Returns [`None`] when the path is not on a block device.
pub fn find_block_device<P: AsRef<Path>>(path: P) -> io::Result<Option<BlockDevice>> {
    fn inner(path: &Path) -> io::Result<Option<BlockDevice>> {
        let stat = nix::sys::stat::stat(path)?;
        let path = sysfs_device_number_to_path(stat.st_dev);
        if path.exists() {
            BlockDevice::new(sysfs_path_to_dev_path(&path)?).map(Some)
        } else {
            Ok(None)
        }
    }
    inner(path.as_ref())
}

/// Convert the device number to a block device path in `/sys`.
///
/// Path has the form `/sys/dev/block/{major}:{minor}`.
fn sysfs_device_number_to_path(dev: dev_t) -> PathBuf {
    let major = nix::sys::stat::major(dev);
    let minor = nix::sys::stat::minor(dev);
    PathBuf::from(format!("/sys/dev/block/{major}:{minor}"))
}

/// Convert the name of a device in `/sys` to its name in `/dev`.
///
/// Based on <https://github.com/util-linux/util-linux/blob/728659867e56378542ec86a3229a3d7cc973c76e/include/sysfs.h#L33>.
fn sysfs_name_to_dev_name(name: String) -> String {
    name.chars()
        .map(|c| if c == '!' { '/' } else { c })
        .collect()
}

/// Convert a device path in `/sys` to a device path in `/dev`.
fn sysfs_path_to_dev_path(path: &Path) -> io::Result<PathBuf> {
    Ok(PathBuf::from(format!(
        "/dev/{}",
        sysfs_name_to_dev_name(sysfs_path_to_name(path)?)
    )))
}

/// Extract the Sysfs device name of a device from its path in `/sys`.
fn sysfs_path_to_name(path: &Path) -> io::Result<String> {
    Ok(path
        .canonicalize()?
        .file_name()
        .expect("there should be a filename according to the Sysfs specification")
        .to_str()
        .expect("device name should be valid UTF-8")
        .to_owned())
}
