use std::ffi::OsStr;
use std::os::linux::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

use reportify::Report;
use reportify::ResultExt;
use tracing::debug;
use xscript::run;
use xscript::Run;

reportify::new_whatever_type! {
    pub MountError
}

pub fn is_mount_point<P: AsRef<Path>>(path: P) -> bool {
    fn is_mount_point(path: &Path) -> bool {
        let Ok(path) = path.canonicalize() else {
            return false;
        };
        if let Some(parent) = path.parent() {
            let Ok(path_metadata) = path.symlink_metadata() else {
                return false;
            };
            let Ok(parent_metadata) = parent.symlink_metadata() else {
                return false;
            };
            // The path is a mount point, if it resides on a different device than its parent.
            path_metadata.st_dev() != parent_metadata.st_dev()
        } else {
            // Path is canonical but has no parent, so it must be a mount point.
            true
        }
    }
    is_mount_point(path.as_ref())
}

pub struct Mounted {
    path: PathBuf,
}

impl Mounted {
    pub fn mount(dev: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<Self, Report<MountError>> {
        let dst = dst.as_ref();
        let dev = dev.as_ref();
        debug!("Mounting {dev:?} to {dst:?}.");
        // FIXME: The `mount` command works without specifying the filesystem type,
        // which is not the case for `nix::mount::mount`.
        run!(["mount", dev, dst])
            .whatever("unable to mount filesystem")
            .field_debug("dev", dev)
            .field_debug("dst", dst)?;
        Ok(Mounted { path: dst.into() })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn mount_fs(
        fstype: impl AsRef<str>,
        src: impl AsRef<Path>,
        dst: impl AsRef<Path>,
    ) -> Result<Self, Report<MountError>> {
        let dst = dst.as_ref();
        let src = src.as_ref();
        let fstype = fstype.as_ref();
        debug!("Mounting {src:?} with {fstype:?} to {dst:?}.");
        nix::mount::mount(
            Some(src),
            dst,
            Some(fstype),
            nix::mount::MsFlags::empty(),
            None as Option<&OsStr>,
        )
        .whatever("unable to mount filesystem")
        .field_debug("src", src)
        .field_debug("dst", dst)
        .field("fstype", fstype)?;
        Ok(Mounted { path: dst.into() })
    }

    pub fn bind(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<Self, Report<MountError>> {
        let dst = dst.as_ref();
        let src = src.as_ref();
        debug!("Mounting {src:?} to {dst:?}.");
        nix::mount::mount(
            Some(src),
            dst,
            None as Option<&OsStr>,
            nix::mount::MsFlags::MS_BIND,
            None as Option<&OsStr>,
        )
        .whatever("unable to bind mount")
        .field_debug("src", src)
        .field_debug("dst", dst)?;
        Ok(Mounted { path: dst.into() })
    }

    pub fn bind_recursive(
        src: impl AsRef<Path>,
        dst: impl AsRef<Path>,
    ) -> Result<Self, Report<MountError>> {
        let dst = dst.as_ref();
        let src = src.as_ref();
        debug!("Mounting {src:?} to {dst:?}.");
        nix::mount::mount(
            Some(src),
            dst,
            None as Option<&OsStr>,
            nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
            None as Option<&OsStr>,
        )
        .whatever("unable to bind mount")
        .field_debug("src", src)
        .field_debug("dst", dst)?;
        Ok(Mounted { path: dst.into() })
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        // Try normal unmount first
        if let Err(error) = nix::mount::umount(&self.path) {
            // If EBUSY, try lazy unmount (MNT_DETACH) to avoid mount accumulation
            if error == nix::errno::Errno::EBUSY {
                if let Err(error) =
                    nix::mount::umount2(&self.path, nix::mount::MntFlags::MNT_DETACH)
                {
                    eprintln!("Error lazy unmounting {:?}: {:?}", self.path, error)
                }
            } else {
                eprintln!("Error unmounting {:?}: {:?}", self.path, error)
            }
        }
    }
}

pub struct MountStack(Vec<Mounted>);

impl MountStack {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push(&mut self, mounted: Mounted) {
        self.0.push(mounted);
    }

    pub fn unmount_all(&mut self) {
        while let Some(top) = self.0.pop() {
            drop(top);
        }
    }
}

impl Drop for MountStack {
    fn drop(&mut self) {
        self.unmount_all()
    }
}
