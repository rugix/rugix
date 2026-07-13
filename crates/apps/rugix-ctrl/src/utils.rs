use std::fs;
use std::path::Path;

use crate::system::SystemResult;
use reportify::ResultExt;
use serde::Deserialize;
use serde::Serialize;
use xscript::run;
use xscript::Run;

pub static DEFERRED_SPARE_REBOOT_FLAG: &str = "/run/rugix/mounts/data/.rugix/deferred-reboot-spare";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeferredRebootTarget {
    version: u32,
    boot_group: String,
}

/// Indicates whether the process is the init process.
pub fn is_init_process() -> bool {
    std::process::id() == 1
}

/// Reboot the system.
pub fn reboot() -> SystemResult<()> {
    if is_init_process() {
        // Make sure that no data is lost.
        nix::unistd::sync();
        unsafe {
            // SAFETY: The provided arguments are proper `\0`-terminated strings.
            nix::libc::syscall(
                nix::libc::SYS_reboot,
                nix::libc::LINUX_REBOOT_MAGIC1,
                nix::libc::LINUX_REBOOT_MAGIC2,
                nix::libc::LINUX_REBOOT_CMD_RESTART2,
                c"",
            );
        }
    } else {
        run!(["reboot"]).whatever("unable to run `reboot`")?;
    };
    Ok(())
}

pub fn set_flag(path: impl AsRef<Path>) -> SystemResult<()> {
    set_flag_data(path, &[])
}

pub(crate) fn set_flag_data(path: impl AsRef<Path>, data: &[u8]) -> SystemResult<()> {
    let path = path.as_ref();
    rugix_common::fsutils::atomic_write(path, data).whatever("unable to set flag")
}

pub fn set_deferred_reboot_target(boot_group: &str) -> SystemResult<()> {
    set_deferred_reboot_target_at(Path::new(DEFERRED_SPARE_REBOOT_FLAG), boot_group)
}

fn set_deferred_reboot_target_at(path: &Path, boot_group: &str) -> SystemResult<()> {
    let data = serde_json::to_vec(&DeferredRebootTarget {
        version: 1,
        boot_group: boot_group.to_owned(),
    })
    .whatever("unable to encode deferred reboot target")?;
    set_flag_data(path, &data)
}

/// Read the recorded target. `None` denotes a legacy empty marker.
pub fn read_deferred_reboot_target() -> SystemResult<Option<String>> {
    read_deferred_reboot_target_at(Path::new(DEFERRED_SPARE_REBOOT_FLAG))
}

fn read_deferred_reboot_target_at(path: &Path) -> SystemResult<Option<String>> {
    let data = fs::read(path).whatever("unable to read deferred reboot target")?;
    if data.is_empty() {
        return Ok(None);
    }
    let target = serde_json::from_slice::<DeferredRebootTarget>(&data)
        .whatever("unable to decode deferred reboot target")?;
    if target.version != 1 {
        reportify::bail!(
            "unsupported deferred reboot target version {}",
            target.version
        );
    }
    Ok(Some(target.boot_group))
}

pub fn clear_flag(path: impl AsRef<Path>) -> SystemResult<()> {
    let path = path.as_ref();
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                fs::File::open(parent)
                    .whatever("unable to open flag directory")?
                    .sync_all()
                    .whatever("unable to synchronize flag directory")?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).whatever("unable to clear flag"),
    }
    Ok(())
}

pub fn is_flag_set(path: impl AsRef<Path>) -> bool {
    path.as_ref().exists()
}

#[cfg(test)]
mod tests {
    use super::read_deferred_reboot_target_at;
    use super::set_deferred_reboot_target_at;

    #[test]
    fn deferred_reboot_targets_are_versioned_and_legacy_markers_remain_readable() {
        let tempdir = tempfile::tempdir().unwrap();
        let marker = tempdir.path().join("flags/deferred");
        set_deferred_reboot_target_at(&marker, "group-b").unwrap();
        assert_eq!(
            read_deferred_reboot_target_at(&marker).unwrap(),
            Some("group-b".to_owned())
        );

        std::fs::write(&marker, b"").unwrap();
        assert_eq!(read_deferred_reboot_target_at(&marker).unwrap(), None);
    }

    #[test]
    fn unknown_deferred_reboot_marker_versions_are_rejected() {
        let tempdir = tempfile::tempdir().unwrap();
        let marker = tempdir.path().join("deferred");
        std::fs::write(&marker, br#"{"version":2,"bootGroup":"group-b"}"#).unwrap();
        assert!(read_deferred_reboot_target_at(&marker).is_err());
    }
}
