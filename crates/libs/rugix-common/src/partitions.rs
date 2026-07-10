use std::path::Path;

use reportify::Report;
use reportify::ResultExt;
use xscript::cmd_os;
use xscript::read_str;
use xscript::run;
use xscript::ParentEnv;
use xscript::Run;

pub fn is_dir(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_dir()
}

reportify::new_whatever_type! {
    pub DiskError
}

/// Returns the disk id of the provided image or device.
pub fn get_disk_id(path: impl AsRef<Path>) -> Result<String, Report<DiskError>> {
    fn _disk_id(path: &Path) -> Result<String, Report<DiskError>> {
        let disk_id = read_str!(["sfdisk", "--disk-id", path])
            .whatever("unable to retrieve disk id")
            .field_debug("disk", path)?;
        if let Some(dos_id) = disk_id.strip_prefix("0x") {
            Ok(dos_id.to_owned())
        } else {
            Ok(disk_id)
        }
    }
    _disk_id(path.as_ref())
}

/// Formats a boot partition with FAT32.
pub fn mkfs_vfat(dev: impl AsRef<Path>, label: impl AsRef<str>) -> Result<(), Report<DiskError>> {
    run!(["mkfs.vfat", "-n", label.as_ref(), dev.as_ref()])
        .whatever("unable to create FAT32 filesystem")?;
    Ok(())
}

/// Formats a system partition with EXT4.
pub fn mkfs_ext4(
    dev: impl AsRef<Path>,
    label: impl AsRef<str>,
    additional_options: &[String],
) -> Result<(), Report<DiskError>> {
    let mut cmd = cmd_os!("mkfs.ext4", "-F", "-L", label.as_ref(), dev.as_ref());
    cmd.extend_args(additional_options);
    ParentEnv
        .run(cmd)
        .whatever("unable to create ETX4 filesystem")?;
    Ok(())
}
