//! Reading and interpreting Rugix parameters on the early-boot kernel command line.

use std::fs;

use nix::mount::MsFlags;
use reportify::ResultExt;

use rugix_common::mount::is_mount_point;

use crate::system::SystemResult;

/// Return whether quiet initialization is requested on the kernel command line.
pub(crate) fn init_quiet() -> SystemResult<bool> {
    Ok(read()?
        .split_whitespace()
        .any(|param| param == INIT_QUIET_PARAM))
}

/// Read the kernel command line, mounting procfs first when necessary.
pub(crate) fn read() -> SystemResult<String> {
    mount_proc()?;
    fs::read_to_string("/proc/cmdline").whatever("failed to read `/proc/cmdline`")
}

const INIT_QUIET_PARAM: &str = "rugix.init.quiet";

fn mount_proc() -> SystemResult<()> {
    if is_mount_point("/proc") {
        return Ok(());
    }
    fs::create_dir_all("/proc").whatever("failed to create `/proc`")?;
    nix::mount::mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .whatever("failed to mount procfs")
}
