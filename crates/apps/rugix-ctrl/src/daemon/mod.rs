//! Privileged Rugix Ctrl operation daemon.

use reportify::bail;

use crate::system::SystemResult;

pub(crate) mod client;
mod config;
mod policy;
mod protocol;
mod server;

pub(crate) use config::load_daemon_settings;
pub(crate) use protocol::DaemonOperation;

/// Run the privileged operation daemon in the foreground.
pub(crate) fn run() -> SystemResult<()> {
    if !is_privileged() {
        bail!("the Rugix Ctrl daemon must run as root");
    }
    server::serve(load_daemon_settings()?)
}

/// Determine whether Rugix Ctrl can execute privileged operations locally.
pub(crate) fn is_privileged() -> bool {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}
