//! Optional init error shell controlled by the kernel cmdline.
//!
//! Call [`prompt_on_init_error`] after Rugix init fails. The function checks
//! `rugix.init.shell_on_error[=<seconds>]` on the kernel cmdline, then either
//! offers an interactive debug shell on `/dev/console` or prints a security
//! notice explaining how to enable it on a future boot.

use std::ffi::CString;
use std::fs::OpenOptions;
use std::fs::{self};
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::io::{self};
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

use nix::poll::poll;
use nix::poll::PollFd;
use nix::poll::PollFlags;
use nix::poll::PollTimeout;
use nix::sys::termios::cfmakeraw;
use nix::sys::termios::tcgetattr;
use nix::sys::termios::tcsetattr;
use nix::sys::termios::SetArg;
use nix::sys::termios::Termios;
use reportify::ResultExt;
use tracing::warn;

use crate::system::SystemResult;

const SHELL_ON_ERROR_PARAM: &str = "rugix.init.shell_on_error";
const SHELL_ON_ERROR_PREFIX: &str = "rugix.init.shell_on_error=";
const DEFAULT_SHELL_ON_ERROR_TIMEOUT_SECS: u64 = 30;

/// Prompts for a debug shell after a Rugix init failure when enabled.
///
/// This reads the kernel cmdline and only opens a shell if
/// `rugix.init.shell_on_error` or `rugix.init.shell_on_error=<seconds>` is
/// present. Without that opt-in, it prints a console message explaining how to
/// enable the shell instead of exposing a root shell by default.
pub fn prompt_on_init_error() {
    let Some(timeout) = shell_on_error_timeout() else {
        print_shell_disabled_message();
        return;
    };
    if let Err(error) = prompt_for_debug_shell(timeout) {
        warn!(error = ?error, "unable to start debug shell");
    }
}

fn shell_on_error_timeout() -> Option<Duration> {
    let cmdline = match super::kernel_cmdline::read() {
        Ok(cmdline) => cmdline,
        Err(error) => {
            warn!(error = ?error, "unable to read kernel cmdline");
            return None;
        }
    };
    parse_shell_on_error_timeout(&cmdline)
}

/// Parses the init error shell timeout from the kernel cmdline.
///
/// This is intentionally opt-in: without an enabling kernel cmdline option,
/// Rugix init must not expose a root shell to someone with console access.
fn parse_shell_on_error_timeout(cmdline: &str) -> Option<Duration> {
    for param in cmdline.split_whitespace() {
        if param == SHELL_ON_ERROR_PARAM {
            return Some(default_shell_on_error_timeout());
        }
        if let Some(value) = param.strip_prefix(SHELL_ON_ERROR_PREFIX) {
            return match value {
                "" | "1" | "true" | "yes" | "on" => Some(default_shell_on_error_timeout()),
                "0" | "false" | "no" | "off" => None,
                timeout => match timeout.parse::<u64>() {
                    Ok(timeout) => Some(Duration::from_secs(timeout)),
                    Err(error) => {
                        warn!(
                            value = timeout,
                            error = ?error,
                            "ignoring invalid `{SHELL_ON_ERROR_PARAM}` timeout"
                        );
                        None
                    }
                },
            };
        }
    }
    None
}

fn print_shell_disabled_message() {
    let message = format!(
        "\nRugix initialization failed. The init error shell is disabled. \
         For security, Rugix only opens one when `{SHELL_ON_ERROR_PARAM}` or \
         `{SHELL_ON_ERROR_PARAM}=<seconds>` is set on the kernel cmdline.\n"
    );
    if let Err(error) = write_console_message(&message) {
        warn!(error = ?error, "unable to write init error shell hint");
        eprint!("{message}");
    }
}

fn write_console_message(message: &str) -> io::Result<()> {
    let mut console = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open("/dev/console")?;
    console.write_all(message.as_bytes())?;
    console.flush()
}

fn prompt_for_debug_shell(timeout: Duration) -> SystemResult<()> {
    let mut console = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open("/dev/console")
        .whatever("unable to open `/dev/console`")?;
    writeln!(
        console,
        "\nRugix initialization failed. Press any key within {} seconds to open a debug shell.",
        timeout.as_secs()
    )
    .whatever("unable to write debug prompt")?;
    console.flush().whatever("unable to flush debug prompt")?;
    if wait_for_debug_key(&console, timeout)? {
        writeln!(console, "Starting debug shell.").whatever("unable to write debug prompt")?;
        console.flush().whatever("unable to flush debug prompt")?;
        exec_debug_shell()?;
    }
    writeln!(console, "No key pressed; continuing failure handling.")
        .whatever("unable to write debug timeout message")?;
    Ok(())
}

fn wait_for_debug_key(console: &fs::File, timeout: Duration) -> SystemResult<bool> {
    let _input_mode = ConsoleInputMode::raw(console).inspect_err(|error| {
        warn!(error = ?error, "unable to set console raw mode");
    });
    let timeout = PollTimeout::try_from(timeout).unwrap_or(PollTimeout::MAX);
    let events = {
        let mut poll_fds = [PollFd::new(console.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut poll_fds, timeout).whatever("unable to wait for console input")?;
        if ready == 0 {
            return Ok(false);
        }
        poll_fds[0].revents()
    };
    let Some(events) = events else {
        return Ok(false);
    };
    if !events.contains(PollFlags::POLLIN) {
        return Ok(false);
    }
    let mut buffer = [0];
    let mut console = console;
    loop {
        match console.read(&mut buffer) {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error).whatever("unable to read debug key from console"),
        }
    }
}

fn exec_debug_shell() -> SystemResult<()> {
    let shell = CString::new("/bin/sh").unwrap();
    nix::unistd::execv(&shell, &[&shell]).whatever("unable to run debug shell")?;
    Ok(())
}

const fn default_shell_on_error_timeout() -> Duration {
    Duration::from_secs(DEFAULT_SHELL_ON_ERROR_TIMEOUT_SECS)
}

struct ConsoleInputMode<'a> {
    console: &'a fs::File,
    original: Termios,
}

impl<'a> ConsoleInputMode<'a> {
    fn raw(console: &'a fs::File) -> nix::Result<Self> {
        let original = tcgetattr(console)?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        tcsetattr(console, SetArg::TCSANOW, &raw)?;
        Ok(Self { console, original })
    }
}

impl Drop for ConsoleInputMode<'_> {
    fn drop(&mut self) {
        if let Err(error) = tcsetattr(self.console, SetArg::TCSANOW, &self.original) {
            warn!(error = ?error, "unable to restore console input mode");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_on_error_is_disabled_by_default() {
        assert_eq!(parse_shell_on_error_timeout("quiet splash"), None);
    }

    #[test]
    fn shell_on_error_accepts_bare_flag() {
        assert_eq!(
            parse_shell_on_error_timeout("quiet rugix.init.shell_on_error splash"),
            Some(Duration::from_secs(DEFAULT_SHELL_ON_ERROR_TIMEOUT_SECS))
        );
    }

    #[test]
    fn shell_on_error_accepts_boolean_values() {
        assert_eq!(
            parse_shell_on_error_timeout("rugix.init.shell_on_error=true"),
            Some(Duration::from_secs(DEFAULT_SHELL_ON_ERROR_TIMEOUT_SECS))
        );
        assert_eq!(
            parse_shell_on_error_timeout("rugix.init.shell_on_error=off"),
            None
        );
    }

    #[test]
    fn shell_on_error_accepts_custom_timeout() {
        assert_eq!(
            parse_shell_on_error_timeout("rugix.init.shell_on_error=60"),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn shell_on_error_rejects_invalid_timeout() {
        assert_eq!(
            parse_shell_on_error_timeout("rugix.init.shell_on_error=later"),
            None
        );
    }
}
