//! Systemd integration for Rugix Apps.

use std::process::Command;

use reportify::ResultExt;

use super::AppsResult;

/// Runtime directory where systemd picks up transient units.
pub const RUNTIME_UNITS_DIR: &str = "/run/systemd/system";

pub mod restore;

/// Run `systemctl daemon-reload`.
pub fn daemon_reload() -> AppsResult<()> {
    run(&["daemon-reload"])
}

/// Enable a unit with `--runtime`.
pub fn enable_runtime(unit: &str) -> AppsResult<()> {
    run(&["enable", "--runtime", unit])
}

/// Disable a unit with `--runtime`.
pub fn disable_runtime(unit: &str) -> AppsResult<()> {
    run(&["disable", "--runtime", unit])
}

/// Start a unit, waiting for it to finish.
pub fn start(unit: &str) -> AppsResult<()> {
    run(&["start", unit])
}

/// Queue a unit for start without blocking.
pub fn start_no_block(unit: &str) -> AppsResult<()> {
    run(&["start", "--no-block", unit])
}

/// Stop a unit.
pub fn stop(unit: &str) -> AppsResult<()> {
    run(&["stop", unit])
}

/// Check whether a unit is active.
///
/// Returns the raw status string (e.g. `"active"`, `"inactive"`).
pub fn is_active(unit: &str) -> AppsResult<String> {
    let output = Command::new("systemctl")
        .args(["is-active", unit])
        .output()
        .whatever("unable to run systemctl is-active")?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Run `systemctl` with the given arguments.
fn run(args: &[&str]) -> AppsResult<()> {
    run_with(args, |args| {
        Command::new("systemctl")
            .args(args)
            .status()
            .whatever(format!("unable to run systemctl {}", args.join(" ")))
    })
}

fn run_with(
    args: &[&str],
    execute: impl FnOnce(&[&str]) -> AppsResult<std::process::ExitStatus>,
) -> AppsResult<()> {
    if !execute(args)?.success() {
        reportify::bail!("systemctl {} failed", args.join(" "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;

    use super::run_with;

    #[test]
    fn systemctl_failures_are_not_reported_as_success() {
        assert!(run_with(&["enable", "--runtime", "app.service"], |_| {
            Ok(std::process::ExitStatus::from_raw(1 << 8))
        })
        .is_err());
        assert!(run_with(&["enable", "--runtime", "app.service"], |_| {
            Ok(std::process::ExitStatus::from_raw(0))
        })
        .is_ok());
    }
}
