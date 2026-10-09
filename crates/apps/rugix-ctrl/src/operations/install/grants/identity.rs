//! Device identity supplied by a trusted helper executable.
//!
//! Identity must never come from the installation request, so it is resolved by an
//! executable named in local configuration. A helper that fails, stalls, or
//! returns anything unexpected rejects the operation.

use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use reportify::bail;
use reportify::whatever;
use reportify::ResultExt;
use rugix_grants::RecipientIdentity;

use crate::config::grants::GrantIdentity;
use crate::config::grants::GrantsConfig;
use crate::system::SystemResult;

/// Longest a helper may take before the operation is rejected.
///
/// A helper that queries a service must apply its own, shorter timeout. This bound
/// exists so a stalled helper cannot hold an installation open indefinitely.
const TIMEOUT: Duration = Duration::from_secs(10);

/// How often the helper is checked for completion.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Largest identity document accepted from a helper.
const MAX_OUTPUT: usize = 64 * 1024;

/// Largest amount of helper diagnostics retained for the error report.
const MAX_DIAGNOSTICS: usize = 4 * 1024;

/// Resolve identity from the configured helper.
#[tracing::instrument(level = "debug", skip_all)]
pub(crate) fn load(config: &GrantsConfig) -> SystemResult<RecipientIdentity> {
    let output = run(Path::new(&config.identity_helper))?;
    if !output.status.success() {
        bail!(
            "grant identity helper failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.diagnostics).trim()
        );
    }
    if output.stdout.len() > MAX_OUTPUT {
        bail!("grant identity helper produced more than {MAX_OUTPUT} bytes");
    }
    let identity: GrantIdentity =
        serde_json::from_slice(&output.stdout).whatever("invalid grant identity helper output")?;
    let groups = identity.groups.unwrap_or_default();
    if identity.device.is_empty() || groups.iter().any(|group| group.is_empty()) {
        bail!("grant identity identifiers must not be empty");
    }
    Ok(RecipientIdentity {
        namespace: config.namespace.clone(),
        recipient_id: identity.device,
        groups,
    })
}

/// Bounded result of one helper invocation.
struct HelperOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    diagnostics: Vec<u8>,
}

/// Run the helper, rejecting the operation if it does not finish in time.
///
/// Output is read on a separate thread because a helper can fill a pipe before
/// exiting. This thread keeps ownership of the child, so the process is never
/// reaped while it is still waiting and a signal cannot reach an unrelated process.
fn run(helper: &Path) -> SystemResult<HelperOutput> {
    let mut child = Command::new(helper)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| whatever!("unable to run grant identity helper: {error}"))?;
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let read = stdout
            .by_ref()
            .take(MAX_OUTPUT as u64 + 1)
            .read_to_end(&mut output)
            .and_then(|_| {
                stderr
                    .by_ref()
                    .take(MAX_DIAGNOSTICS as u64)
                    .read_to_end(&mut diagnostics)
            });
        read.map(|_| (output, diagnostics))
    });
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        let finished = child
            .try_wait()
            .whatever("unable to wait for grant identity helper")?;
        if let Some(status) = finished {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "grant identity helper did not finish within {} seconds",
                TIMEOUT.as_secs()
            );
        }
        thread::sleep(POLL_INTERVAL);
    };
    let (stdout, diagnostics) = reader
        .join()
        .map_err(|_| whatever!("grant identity helper reader failed"))?
        .whatever("unable to read grant identity helper output")?;
    Ok(HelperOutput {
        status,
        stdout,
        diagnostics,
    })
}
