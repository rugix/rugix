//! Durable replay state for installation grants.
//!
//! The state records every admitted grant until it expires, together with a
//! monotonic time watermark. The two make replay protection independent of any
//! issuer-managed counter: an exact grant is admitted once, and verification time
//! never moves below the watermark, so an expired record can be dropped without
//! ever becoming admissible again.
//!
//! [`GrantStore`] holds an exclusive lock on the state directory for as long as an
//! installation runs, so concurrent granted installations are refused rather than
//! interleaved. The directory is private to the privileged executor, which is what
//! protects the history.

use std::fs;
use std::fs::File;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;

use nix::fcntl::Flock;
use nix::fcntl::FlockArg;
use reportify::bail;
use reportify::ResultExt;
use rugix_grants::RecipientIdentity;
use tracing::info;
use tracing::warn;

use crate::config::grants::AdmittedGrant;
use crate::config::grants::GrantState;
use crate::system::SystemResult;

/// Only supported state version.
const STATE_VERSION: u32 = 1;

/// Largest number of unexpired grants retained at once.
///
/// Records expire on their own, so a flood of valid grants delays further
/// installations for at most one validity window instead of discarding history.
const MAX_ADMITTED: usize = 1024;

/// Exclusive handle to a device's grant replay state.
pub(crate) struct GrantStore {
    directory: PathBuf,
    state: GrantState,
    _lock: Flock<File>,
}

impl GrantStore {
    /// Lock the state directory and load the state belonging to `identity`.
    ///
    /// State for an unknown device is created on first use. Protecting the
    /// directory is what protects the history: anyone who could delete it could
    /// equally recreate it, so refusing to create it would add no protection.
    pub(crate) fn open(directory: PathBuf, identity: &RecipientIdentity) -> SystemResult<Self> {
        fs::create_dir_all(&directory).whatever("unable to create grant state directory")?;
        // Keep unprivileged callers from reading history or holding the lock.
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .whatever("unable to restrict grant state directory")?;
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(directory.join("lock"))
            .whatever("unable to open grant state lock")?;
        let lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, error)| error)
            .whatever("another granted installation is in progress")?;
        let path = directory.join("state.json");
        let state = match fs::read(&path) {
            Ok(bytes) => {
                let state: GrantState =
                    serde_json::from_slice(&bytes).whatever("invalid grant replay state")?;
                if state.version != STATE_VERSION {
                    bail!("unsupported grant state version {}", state.version);
                }
                state
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                info!(device = %identity.recipient_id, "creating grant replay state");
                GrantState {
                    version: STATE_VERSION,
                    namespace: identity.namespace.clone(),
                    device: identity.recipient_id.clone(),
                    time_watermark: 0,
                    admitted: Vec::new(),
                }
            }
            Err(error) => {
                bail!("unable to read grant state: {error}")
            }
        };
        let store = Self {
            directory,
            state,
            _lock: lock,
        };
        store.check_identity(identity)?;
        Ok(store)
    }

    /// Reject an identity that does not match the recorded state.
    pub(crate) fn check_identity(&self, identity: &RecipientIdentity) -> SystemResult<()> {
        if identity.namespace != self.state.namespace || identity.recipient_id != self.state.device
        {
            bail!("grant identity does not match the recorded replay state");
        }
        Ok(())
    }

    /// Verification time, never below the durable watermark.
    ///
    /// A clock that moves backwards, for example after power loss without a
    /// battery-backed clock, cannot revive a grant that was already used.
    pub(crate) fn effective_now(&self, clock: SystemTime) -> SystemTime {
        let watermark = SystemTime::UNIX_EPOCH + Duration::from_secs(self.state.time_watermark);
        if clock < watermark {
            warn!(
                watermark = self.state.time_watermark,
                "system clock is behind the recorded grant watermark; using the watermark"
            );
        }
        clock.max(watermark)
    }

    /// Reject a grant that was already consumed, before any installer work starts.
    pub(crate) fn check_admissible(&self, hash: &str) -> SystemResult<()> {
        if self.record(hash).is_some_and(|record| record.consumed) {
            bail!("this grant was already consumed; a new grant is required");
        }
        Ok(())
    }

    /// Durably record an admitted grant, or accept a retry of one already recorded.
    pub(crate) fn admit(
        &mut self,
        hash: &str,
        id: &str,
        expires_at: u64,
        now: SystemTime,
    ) -> SystemResult<()> {
        self.check_admissible(hash)?;
        self.advance(now);
        if self.record(hash).is_none() {
            if self.state.admitted.len() >= MAX_ADMITTED {
                bail!(
                    "too many unexpired installation grants are recorded; retry once they expire"
                );
            }
            self.state.admitted.push(AdmittedGrant {
                hash: hash.to_owned(),
                id: id.to_owned(),
                expires_at,
                consumed: false,
            });
        }
        self.save()
    }

    /// Durably mark an admitted grant as consumed.
    pub(crate) fn consume(&mut self, hash: &str, now: SystemTime) -> SystemResult<()> {
        self.advance(now);
        let Some(record) = self
            .state
            .admitted
            .iter_mut()
            .find(|record| record.hash == hash)
        else {
            bail!("the admitted installation grant is no longer recorded");
        };
        record.consumed = true;
        self.save()
    }

    fn record(&self, hash: &str) -> Option<&AdmittedGrant> {
        self.state
            .admitted
            .iter()
            .find(|record| record.hash == hash)
    }

    /// Raise the watermark and drop records that can never be admitted again.
    ///
    /// A record is dropped only once the watermark reaches its expiry, so every
    /// later verification rejects that grant for being outside its window.
    fn advance(&mut self, now: SystemTime) {
        let now = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let watermark = self.state.time_watermark.max(now);
        self.state.time_watermark = watermark;
        self.state
            .admitted
            .retain(|record| record.expires_at > watermark);
    }

    fn save(&self) -> SystemResult<()> {
        let bytes = serde_json::to_vec(&self.state).whatever("unable to encode grant state")?;
        rugix_common::fsutils::atomic_write(&self.directory.join("state.json"), &bytes)
            .whatever("unable to persist grant replay state")
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::path::PathBuf;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn identity() -> RecipientIdentity {
        RecipientIdentity {
            namespace: "example".into(),
            recipient_id: "device-1".into(),
            groups: Vec::new(),
        }
    }

    fn time(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn open(directory: &Path) -> GrantStore {
        GrantStore::open(directory.to_path_buf(), &identity()).unwrap()
    }

    fn initialized() -> (tempfile::TempDir, GrantStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = open(&state_dir(&directory));
        (directory, store)
    }

    fn state_dir(directory: &tempfile::TempDir) -> PathBuf {
        directory.path().join("grants")
    }

    /// Verification time never drops below the watermark left by an admission.
    #[test]
    fn the_watermark_floors_a_clock_that_moved_backwards() {
        let (_directory, mut store) = initialized();
        assert_eq!(store.effective_now(time(NOW)), time(NOW));
        store.admit("hash", "grant-1", NOW + 60, time(NOW)).unwrap();
        assert_eq!(store.effective_now(time(NOW - 86400)), time(NOW));
        assert_eq!(store.effective_now(time(NOW + 10)), time(NOW + 10));
    }

    /// A consumed grant stays rejected after its record expires, because the
    /// watermark has already passed its validity window.
    #[test]
    fn pruning_expired_records_cannot_revive_them() {
        let (directory, mut store) = initialized();
        store.admit("hash", "grant-1", NOW + 60, time(NOW)).unwrap();
        store.consume("hash", time(NOW)).unwrap();
        assert!(store.check_admissible("hash").is_err());
        store
            .admit("other", "grant-2", NOW + 3600, time(NOW + 120))
            .unwrap();
        drop(store);
        let store = open(&state_dir(&directory));
        assert_eq!(store.state.admitted.len(), 1);
        assert!(store.check_admissible("hash").is_ok());
        assert!(store.effective_now(time(NOW)) >= time(NOW + 120));
    }

    /// An admitted grant can be retried until it is consumed.
    #[test]
    fn admission_is_repeatable_and_consumption_is_final() {
        let (_directory, mut store) = initialized();
        store.admit("hash", "grant-1", NOW + 60, time(NOW)).unwrap();
        store.admit("hash", "grant-1", NOW + 60, time(NOW)).unwrap();
        store.consume("hash", time(NOW)).unwrap();
        assert!(store.admit("hash", "grant-1", NOW + 60, time(NOW)).is_err());
        assert!(store.consume("missing", time(NOW)).is_err());
    }

    /// Unexpired records are bounded, and the limit clears itself on expiry.
    #[test]
    fn retained_records_are_bounded() {
        let (_directory, mut store) = initialized();
        for index in 0..MAX_ADMITTED {
            store
                .admit(&format!("hash-{index}"), "grant", NOW + 60, time(NOW))
                .unwrap();
        }
        assert!(store
            .admit("overflow", "grant", NOW + 60, time(NOW))
            .is_err());
        store
            .admit("after-expiry", "grant", NOW + 120, time(NOW + 60))
            .unwrap();
        assert_eq!(store.state.admitted.len(), 1);
    }

    /// State for an unknown device is created on first use and keeps its history.
    #[test]
    fn state_is_created_on_first_use() {
        let (directory, mut store) = initialized();
        store.admit("hash", "grant-1", NOW + 60, time(NOW)).unwrap();
        store.consume("hash", time(NOW)).unwrap();
        drop(store);
        let store = open(&state_dir(&directory));
        assert!(store.check_admissible("hash").is_err());
    }

    /// State belonging to another identity or version is never usable.
    #[test]
    fn foreign_state_fails_closed() {
        let (directory, store) = initialized();
        store.save().unwrap();
        drop(store);
        let other = RecipientIdentity {
            recipient_id: "device-2".into(),
            ..identity()
        };
        assert!(GrantStore::open(state_dir(&directory), &other).is_err());
        let path = state_dir(&directory).join("state.json");
        let mut state: GrantState = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        state.version = 2;
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(GrantStore::open(state_dir(&directory), &identity()).is_err());
        fs::write(&path, b"not json").unwrap();
        assert!(GrantStore::open(state_dir(&directory), &identity()).is_err());
    }

    /// The state directory and its records stay private to the privileged executor.
    #[test]
    fn state_is_not_readable_by_other_users() {
        let (directory, mut store) = initialized();
        store.admit("hash", "grant-1", NOW + 60, time(NOW)).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&state_dir(&directory)), 0o700);
        assert_eq!(mode(&state_dir(&directory).join("lock")), 0o600);
    }
}
