//! Shared types for bundle installation operations.

use std::io::Read;
use std::io::Seek;

use serde::Deserialize;
use serde::Serialize;
use si_crypto_hashes::HashDigest;

use crate::http_source::RetryConfig;

/// An event emitted while installing a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BundleInstallEvent {
    /// Bundle installation started.
    Started,
    /// Installation progress changed.
    UpdateProgress {
        progress: f64,
        bytes_read: u64,
        bytes_total: u64,
    },
    /// A component compatibility check was skipped.
    CompatibilityCheckSkipped { scope: String, reason: String },
}

/// Source of a bundle installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InstallSource {
    /// Read the bundle from the operation input stream.
    Stream,
    /// Fetch the bundle over HTTP.
    Http {
        url: String,
        disable_range_queries: bool,
        retry: RetryConfig,
    },
}

/// Bundle data supplied alongside an install operation.
pub enum BundleInput {
    /// The bundle source does not require a data stream.
    None,
    /// A sequential input stream, such as standard input or a socket.
    Stream(Box<dyn Read>),
    /// A seekable input stream, such as a local file.
    Seekable(Box<dyn ReadSeek>),
}

/// A readable and seekable operation input.
pub trait ReadSeek: Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}

/// Bundle verification and compatibility options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BundleInstallOptions {
    pub(crate) bundle_hash: Option<HashDigest>,
    pub(crate) root_cert: Option<Vec<u8>>,
    pub(crate) insecure_skip_bundle_verification: bool,
    pub(crate) insecure_allow_missing_block_index: bool,
    pub(crate) skip_compatibility_check: bool,
}
