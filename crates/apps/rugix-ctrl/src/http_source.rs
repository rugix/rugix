//! HTTP-backed bundle source with resumable downloads and dynamic range-query skipping.
//!
//! [`HttpSource`] streams bundle data while [`RangeQueryStrategy`] controls whether HTTP
//! range queries are disabled, reserved for recovery, or used proactively for block
//! reuse.

use std::io;
use std::io::Read;
use std::time::Duration;

use byte_calc::NumBytes;
use reportify::bail;
use reportify::ResultExt;
use rugix_bundle::source::BundleSource;
use serde::Deserialize;
use serde::Serialize;
use tracing::error;
use tracing::warn;
use ureq::http::Response;
use ureq::Body;

use crate::system::SystemResult;

/// Configuration for HTTP retry/reconnect behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of consecutive retry attempts before giving up.
    pub max_retries: u32,
    /// Initial backoff duration before the first retry.
    pub initial_backoff: Duration,
    /// Maximum backoff duration (caps the exponential growth).
    pub max_backoff: Duration,
}

/// Controls how HTTP range queries are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RangeQueryStrategy {
    /// Do not issue range queries.
    Disabled,
    /// Stream the full response and use range queries only to resume interrupted reads.
    Resume,
    /// Use range queries for both efficient skipping and interrupted-read recovery.
    Dynamic,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        }
    }
}

pub struct HttpSource {
    url: String,
    range_query_strategy: RangeQueryStrategy,
    current_response: Option<Response<Body>>,
    content_length: Option<u64>,
    current_end: Option<u64>,
    next_chunk_end: Option<u64>,
    current_position: u64,
    current_skipped: u64,
    skip_buffer: Vec<u8>,
    bytes_read: u64,
    bytes_skipped: u64,
    total_bytes: Option<NumBytes>,
    retry_config: RetryConfig,
    /// Tracks consecutive retries in the current failure sequence.
    /// Reset to 0 after every successful body read.
    consecutive_retries: u32,
}

#[derive(Debug, Clone)]
pub struct DownloadStats {
    pub bytes_read: NumBytes,
    pub bytes_skipped: NumBytes,
}

impl DownloadStats {
    pub fn total_bytes(&self) -> NumBytes {
        self.bytes_read + self.bytes_skipped
    }

    pub fn download_ratio(&self) -> f64 {
        self.bytes_read.raw as f64 / self.total_bytes().raw as f64
    }
}

/// Minimal size of chunks to be fetched individually via range queries.
const MIN_CHUNK_SIZE: NumBytes = NumBytes::kibibytes(64);

/// Determines whether a ureq error is transient and worth retrying.
fn is_retryable(err: &ureq::Error) -> bool {
    matches!(
        err,
        ureq::Error::Io(_)
            | ureq::Error::Timeout(_)
            | ureq::Error::HostNotFound
            | ureq::Error::ConnectionFailed
    )
}

/// Performs an HTTP GET request with retry and exponential backoff.
///
/// Retries transient errors up to the configured maximum. Non-retryable errors
/// are returned immediately.
fn get_with_retry(
    url: &str,
    range_header: Option<&str>,
    config: &RetryConfig,
) -> Result<Response<Body>, ureq::Error> {
    let mut consecutive_retries = 0u32;
    loop {
        let mut request = ureq::get(url);
        if let Some(range) = range_header {
            request = request.header("Range", range);
        }
        match request.call() {
            Ok(response) => return Ok(response),
            Err(err) => {
                if !is_retryable(&err) || consecutive_retries >= config.max_retries {
                    return Err(err);
                }
                let backoff = compute_backoff(config, consecutive_retries);
                warn!(
                    %url,
                    attempt = consecutive_retries + 1,
                    max_retries = config.max_retries,
                    backoff_ms = backoff.as_millis() as u64,
                    error = %err,
                    "HTTP request failed, retrying after backoff",
                );
                std::thread::sleep(backoff);
                consecutive_retries += 1;
            }
        }
    }
}

fn compute_backoff(config: &RetryConfig, consecutive_retries: u32) -> Duration {
    let base = config.initial_backoff.as_secs_f64() * 2.0f64.powi(consecutive_retries as i32);
    let clamped = base.min(config.max_backoff.as_secs_f64());
    Duration::from_secs_f64(clamped)
}

impl HttpSource {
    pub(crate) fn new(
        url: &str,
        requested_range_query_strategy: RangeQueryStrategy,
        retry_config: RetryConfig,
    ) -> SystemResult<Self> {
        // Try a request with a `Range` header and look at the response to determine the
        // content length and whether range requests are supported by the server.
        let (mut content_length, range_query_strategy) =
            if requested_range_query_strategy != RangeQueryStrategy::Disabled {
                get_with_retry(url, Some("bytes=0-0"), &retry_config)
                    .ok()
                    .and_then(|response| {
                        if response.status() != 206 {
                            return None;
                        }
                        response.headers().get("Content-Range").and_then(|range| {
                            range
                                .to_str()
                                .ok()?
                                .rsplit_once("/")?
                                .1
                                .trim()
                                .parse::<u64>()
                                .ok()
                        })
                    })
                    .map(|length| (Some(length), requested_range_query_strategy))
                    .unwrap_or((None, RangeQueryStrategy::Disabled))
            } else {
                (None, RangeQueryStrategy::Disabled)
            };

        let (current_response, current_end) = if range_query_strategy != RangeQueryStrategy::Dynamic
        {
            // Fetch the whole bundle all at once.
            let response = get_with_retry(url, None, &retry_config)
                .whatever("unable to get bundle from URL")?;
            let response_content_length = response
                .headers()
                .get("Content-Length")
                .and_then(|length| length.to_str().ok()?.trim().parse::<u64>().ok());
            content_length = content_length.or(response_content_length);
            (response, content_length)
        } else {
            // Fetch a first chunk of the bundle.
            let first_chunk_size = MIN_CHUNK_SIZE.raw.min(
                content_length.expect("range query support probe provides the content length"),
            );
            let range = format!("bytes=0-{}", first_chunk_size - 1);
            (
                get_with_retry(url, Some(&range), &retry_config)
                    .whatever("unable to get bundle from URL")?,
                Some(first_chunk_size),
            )
        };
        Ok(Self {
            url: url.to_owned(),
            range_query_strategy,
            content_length,
            current_response: Some(current_response),
            current_end,
            next_chunk_end: None,
            current_skipped: 0,
            current_position: 0,
            skip_buffer: Vec::new(),
            bytes_read: 0,
            bytes_skipped: 0,
            total_bytes: content_length.map(|l| l.into()),
            retry_config,
            consecutive_retries: 0,
        })
    }
}

impl HttpSource {
    pub fn get_download_stats(&self) -> DownloadStats {
        DownloadStats {
            bytes_read: NumBytes::new(self.bytes_read),
            bytes_skipped: NumBytes::new(self.bytes_skipped),
        }
    }

    /// Issues a Range GET request with retry and exponential backoff.
    fn fetch_range_with_retry(
        &mut self,
        start: u64,
        end: u64,
    ) -> rugix_bundle::BundleResult<Response<Body>> {
        let range_header = format!("bytes={}-{}", start, end - 1);
        loop {
            let mut request = ureq::get(&self.url);
            request = request.header("Range", &range_header);
            match request.call() {
                Ok(response) => {
                    // Validate the server still supports range queries.
                    if response.status() != 206 {
                        bail!(
                            "server returned {} instead of 206 for range request",
                            response.status(),
                        );
                    }
                    // Validate content length hasn't changed (content wasn't replaced).
                    if let Some(expected) = self.content_length {
                        if let Some(total) = response
                            .headers()
                            .get("Content-Range")
                            .and_then(|r| r.to_str().ok())
                            .and_then(|r| r.rsplit_once("/"))
                            .and_then(|(_, total)| total.trim().parse::<u64>().ok())
                        {
                            if total != expected {
                                bail!(
                                    "content length changed during download ({expected} -> {total})",
                                );
                            }
                        }
                    }
                    return Ok(response);
                }
                Err(err) => {
                    if !is_retryable(&err)
                        || self.consecutive_retries >= self.retry_config.max_retries
                    {
                        return Err(err).whatever("unable to get bundle from URL after retries");
                    }
                    let backoff = compute_backoff(&self.retry_config, self.consecutive_retries);
                    warn!(
                        url = %self.url,
                        attempt = self.consecutive_retries + 1,
                        max_retries = self.retry_config.max_retries,
                        backoff_ms = backoff.as_millis() as u64,
                        position = start,
                        error = %err,
                        "HTTP range request failed, retrying after backoff",
                    );
                    std::thread::sleep(backoff);
                    self.consecutive_retries += 1;
                }
            }
        }
    }

    /// Applies the retry policy to a response-body failure and prepares a reconnect.
    fn reconnect_after_body_error(&mut self, io_err: &io::Error, action: &'static str) -> bool {
        if self.range_query_strategy == RangeQueryStrategy::Disabled
            || self.consecutive_retries >= self.retry_config.max_retries
        {
            return false;
        }
        let backoff = compute_backoff(&self.retry_config, self.consecutive_retries);
        warn!(
            url = %self.url,
            attempt = self.consecutive_retries + 1,
            max_retries = self.retry_config.max_retries,
            backoff_ms = backoff.as_millis() as u64,
            position = self.current_position,
            error = %io_err,
            action,
            "HTTP response read failed, reconnecting after backoff",
        );
        std::thread::sleep(backoff);
        self.consecutive_retries += 1;
        self.current_response = None;
        true
    }
}

impl BundleSource for HttpSource {
    fn read(&mut self, slice: &mut [u8]) -> rugix_bundle::BundleResult<usize> {
        assert_ne!(slice.len(), 0, "slice must not be empty");
        if self.current_skipped > 0 {
            self.current_position += self.current_skipped;
            // Check whether we exceeded the chunk that we are currently reading. Note
            // that the end position is itself not included in the chunk.
            let chunk_exceeded = self
                .current_end
                .map(|end| self.current_position >= end)
                .unwrap_or(false);
            if chunk_exceeded {
                // We have exceeded the chunk and need to fetch a new one.
                self.current_response = None;
                let actually_skipped = self.current_position
                    - self
                        .current_end
                        .expect("an exceeded chunk has a known end position");
                // Count the bytes that were still in the pending request as read.
                self.bytes_skipped += actually_skipped;
                self.bytes_read += self.current_skipped - actually_skipped;
            } else {
                // We are still within the chunk and need to skip the bytes by reading.
                if self.current_response.is_some() {
                    // Read the bytes that we skip from the current response.
                    let mut remaining = self.current_skipped;
                    while remaining > 0 {
                        self.skip_buffer.resize(remaining.min(8192) as usize, 0);
                        let read_result = self
                            .current_response
                            .as_mut()
                            .expect("the current response was checked before reading skipped bytes")
                            .body_mut()
                            .as_reader()
                            .read(&mut self.skip_buffer);
                        let read = match read_result {
                            Ok(0) => {
                                error!("unexpected end of HTTP stream during skip");
                                self.current_response = None;
                                break;
                            }
                            Ok(n) => n,
                            Err(io_err) => {
                                if !self
                                    .reconnect_after_body_error(&io_err, "skipping bundle bytes")
                                {
                                    return Err(io_err).whatever("unable to read from HTTP source");
                                }
                                break;
                            }
                        };
                        self.consecutive_retries = 0;
                        remaining -= read as u64;
                    }
                    // Account for bytes actually consumed vs truly skipped.
                    let consumed = self.current_skipped - remaining;
                    self.bytes_read += consumed;
                    self.bytes_skipped += remaining;
                } else {
                    self.bytes_skipped += self.current_skipped;
                }
            }
            self.current_skipped = 0;
        }
        loop {
            if self.current_response.is_none() {
                // We need to issue a new request for a new chunk.
                if self.range_query_strategy == RangeQueryStrategy::Disabled {
                    if self.content_length == Some(self.current_position) {
                        return Ok(0);
                    }
                    bail!("response is not available but range queries are not supported");
                }
                // Compute the end of the next chunk using the provided hint, if any.
                let content_length = self
                    .content_length
                    .expect("range query support probe provides the content length");
                let next_end = if self.range_query_strategy == RangeQueryStrategy::Dynamic {
                    (self.current_position + MIN_CHUNK_SIZE.raw.max(slice.len() as u64))
                        .max(self.next_chunk_end.unwrap_or(0))
                        .min(content_length)
                } else {
                    content_length
                };
                self.next_chunk_end = None;
                if self.current_position == next_end {
                    assert_eq!(self.current_position, content_length);
                    // We reached the end of the update bundle, return `0`.
                    return Ok(0);
                }
                assert!(self.current_position < next_end);
                self.current_response =
                    Some(self.fetch_range_with_retry(self.current_position, next_end)?);
                self.current_end = Some(next_end);
            }
            // We should now be able to read some bytes from the current response.
            let read_result = self
                .current_response
                .as_mut()
                .expect("a response is available after reconnecting when necessary")
                .body_mut()
                .as_reader()
                .read(slice);
            let read = match read_result {
                Ok(0)
                    if self
                        .current_end
                        .is_some_and(|end| self.current_position < end) =>
                {
                    let io_err = io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "HTTP response ended before the requested range was complete",
                    );
                    if !self.reconnect_after_body_error(&io_err, "reading bundle bytes") {
                        return Err(io_err).whatever("unable to read from HTTP source");
                    }
                    continue;
                }
                Ok(0) => {
                    // We reached the end of the response. Do a followup request.
                    self.current_response = None;
                    continue;
                }
                Ok(n) => n,
                Err(io_err) => {
                    if !self.reconnect_after_body_error(&io_err, "reading bundle bytes") {
                        return Err(io_err).whatever("unable to read from HTTP source");
                    }
                    continue;
                }
            };
            self.consecutive_retries = 0;
            self.bytes_read += read as u64;
            self.current_position += read as u64;
            break Ok(read);
        }
    }

    fn hint_next_chunk(&mut self, length: NumBytes) {
        if length.raw != 0 {
            self.next_chunk_end = Some(self.current_position + length.raw);
        }
    }

    fn skip(&mut self, length: byte_calc::NumBytes) -> rugix_bundle::BundleResult<()> {
        self.current_skipped += length.raw;
        Ok(())
    }

    fn bytes_read(&self) -> Option<NumBytes> {
        Some(NumBytes::new(
            self.bytes_read + self.bytes_skipped + self.current_skipped,
        ))
    }

    fn bytes_total(&self) -> Option<NumBytes> {
        self.total_bytes
    }
}
