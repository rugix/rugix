//! Pooled HTTP bundle access, independent range readers, and resumable streams.
//!
//! [`HttpSource`] probes access capabilities and yields an owned
//! [`BundleSource`] and a separate [`DownloadTracker`]. The bundle reader plans
//! and verifies blocks; this backend acquires their encoded byte intervals.
//!
//! Each installation shares one `ureq::Agent` connection pool. Readers consume
//! completed response bodies through EOF to return connections to the pool.
//! Range responses must match the requested interval and probed resource length,
//! and content encoding must preserve byte offsets. A strong ETag, when supplied,
//! pins subsequent requests through `If-Match`. Servers without range support
//! fall back to the original full response. Disabling ranges opens a stream.
//!
//! DNS, connection setup, request transmission, and response headers have
//! 60-second deadlines. [`HttpFetchConfig`] separately bounds idle socket reads,
//! including TLS control traffic, without limiting the total duration of a
//! progressing body. It also configures the range size, worker concurrency, and
//! connection-pool capacity. The transport uses ureq's unversioned API and must
//! be checked when upgrading ureq.
//!
//! Each reader resumes transient failures from its own remaining interval and
//! resets its consecutive retry count when body bytes arrive. Invalid ranges
//! and changed representations are terminal. Cancellation interrupts backoff
//! immediately; active network operations end at their current deadline.
//!
//! [`DownloadTracker`] counts actual response-body bytes, including probes and
//! replacement reads. Skipped bytes are the resource length minus the union of
//! consumed intervals. Readers must close before coverage statistics are final;
//! these counters are separate from the bundle parser's logical progress.

use std::io;
use std::io::Read;
use std::ops::Range;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::time::Duration;

use reportify::bail;
use reportify::ResultExt;
use rugix_bundle::reader::BundleSource;
use rugix_bundle::reader::RangeSource;
use rugix_bundle::reader::SourceReader;
use rugix_bundle::BundleResult;
use serde::Deserialize;
use serde::Serialize;
use tracing::warn;
use ureq::http::Response;
use ureq::unversioned::resolver::DefaultResolver;
use ureq::Body;

use crate::system::SystemResult;

mod options;
mod stats;
mod transport;

pub(crate) use options::parse_max_range_size;
pub use options::HttpFetchConfig;
pub use stats::DownloadStats;

use stats::Counters;
use transport::connector;

/// Configuration for consecutive HTTP retry attempts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
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

/// Requested access mode; the probe may resolve an unsupported range mode to a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeQueryStrategy {
    Disabled,
    Resume,
    Dynamic,
}

/// An owned input and a separate traffic tracker for one install operation.
pub struct HttpSource {
    source: BundleSource,
    tracker: DownloadTracker,
}

/// Read counters after all cursors and fetch workers have closed their readers.
pub struct DownloadTracker {
    resource: Arc<HttpResource>,
}

impl DownloadTracker {
    pub fn get_download_stats(&self) -> DownloadStats {
        self.resource.session.counters.snapshot(self.resource.size)
    }

    pub fn size_hint(&self) -> Option<byte_calc::NumBytes> {
        self.resource.size.map(Into::into)
    }
}

impl HttpSource {
    pub(crate) fn new(
        url: &str,
        strategy: RangeQueryStrategy,
        retry: RetryConfig,
        options: &HttpFetchConfig,
    ) -> SystemResult<Self> {
        Self::new_with_timeouts(url, strategy, retry, Duration::from_secs(60), options)
    }

    fn new_with_timeouts(
        url: &str,
        strategy: RangeQueryStrategy,
        retry: RetryConfig,
        timeout: Duration,
        options: &HttpFetchConfig,
    ) -> SystemResult<Self> {
        if options.stall_timeout.is_zero() {
            bail!("HTTP stall timeout must be positive");
        }
        let cancellation = Arc::new(Cancellation::default());
        // ureq carries a configured response deadline into body reads. The
        // request-send deadline also bounds GET response headers; the transport
        // bounds body idleness without expiring a progressing stream.
        let config = ureq::Agent::config_builder()
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            )
            .timeout_resolve(Some(timeout))
            .timeout_connect(Some(timeout))
            .timeout_send_request(Some(timeout))
            .max_idle_connections(options.concurrency.get().saturating_mul(2))
            .max_idle_connections_per_host(options.concurrency.get())
            .build();
        let agent = ureq::Agent::with_parts(
            config,
            connector(options.stall_timeout, Arc::clone(&cancellation)),
            DefaultResolver::default(),
        );
        let session = Arc::new(HttpSession {
            agent,
            url: url.to_owned(),
            retry,
            cancellation,
            counters: Counters::default(),
        });
        let mut retries = 0;
        let probe = strategy != RangeQueryStrategy::Disabled;
        let response = session
            .request(
                if probe { Some("bytes=0-0") } else { None },
                None,
                &mut retries,
            )
            .whatever("unable to open HTTP bundle source")?;
        validate_encoding(&response).whatever("invalid HTTP bundle encoding")?;
        let ranges = probe && response.status() == 206;
        let size = if ranges {
            let (start, end, total) =
                content_range(&response).whatever("invalid range support response")?;
            if start != 0 || end != 1 || total == 0 {
                bail!("range support probe returned the wrong interval");
            }
            Some(total)
        } else {
            if response.status() != 200 {
                bail!("HTTP server returned an unexpected bundle status");
            }
            content_length(&response).whatever("invalid bundle content length")?
        };
        let etag = response
            .headers()
            .get("ETag")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.starts_with("W/"))
            .map(Arc::<str>::from);
        let resource = Arc::new(HttpResource {
            session,
            size,
            etag,
            ranges,
        });
        let source = if ranges {
            let mut reader =
                HttpReader::new(resource.as_ref().clone(), response, 0, Some(1), retries);
            reader
                .read_exact(&mut [0])
                .whatever("unable to read range support probe")?;
            drop(reader);
            if strategy == RangeQueryStrategy::Dynamic {
                BundleSource::RangeSource(Arc::clone(&resource) as Arc<dyn RangeSource>)
            } else {
                let mut retries = 0;
                let response = resource
                    .full_response(&mut retries)
                    .whatever("unable to open streaming bundle response")?;
                BundleSource::StreamSource(Box::new(HttpReader::new(
                    resource.as_ref().clone(),
                    response,
                    0,
                    size,
                    retries,
                )))
            }
        } else {
            BundleSource::StreamSource(Box::new(HttpReader::new(
                resource.as_ref().clone(),
                response,
                0,
                size,
                retries,
            )))
        };
        Ok(Self {
            source,
            tracker: DownloadTracker { resource },
        })
    }

    pub fn into_parts(self) -> (BundleSource, DownloadTracker) {
        (self.source, self.tracker)
    }
}

/// Each session owns one connection pool shared by all payload range readers.
struct HttpSession {
    agent: ureq::Agent,
    url: String,
    retry: RetryConfig,
    cancellation: Arc<Cancellation>,
    counters: Counters,
}

impl HttpSession {
    fn request(
        &self,
        range: Option<&str>,
        etag: Option<&str>,
        retries: &mut u32,
    ) -> BundleResult<Response<Body>> {
        loop {
            if self.cancellation.is_canceled() {
                bail!("bundle download canceled")
            }
            let mut request = self
                .agent
                .get(&self.url)
                .header("Accept-Encoding", "identity");
            if let Some(range) = range {
                request = request.header("Range", range)
            }
            if let Some(etag) = etag {
                request = request.header("If-Match", etag)
            }
            match request.call() {
                Ok(response) => return Ok(response),
                Err(error) => {
                    if !is_retryable(&error) || *retries >= self.retry.max_retries {
                        return Err(error).whatever("HTTP bundle request failed");
                    }
                    warn!(attempt = *retries + 1, %error, "HTTP bundle request failed, retrying");
                    self.backoff(*retries)?;
                    *retries += 1;
                }
            }
        }
    }

    fn backoff(&self, retries: u32) -> BundleResult<()> {
        let seconds = (self.retry.initial_backoff.as_secs_f64() * 2.0_f64.powf(f64::from(retries)))
            .min(self.retry.max_backoff.as_secs_f64());
        self.cancellation.wait(Duration::from_secs_f64(seconds))
    }
}

/// Length and optional strong validator describe one selected representation.
#[derive(Clone)]
struct HttpResource {
    session: Arc<HttpSession>,
    size: Option<u64>,
    etag: Option<Arc<str>>,
    ranges: bool,
}

impl HttpResource {
    fn range_response(&self, range: Range<u64>, retries: &mut u32) -> BundleResult<Response<Body>> {
        let header = format!("bytes={}-{}", range.start, range.end - 1);
        let response = self
            .session
            .request(Some(&header), self.etag.as_deref(), retries)?;
        if response.status() != 206 {
            bail!(
                "server returned {} instead of 206 for range request",
                response.status()
            );
        }
        self.validate(&response)?;
        let (start, end, total) = content_range(&response)?;
        if start != range.start || end != range.end || Some(total) != self.size {
            bail!("server returned the wrong bundle range or changed its length");
        }
        if content_length(&response)?.is_some_and(|length| length != end - start) {
            bail!("range response content length does not match its interval");
        }
        Ok(response)
    }

    fn full_response(&self, retries: &mut u32) -> BundleResult<Response<Body>> {
        let response = self.session.request(None, self.etag.as_deref(), retries)?;
        if response.status() != 200 {
            bail!("server did not return a full bundle response")
        }
        self.validate(&response)?;
        if let (Some(expected), Some(found)) = (self.size, content_length(&response)?) {
            if expected != found {
                bail!("bundle length changed during download")
            }
        }
        Ok(response)
    }

    fn validate(&self, response: &Response<Body>) -> BundleResult<()> {
        validate_encoding(response)?;
        if let (Some(expected), Some(found)) = (&self.etag, response.headers().get("ETag")) {
            if found.to_str().whatever("invalid bundle ETag")? != expected.as_ref() {
                bail!("bundle ETag changed during download");
            }
        }
        Ok(())
    }
}

impl RangeSource for HttpResource {
    fn size(&self) -> u64 {
        self.size
            .expect("range-capable HTTP resources have a probed length")
    }

    fn open_range(&self, range: Range<u64>) -> BundleResult<SourceReader> {
        if range.start > range.end || range.end > self.size() {
            bail!("bundle range is outside the source");
        }
        if range.is_empty() {
            return Ok(Box::new(io::empty()));
        }
        let mut retries = 0;
        let response = self.range_response(range.clone(), &mut retries)?;
        Ok(Box::new(HttpReader::new(
            self.clone(),
            response,
            range.start,
            Some(range.end),
            retries,
        )))
    }

    fn cancel(&self) {
        self.session.cancellation.cancel();
    }
}

/// A response body and its private absolute position; retries resume only this reader.
struct HttpReader {
    resource: HttpResource,
    reader: SourceReader,
    start: u64,
    position: u64,
    end: Option<u64>,
    retries: u32,
}

impl HttpReader {
    fn new(
        resource: HttpResource,
        response: Response<Body>,
        start: u64,
        end: Option<u64>,
        retries: u32,
    ) -> Self {
        Self {
            resource,
            reader: Box::new(response.into_body().into_reader()),
            start,
            position: start,
            end,
            retries,
        }
    }
}

impl Read for HttpReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.end == Some(self.position) {
            return Ok(0);
        }
        let length = self
            .end
            .map(|end| (end - self.position).min(buffer.len() as u64) as usize)
            .unwrap_or(buffer.len());
        loop {
            if self.resource.session.cancellation.is_canceled() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "bundle download canceled",
                ));
            }
            let error = match self.reader.read(&mut buffer[..length]) {
                Ok(0) if self.end.is_some() => io::Error::from(io::ErrorKind::UnexpectedEof),
                Ok(read) => {
                    self.position += read as u64;
                    self.resource
                        .session
                        .counters
                        .bytes_read
                        .fetch_add(read as u64, Ordering::Relaxed);
                    if read > 0 {
                        self.retries = 0;
                        if self.end == Some(self.position) {
                            let mut extra = [0];
                            if self.reader.read(&mut extra)? != 0 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "HTTP response exceeded its declared bundle range",
                                ));
                            }
                        }
                    }
                    return Ok(read);
                }
                Err(error) => error,
            };
            if !self.resource.ranges
                || self.retries >= self.resource.session.retry.max_retries
                || !matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::Other
                )
            {
                return Err(error);
            }
            warn!(position = self.position, attempt = self.retries + 1, %error, "HTTP body interrupted, resuming range");
            self.resource
                .session
                .backoff(self.retries)
                .map_err(|error| io::Error::other(format!("{error:?}")))?;
            self.retries += 1;
            let end = self
                .end
                .expect("range-capable response bodies have a known end");
            let response = self
                .resource
                .range_response(self.position..end, &mut self.retries)
                .map_err(|error| io::Error::other(format!("{error:?}")))?;
            self.reader = Box::new(response.into_body().into_reader());
        }
    }
}

impl Drop for HttpReader {
    fn drop(&mut self) {
        self.resource
            .session
            .counters
            .record(self.start..self.position);
    }
}

#[derive(Debug, Default)]
pub(crate) struct Cancellation {
    canceled: Mutex<bool>,
    changed: Condvar,
}

impl Cancellation {
    fn is_canceled(&self) -> bool {
        *self
            .canceled
            .lock()
            .expect("cancellation lock only guards a boolean")
    }

    fn cancel(&self) {
        *self
            .canceled
            .lock()
            .expect("cancellation lock only guards a boolean") = true;
        self.changed.notify_all();
    }

    fn wait(&self, duration: Duration) -> BundleResult<()> {
        let guard = self
            .canceled
            .lock()
            .expect("cancellation lock only guards a boolean");
        let (canceled, _) = self
            .changed
            .wait_timeout_while(guard, duration, |canceled| !*canceled)
            .expect("cancellation lock only guards a boolean");
        if *canceled {
            bail!("bundle download canceled")
        }
        Ok(())
    }
}

fn is_retryable(error: &ureq::Error) -> bool {
    matches!(
        error,
        ureq::Error::Io(_)
            | ureq::Error::Timeout(_)
            | ureq::Error::HostNotFound
            | ureq::Error::ConnectionFailed
            | ureq::Error::StatusCode(429 | 500 | 502 | 503 | 504)
    )
}

fn content_length(response: &Response<Body>) -> BundleResult<Option<u64>> {
    response
        .headers()
        .get("Content-Length")
        .map(|value| {
            value
                .to_str()
                .whatever("invalid content length header")?
                .parse::<u64>()
                .whatever("invalid content length value")
        })
        .transpose()
}

fn content_range(response: &Response<Body>) -> BundleResult<(u64, u64, u64)> {
    let value = response
        .headers()
        .get("Content-Range")
        .ok_or_else(|| reportify::whatever!("range response lacks Content-Range"))?
        .to_str()
        .whatever("invalid content range header")?;
    let value = value
        .strip_prefix("bytes ")
        .ok_or_else(|| reportify::whatever!("invalid content range unit"))?;
    let (range, total) = value
        .split_once('/')
        .ok_or_else(|| reportify::whatever!("invalid content range total"))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| reportify::whatever!("invalid content range interval"))?;
    let start: u64 = start.parse::<u64>().whatever("invalid range start")?;
    let end: u64 = end.parse::<u64>().whatever("invalid range end")?;
    let total: u64 = total.parse::<u64>().whatever("invalid range total")?;
    let end = end
        .checked_add(1)
        .ok_or_else(|| reportify::whatever!("range end overflow"))?;
    if start >= end || end > total {
        bail!("invalid content range bounds")
    }
    Ok((start, end, total))
}

fn validate_encoding(response: &Response<Body>) -> BundleResult<()> {
    if let Some(encoding) = response.headers().get("Content-Encoding") {
        if !encoding
            .to_str()
            .whatever("invalid HTTP content encoding")?
            .eq_ignore_ascii_case("identity")
        {
            bail!("encoded HTTP responses cannot preserve bundle byte offsets");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::BufRead;
    use std::io::BufReader;
    use std::io::Read;
    use std::io::Write;
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread::JoinHandle;
    use std::time::Duration;
    use std::time::Instant;

    use rugix_bundle::reader::BundleSource;

    use super::HttpFetchConfig;
    use super::HttpSource;
    use super::RangeQueryStrategy;
    use super::RetryConfig;

    const TIMEOUT: Duration = Duration::from_millis(200);

    struct Response {
        status: &'static str,
        headers: String,
        header_delay: Duration,
        chunks: Vec<(Duration, Vec<u8>)>,
        close: bool,
    }

    impl Response {
        fn range(start: usize, end: usize) -> Self {
            Self {
                status: "206 Partial Content",
                headers: format!(
                "Content-Range: bytes {start}-{}/8\r\nContent-Length: {}\r\nETag: \"fixture\"\r\n",
                end - 1,
                end - start
            ),
                header_delay: Duration::ZERO,
                chunks: vec![(Duration::ZERO, b"01234567"[start..end].to_vec())],
                close: false,
            }
        }

        fn full() -> Self {
            Self {
                status: "200 OK",
                headers: "Content-Length: 8\r\n".into(),
                header_delay: Duration::ZERO,
                chunks: vec![(Duration::ZERO, b"01234567".to_vec())],
                close: false,
            }
        }
    }

    #[derive(Default)]
    struct State {
        responses: Mutex<VecDeque<Response>>,
        requests: Mutex<Vec<String>>,
        connections: AtomicUsize,
        stopping: AtomicBool,
    }

    /// Scripted responses use real TCP connections and persistent HTTP/1.1 bodies.
    struct Server {
        url: String,
        state: Arc<State>,
        worker: Option<JoinHandle<()>>,
    }

    impl Server {
        fn new(responses: Vec<Response>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/bundle", listener.local_addr().unwrap());
            listener.set_nonblocking(true).unwrap();
            let state = Arc::new(State {
                responses: Mutex::new(responses.into()),
                ..State::default()
            });
            let worker_state = Arc::clone(&state);
            let worker = std::thread::spawn(move || {
                let mut connections = Vec::new();
                while !worker_state.stopping.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            worker_state.connections.fetch_add(1, Ordering::Relaxed);
                            let state = Arc::clone(&worker_state);
                            connections.push(std::thread::spawn(move || serve(stream, state)));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("unable to accept test HTTP connection: {error}"),
                    }
                }
                for connection in connections {
                    connection.join().unwrap();
                }
            });
            Self {
                url,
                state,
                worker: Some(worker),
            }
        }

        fn source(&self, strategy: RangeQueryStrategy, retries: u32) -> HttpSource {
            HttpSource::new_with_timeouts(
                &self.url,
                strategy,
                RetryConfig {
                    max_retries: retries,
                    initial_backoff: Duration::ZERO,
                    max_backoff: Duration::ZERO,
                },
                TIMEOUT,
                &HttpFetchConfig {
                    stall_timeout: TIMEOUT,
                    ..HttpFetchConfig::default()
                },
            )
            .unwrap()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.state.stopping.store(true, Ordering::Relaxed);
            self.worker.take().unwrap().join().unwrap();
        }
    }

    fn serve(mut stream: TcpStream, state: Arc<State>) {
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        stream.set_nodelay(true).unwrap();
        let mut input = BufReader::new(stream.try_clone().unwrap());
        while !state.stopping.load(Ordering::Relaxed) {
            let mut request = String::new();
            match input.read_line(&mut request) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(_) => break,
            }
            loop {
                let mut line = String::new();
                if input.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                if line == "\r\n" {
                    break;
                }
                request.push_str(&line);
            }
            state.requests.lock().unwrap().push(request);
            let Some(response) = state.responses.lock().unwrap().pop_front() else {
                break;
            };
            std::thread::sleep(response.header_delay);
            let connection = if response.close {
                "close"
            } else {
                "keep-alive"
            };
            if write!(
                stream,
                "HTTP/1.1 {}\r\n{}Connection: {connection}\r\n\r\n",
                response.status, response.headers
            )
            .is_err()
            {
                break;
            }
            for (delay, bytes) in response.chunks {
                std::thread::sleep(delay);
                if stream.write_all(&bytes).is_err() {
                    return;
                }
            }
            if response.close {
                break;
            }
        }
    }

    /// Separate readers keep their positions and completed readers return pooled
    /// connections.
    #[test]
    fn independent_ranges_reuse_connections() {
        let server = Server::new(vec![
            Response::range(0, 1),
            Response::range(2, 6),
            Response::range(0, 4),
            Response::range(4, 8),
        ]);
        let (source, tracker) = server.source(RangeQueryStrategy::Dynamic, 0).into_parts();
        let BundleSource::RangeSource(source) = source else {
            panic!("expected range source");
        };
        let mut first = source.open_range(2..6).unwrap();
        let mut bytes = Vec::new();
        first.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"2345");
        drop(first);
        assert_eq!(server.state.connections.load(Ordering::Relaxed), 1);
        let mut left = source.open_range(0..4).unwrap();
        let mut right = source.open_range(4..8).unwrap();
        let mut bytes = Vec::new();
        right.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"4567");
        drop(right);
        let mut bytes = Vec::new();
        left.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"0123");
        drop(left);
        assert_eq!(server.state.connections.load(Ordering::Relaxed), 2);
        assert_eq!(tracker.get_download_stats().bytes_read.raw, 13);
        assert_eq!(tracker.get_download_stats().bytes_skipped.raw, 0);
        let requests = server.state.requests.lock().unwrap();
        assert!(requests.iter().skip(1).all(|request| request
            .to_ascii_lowercase()
            .contains("if-match: \"fixture\"")));
    }

    /// A truncated body resumes at its private cursor without downloading received bytes
    /// again.
    #[test]
    fn truncated_range_resumes_at_the_remaining_interval() {
        let mut interrupted = Response::range(2, 8);
        interrupted.chunks[0].1.truncate(3);
        interrupted.close = true;
        let server = Server::new(vec![
            Response::range(0, 1),
            interrupted,
            Response::range(5, 8),
        ]);
        let (source, tracker) = server.source(RangeQueryStrategy::Dynamic, 1).into_parts();
        let BundleSource::RangeSource(source) = source else {
            panic!("expected range source");
        };
        let mut reader = source.open_range(2..8).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"234567");
        drop(reader);
        assert_eq!(tracker.get_download_stats().bytes_read.raw, 7);
        assert!(server.state.requests.lock().unwrap()[2]
            .to_ascii_lowercase()
            .contains("range: bytes=5-7"));
    }

    /// Repeated empty responses exhaust the retry budget instead of looping indefinitely.
    #[test]
    fn retries_without_progress_are_bounded() {
        let empty = || {
            let mut response = Response::range(2, 8);
            response.chunks.clear();
            response.close = true;
            response
        };
        let server = Server::new(vec![Response::range(0, 1), empty(), empty(), empty()]);
        let (source, _) = server.source(RangeQueryStrategy::Dynamic, 2).into_parts();
        let BundleSource::RangeSource(source) = source else {
            panic!("expected range source");
        };
        let mut reader = source.open_range(2..8).unwrap();
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        assert_eq!(server.state.requests.lock().unwrap().len(), 4);
    }

    /// Wrong ranges and changed representations fail even when retrying is enabled.
    #[test]
    fn invalid_range_responses_are_terminal() {
        for mut invalid in [Response::range(1, 8), Response::range(2, 8)] {
            if invalid.headers.contains("bytes 2-7") {
                invalid.headers = invalid.headers.replace("\"fixture\"", "\"changed\"");
            }
            let server = Server::new(vec![Response::range(0, 1), invalid]);
            let (source, _) = server.source(RangeQueryStrategy::Dynamic, 5).into_parts();
            let BundleSource::RangeSource(source) = source else {
                panic!("expected range source");
            };
            assert!(source.open_range(2..8).is_err());
            assert_eq!(server.state.requests.lock().unwrap().len(), 2);
        }
    }

    /// Cancellation is terminal even for callers that retry Interrupted errors
    /// automatically.
    #[test]
    fn canceled_range_read_exact_returns() {
        let mut stalled = Response::range(2, 8);
        stalled.chunks[0].0 = TIMEOUT * 2;
        let server = Server::new(vec![Response::range(0, 1), stalled]);
        let (source, _) = server.source(RangeQueryStrategy::Dynamic, 5).into_parts();
        let BundleSource::RangeSource(source) = source else {
            panic!("expected range source");
        };
        let mut reader = source.open_range(2..8).unwrap();
        source.cancel();
        let error = reader.read_exact(&mut [0; 6]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(source.open_range(0..1).is_err());
    }

    /// Progressing bodies can outlive the idle deadline, while stalled bodies and headers
    /// cannot.
    #[test]
    fn idle_deadlines_allow_progressing_streams_and_bound_stalls() {
        let mut progressing = Response::full();
        progressing.chunks = b"01234567"
            .iter()
            .map(|byte| (TIMEOUT / 4, vec![*byte]))
            .collect();
        let server = Server::new(vec![progressing]);
        let (source, _) = HttpSource::new(
            &server.url,
            RangeQueryStrategy::Dynamic,
            RetryConfig {
                max_retries: 0,
                ..RetryConfig::default()
            },
            &HttpFetchConfig {
                stall_timeout: TIMEOUT / 2,
                ..HttpFetchConfig::default()
            },
        )
        .unwrap()
        .into_parts();
        let BundleSource::StreamSource(mut reader) = source else {
            panic!("expected streaming fallback");
        };
        let started = Instant::now();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"01234567");
        assert!(started.elapsed() > TIMEOUT);
        drop(reader);
        drop(server);

        let mut stalled = Response::full();
        stalled.chunks[0].0 = TIMEOUT * 2;
        let server = Server::new(vec![stalled]);
        let (source, _) = HttpSource::new(
            &server.url,
            RangeQueryStrategy::Disabled,
            RetryConfig {
                max_retries: 0,
                ..RetryConfig::default()
            },
            &HttpFetchConfig {
                stall_timeout: TIMEOUT / 2,
                ..HttpFetchConfig::default()
            },
        )
        .unwrap()
        .into_parts();
        let BundleSource::StreamSource(mut reader) = source else {
            panic!("expected stream");
        };
        let started = Instant::now();
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(reader);
        drop(server);

        let mut stalled = Response::full();
        stalled.header_delay = TIMEOUT * 2;
        let server = Server::new(vec![stalled]);
        let started = Instant::now();
        assert!(HttpSource::new_with_timeouts(
            &server.url,
            RangeQueryStrategy::Disabled,
            RetryConfig {
                max_retries: 0,
                ..RetryConfig::default()
            },
            TIMEOUT / 2,
            &HttpFetchConfig {
                stall_timeout: TIMEOUT * 3,
                ..HttpFetchConfig::default()
            }
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
