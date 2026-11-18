//! Reading the logs of app workloads.
//!
//! Orchestrators describe where the logs of a workload are as [`LogSource`]s, for
//! example, a `docker logs` or a `journalctl` command. [`read_logs`] runs the sources,
//! parses their output into [`AppLogRecord`]s, and returns the most recent records of
//! all sources in chronological order. [`write_text`] renders records for humans.
//!
//! Each line of log output becomes one record. Lines and messages are cut at fixed
//! lengths, which bounds the memory that a record of a misbehaving workload takes.
//! Journal entries whose line exceeds the limit cannot be parsed and are skipped.

use std::collections::VecDeque;
use std::io::BufReader;
use std::io::Read;
use std::num::NonZeroUsize;
use std::process::Command;
use std::process::Stdio;
use std::thread;

use reportify::ResultExt;
use rugix_bundle::manifest::AppLogFormat;
use serde::Deserialize;
use serde::Serialize;
use sidex::types::Timestamp;
use tracing::warn;

pub use self::text::write_text;
use super::AppsResult;
use crate::config::output::AppLogRecord;
use crate::config::output::AppLogStream;

mod app_format;
mod journal;
mod lines;
mod text;

pub(crate) use self::journal::GENERATION_FIELD as JOURNAL_GENERATION_FIELD;

/// Maximum length of a line of a source's output.
///
/// Longer lines are cut. Lines of structured formats, which carry fields besides the
/// message, may be longer than messages.
const MAX_LINE_BYTES: usize = 1024 * 1024;

/// Maximum length of the message of a record.
const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Maximum number of lines of a source's diagnostic output included in errors.
const MAX_DIAGNOSTIC_LINES: usize = 10;

/// Selection of the records to read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogQuery {
    /// Maximum number of records, keeping the most recent ones.
    pub lines: NonZeroUsize,
    /// Only include records logged at or after this time, and records without time.
    pub since: Option<Timestamp>,
    /// Only include records logged at or before this time, and records without time.
    pub until: Option<Timestamp>,
}

impl LogQuery {
    /// Check whether a record logged at the given time is selected.
    ///
    /// Records without a time are always selected.
    fn selects(&self, timestamp: Option<Timestamp>) -> bool {
        let Some(timestamp) = timestamp else {
            return true;
        };
        self.since.is_none_or(|since| since <= timestamp)
            && self.until.is_none_or(|until| timestamp <= until)
    }
}

/// Command printing logs of a workload.
///
/// Each output stream of the command must be in chronological order. The command should
/// print no more than the selected records, but [`read_logs`] drops any surplus.
pub struct LogSource {
    /// Command printing the logs.
    pub command: Command,
    /// Format of the command's output.
    pub format: LogSourceFormat,
    /// Producer of the records, unless the output names one.
    pub source: Option<String>,
    /// Generation whose workload produced the records, unless the output names one.
    pub generation: Option<u64>,
}

/// Format of a [`LogSource`]'s output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSourceFormat {
    /// Output of `docker logs --timestamps`.
    ///
    /// Standard output and standard error carry the respective streams of the container.
    DockerLogs,
    /// Output of `journalctl --output json`.
    Journal,
    /// Log records as JSON objects or plain lines, one per line.
    Records,
}

/// Read the most recent records of the given sources in chronological order.
///
/// Records keep the order of their output stream, which sources print in
/// chronological order. `format` is the format of the lines that the workload writes.
/// Fails if a source command fails.
pub fn read_logs(
    sources: Vec<LogSource>,
    query: &LogQuery,
    format: &AppLogFormat,
) -> AppsResult<Vec<AppLogRecord>> {
    let mut streams = Vec::new();
    for source in sources {
        streams.extend(read_source(source, query, format)?);
    }
    let mut records = merge(streams);
    let excess = records.len().saturating_sub(query.lines.get());
    Ok(records.drain(excess..).collect())
}

/// Run a source and return the selected records of each of its streams.
fn read_source(
    mut source: LogSource,
    query: &LogQuery,
    format: &AppLogFormat,
) -> AppsResult<Vec<VecDeque<AppLogRecord>>> {
    let program = source.command.get_program().to_string_lossy().into_owned();
    let mut child = source
        .command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .whatever_with(|_| format!("unable to run `{program}`"))?;
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let parser = LineParser {
        source_format: source.format,
        app_format: format,
        source: source.source.as_deref(),
        generation: source.generation,
    };
    let (stdout, stderr) = thread::scope(|scope| {
        let stderr = scope.spawn(|| read_stderr(stderr, &parser, query));
        let stdout = read_stream(stdout, query, |line| {
            parser.parse(line, AppLogStream::Stdout)
        });
        (
            stdout,
            stderr.join().expect("reading stderr does not panic"),
        )
    });
    let status = child
        .wait()
        .whatever_with(|_| format!("unable to wait for `{program}`"))?;
    let stdout = stdout.whatever_with(|_| format!("unable to read output of `{program}`"))?;
    let (stderr, diagnostics) =
        stderr.whatever_with(|_| format!("unable to read output of `{program}`"))?;
    if !status.success() {
        reportify::bail!(
            "`{program}` failed ({status}): {}",
            Vec::from(diagnostics).join("\n")
        );
    }
    Ok(vec![stdout, stderr])
}

/// Read standard error of a source.
///
/// Returns the records of the stream if the source format carries them there, and the
/// last lines for diagnostics.
fn read_stderr(
    stderr: impl Read,
    parser: &LineParser,
    query: &LogQuery,
) -> std::io::Result<(VecDeque<AppLogRecord>, VecDeque<String>)> {
    let mut diagnostics = VecDeque::new();
    let records = read_stream(stderr, query, |line| {
        if diagnostics.len() == MAX_DIAGNOSTIC_LINES {
            diagnostics.pop_front();
        }
        diagnostics.push_back(String::from_utf8_lossy(&line.bytes).into_owned());
        (parser.source_format == LogSourceFormat::DockerLogs).then(|| {
            parser
                .parse(line, AppLogStream::Stderr)
                .expect("every line of `docker logs` is a record")
        })
    })?;
    Ok((records, diagnostics))
}

/// Read a stream of a source and keep the selected records that `parse` returns for
/// its lines.
fn read_stream(
    stream: impl Read,
    query: &LogQuery,
    mut parse: impl FnMut(lines::Line) -> Option<AppLogRecord>,
) -> std::io::Result<VecDeque<AppLogRecord>> {
    let mut reader = BufReader::new(stream);
    let mut records = VecDeque::new();
    while let Some(line) = lines::read_line(&mut reader, MAX_LINE_BYTES)? {
        if let Some(record) = parse(line) {
            push_selected(&mut records, record, query);
        }
    }
    Ok(records)
}

/// Append a record if the query selects it, keeping only the most recent records.
fn push_selected(records: &mut VecDeque<AppLogRecord>, record: AppLogRecord, query: &LogQuery) {
    if !query.selects(record.timestamp) {
        return;
    }
    if records.len() == query.lines.get() {
        records.pop_front();
    }
    records.push_back(record);
}

/// Merge chronological streams into one, keeping the order within each stream.
///
/// A record without a time is ordered by the time of the preceding record of its stream.
fn merge(streams: Vec<VecDeque<AppLogRecord>>) -> Vec<AppLogRecord> {
    let mut streams = streams
        .into_iter()
        .map(|records| (None, records))
        .collect::<Vec<(Option<Timestamp>, _)>>();
    let mut merged = Vec::new();
    loop {
        let next = streams
            .iter()
            .enumerate()
            .filter_map(|(index, (previous, records))| {
                let record = records.front()?;
                Some((record.timestamp.or(*previous), index))
            })
            .min();
        let Some((_, index)) = next else {
            return merged;
        };
        let (previous, records) = &mut streams[index];
        let record = records.pop_front().expect("the chosen stream has a record");
        if record.timestamp.is_some() {
            *previous = record.timestamp;
        }
        merged.push(record);
    }
}

/// Parser of the lines of a source's output.
struct LineParser<'source> {
    source_format: LogSourceFormat,
    app_format: &'source AppLogFormat,
    source: Option<&'source str>,
    generation: Option<u64>,
}

impl LineParser<'_> {
    /// Parse a line into a record.
    ///
    /// `stream` is the stream of the source's output that carried the line. Returns
    /// `None` for lines that carry no record.
    fn parse(&self, line: lines::Line, stream: AppLogStream) -> Option<AppLogRecord> {
        let text = String::from_utf8_lossy(&line.bytes);
        let mut record = match self.source_format {
            LogSourceFormat::DockerLogs => {
                let (timestamp, message) = match text
                    .split_once(' ')
                    .and_then(|(timestamp, message)| Some((timestamp.parse().ok()?, message)))
                {
                    Some((timestamp, message)) => (Some(timestamp), message),
                    None => {
                        warn!(line = %text, "docker log line without timestamp");
                        (None, &*text)
                    }
                };
                self.workload_record(
                    AppLogRecord::new(message)
                        .with_timestamp(timestamp)
                        .with_stream(Some(stream)),
                )
            }
            LogSourceFormat::Journal => {
                let Some(entry) = journal::parse_entry(&line.bytes) else {
                    warn!(
                        truncated = line.truncated,
                        "skipping unparsable journal entry"
                    );
                    return None;
                };
                let record = AppLogRecord::new(entry.message)
                    .with_timestamp(entry.timestamp)
                    .with_severity(entry.severity)
                    .with_source(entry.source.map(Into::into))
                    .with_generation(entry.generation)
                    .with_fields((!entry.fields.is_empty()).then_some(entry.fields));
                self.workload_record(record)
            }
            LogSourceFormat::Records => {
                sidex::formats::json::from_str_strict::<AppLogRecord>(&text)
                    .unwrap_or_else(|_| self.workload_record(AppLogRecord::new(text.as_ref())))
            }
        };
        if record.source.is_none() {
            record.source = self.source.map(Into::into);
        }
        if record.generation.is_none() {
            record.generation = self.generation;
        }
        if line.truncated {
            record.truncated = Some(true);
        }
        truncate_message(&mut record);
        Some(record)
    }

    /// Interpret a record written by the workload according to the app's log format.
    fn workload_record(&self, mut record: AppLogRecord) -> AppLogRecord {
        app_format::apply(self.app_format, &mut record);
        record
    }
}

/// Cut the message of a record at [`MAX_MESSAGE_BYTES`].
fn truncate_message(record: &mut AppLogRecord) {
    if record.message.len() <= MAX_MESSAGE_BYTES {
        return;
    }
    let end = record.message.floor_char_boundary(MAX_MESSAGE_BYTES);
    record.message = record.message[..end].into();
    record.truncated = Some(true);
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::process::Command;

    use rugix_bundle::manifest::AppLogFormat;

    use super::read_logs;
    use super::LogQuery;
    use super::LogSource;
    use super::LogSourceFormat;

    fn shell_source(script: &str, format: LogSourceFormat, source: &str) -> LogSource {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        LogSource {
            command,
            format,
            source: Some(source.to_owned()),
            generation: Some(1),
        }
    }

    fn query(lines: usize, since: Option<&str>) -> LogQuery {
        LogQuery {
            lines: NonZeroUsize::new(lines).unwrap(),
            since: since.map(|since| since.parse().unwrap()),
            until: None,
        }
    }

    /// Verifies that the records of all sources and streams are merged in
    /// chronological order, that the time filter and the limit keep the most recent
    /// records, and that records without time keep their place in their stream.
    #[test]
    fn sources_are_merged_in_chronological_order() {
        let sources = || {
            vec![
                shell_source(
                    "echo '2026-01-01T00:00:01Z web one'; echo '2026-01-01T00:00:04Z web four' >&2",
                    LogSourceFormat::DockerLogs,
                    "web",
                ),
                shell_source(
                    r#"echo '{"timestamp":"2026-01-01T00:00:02Z","message":"two"}'; echo 'plain'; echo '{"timestamp":"2026-01-01T00:00:03Z","message":"three","source":"worker"}'"#,
                    LogSourceFormat::Records,
                    "orchestrator",
                ),
            ]
        };
        let summary = |records: Vec<crate::config::output::AppLogRecord>| {
            records
                .into_iter()
                .map(|record| format!("{}:{}", record.source.unwrap(), record.message))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            summary(read_logs(sources(), &query(10, None), &AppLogFormat::Text).unwrap()),
            [
                "web:web one",
                "orchestrator:two",
                "orchestrator:plain",
                "worker:three",
                "web:web four"
            ]
        );
        assert_eq!(
            summary(
                read_logs(
                    sources(),
                    &query(2, Some("2026-01-01T00:00:02Z")),
                    &AppLogFormat::Text
                )
                .unwrap()
            ),
            ["worker:three", "web:web four"]
        );
    }

    /// Verifies that a failing source fails the read with its diagnostics.
    #[test]
    fn failing_sources_report_their_diagnostics() {
        let source = shell_source(
            "echo 'no such container' >&2; exit 1",
            LogSourceFormat::Records,
            "app",
        );
        let error = read_logs(vec![source], &query(10, None), &AppLogFormat::Text).unwrap_err();
        assert!(
            format!("{error:?}").contains("no such container"),
            "{error:?}"
        );
    }
}
