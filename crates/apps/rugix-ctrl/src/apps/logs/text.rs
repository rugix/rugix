//! Rendering of log records for humans.

use std::io;
use std::io::Write;

use sidex::types::JsonValue;

use crate::config::output::AppLogRecord;
use crate::config::output::AppLogSeverity;

/// Write a record as text, followed by a newline.
///
/// The text consists of the time, the source, the severity, the message, and the
/// fields as `key=value` pairs, omitting what the record lacks. It spans several lines
/// if the message does.
pub fn write_text(out: &mut impl Write, record: &AppLogRecord) -> io::Result<()> {
    let mut parts = Vec::new();
    if let Some(timestamp) = &record.timestamp {
        parts.push(timestamp.to_string());
    }
    if let Some(source) = &record.source {
        parts.push(source.to_string());
    }
    if let Some(severity) = record.severity {
        parts.push(severity_name(severity).to_owned());
    }
    parts.push(record.message.to_string());
    for (key, value) in record.fields.iter().flat_map(|fields| fields.iter()) {
        parts.push(format!("{key}={}", field_value(value)));
    }
    if record.truncated == Some(true) {
        parts.push("[truncated]".to_owned());
    }
    writeln!(out, "{}", parts.join(" "))
}

fn severity_name(severity: AppLogSeverity) -> &'static str {
    match severity {
        AppLogSeverity::Trace => "TRACE",
        AppLogSeverity::Debug => "DEBUG",
        AppLogSeverity::Info => "INFO",
        AppLogSeverity::Warning => "WARNING",
        AppLogSeverity::Error => "ERROR",
        AppLogSeverity::Critical => "CRITICAL",
    }
}

/// Render a field value, quoting strings only where needed to keep pairs apart.
fn field_value(value: &JsonValue) -> String {
    match value {
        JsonValue::String(text)
            if !text.is_empty()
                && !text
                    .chars()
                    .any(|char| char.is_whitespace() || char == '"' || char == '=') =>
        {
            text.to_string()
        }
        value => sidex::formats::json::to_string(value)
            .expect("JSON values can always be encoded as JSON"),
    }
}

#[cfg(test)]
mod tests {
    use sidex::types::JsonValue;
    use sidex::types::Map;
    use sidex::types::Str;

    use super::write_text;
    use crate::config::output::AppLogRecord;
    use crate::config::output::AppLogSeverity;

    /// Verifies that records render as one line with quoted field values where
    /// necessary.
    #[test]
    fn records_render_as_lines() {
        let fields = [
            ("user", JsonValue::from("alice")),
            ("note", JsonValue::from("two words")),
            ("count", JsonValue::from(3)),
        ]
        .into_iter()
        .map(|(key, value)| (Str::from(key), value))
        .collect::<Map<_, _>>();
        let record = AppLogRecord::new("login failed")
            .with_timestamp(Some("2026-11-17T10:21:03Z".into()))
            .with_source(Some("web".into()))
            .with_severity(Some(AppLogSeverity::Warning))
            .with_fields(Some(fields));
        let mut out = Vec::new();
        write_text(&mut out, &record).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "2026-11-17T10:21:03Z web WARNING login failed user=alice note=\"two words\" count=3\n"
        );
    }
}
