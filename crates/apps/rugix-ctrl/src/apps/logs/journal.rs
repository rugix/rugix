//! Parsing of journal entries printed by `journalctl --output json`.
//!
//! Journald stores fields as byte strings. `journalctl` prints a field as a JSON
//! string if it is valid UTF-8 text, as an array of byte values otherwise, and as an
//! array of such values if an entry has the field more than once.

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::Deserialize;
use sidex::types::JsonValue;
use sidex::types::Map;
use sidex::types::Str;

use crate::config::output::AppLogSeverity;

/// Journal field carrying the generation of an app's workload.
///
/// The binary orchestrator adds it to every entry that the workload of a unit logs
/// with `LogExtraFields=`.
pub(crate) const GENERATION_FIELD: &str = "RUGIX_APP_GENERATION";

/// Journal entry relevant to an app's logs.
pub(crate) struct JournalEntry {
    /// Time at which journald received the entry.
    pub timestamp: Option<Timestamp>,
    /// Message of the entry.
    pub message: String,
    /// Severity derived from the syslog priority.
    pub severity: Option<AppLogSeverity>,
    /// Syslog identifier or command name of the logging process.
    pub source: Option<String>,
    /// Generation recorded in [`GENERATION_FIELD`].
    pub generation: Option<u64>,
    /// Fields that the logging process supplied.
    pub fields: Map<Str, JsonValue>,
}

/// Parse a line of `journalctl --output json` output.
///
/// Returns `None` for lines that are no journal entry.
pub(crate) fn parse_entry(line: &[u8]) -> Option<JournalEntry> {
    let mut fields = serde_json::from_slice::<BTreeMap<String, FieldValue>>(line).ok()?;
    let text = |fields: &mut BTreeMap<String, FieldValue>, name: &str| {
        fields.remove(name).and_then(FieldValue::into_text)
    };
    let timestamp = text(&mut fields, "__REALTIME_TIMESTAMP")
        .and_then(|micros| micros.parse().ok())
        .and_then(|micros| Timestamp::from_microsecond(micros).ok());
    let message = text(&mut fields, "MESSAGE").unwrap_or_default();
    let severity = text(&mut fields, "PRIORITY").and_then(|priority| severity(&priority));
    let source = text(&mut fields, "SYSLOG_IDENTIFIER").or_else(|| text(&mut fields, "_COMM"));
    let generation = text(&mut fields, GENERATION_FIELD).and_then(|value| value.parse().ok());
    // Systemd's own messages about the unit carry metadata of the service manager,
    // which would only clutter the logs of the app.
    let from_service_manager = text(&mut fields, "_PID").as_deref() == Some("1");
    let fields = if from_service_manager {
        Map::new()
    } else {
        fields
            .into_iter()
            .filter(|(name, _)| !name.starts_with('_') && !name.starts_with("SYSLOG_"))
            .filter_map(|(name, value)| Some((Str::from(name), value.into_json()?)))
            .collect()
    };
    Some(JournalEntry {
        timestamp,
        message,
        severity,
        source,
        generation,
        fields,
    })
}

/// Map a syslog priority to a severity.
fn severity(priority: &str) -> Option<AppLogSeverity> {
    Some(match priority {
        "0" | "1" | "2" => AppLogSeverity::Critical,
        "3" => AppLogSeverity::Error,
        "4" => AppLogSeverity::Warning,
        "5" | "6" => AppLogSeverity::Info,
        "7" => AppLogSeverity::Debug,
        _ => return None,
    })
}

/// Value of a journal field as printed by `journalctl`.
#[derive(Deserialize)]
#[serde(untagged)]
enum FieldValue {
    /// Value that is valid UTF-8 text.
    Text(String),
    /// Value that is no valid UTF-8 text.
    Binary(Vec<u8>),
    /// Values of a field that the entry has more than once.
    Multiple(Vec<FieldValue>),
    /// Value that `journalctl` omitted, for instance, because of its size.
    Omitted(()),
}

impl FieldValue {
    /// Text of the value, or of its first value if the field occurs more than once.
    fn into_text(self) -> Option<String> {
        match self {
            FieldValue::Text(text) => Some(text),
            FieldValue::Binary(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
            FieldValue::Multiple(values) => values.into_iter().next()?.into_text(),
            FieldValue::Omitted(()) => None,
        }
    }

    /// JSON representation of the value as a string or an array of strings.
    fn into_json(self) -> Option<JsonValue> {
        match self {
            FieldValue::Multiple(values) => Some(JsonValue::from(
                values
                    .into_iter()
                    .filter_map(FieldValue::into_json)
                    .collect::<Vec<_>>(),
            )),
            value => value.into_text().map(JsonValue::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_entry;
    use crate::config::output::AppLogSeverity;

    /// Verifies that entries map to records, including binary messages, repeated
    /// fields, and the generation, and that only fields of the app are kept.
    #[test]
    fn entries_of_the_app_keep_their_fields() {
        let entry = parse_entry(
            br#"{"__REALTIME_TIMESTAMP":"1763374863123456","MESSAGE":[104,105,255],"PRIORITY":"4","SYSLOG_IDENTIFIER":"server","SYSLOG_FACILITY":"3","_PID":"42","RUGIX_APP_GENERATION":"3","REQUEST":["a","b"],"CODE_LINE":"7","LARGE":null}"#,
        )
        .unwrap();
        assert_eq!(
            entry.timestamp.unwrap().to_string(),
            "2025-11-17T10:21:03.123456Z"
        );
        assert_eq!(entry.message, "hi\u{fffd}");
        assert_eq!(entry.severity, Some(AppLogSeverity::Warning));
        assert_eq!(entry.source.as_deref(), Some("server"));
        assert_eq!(entry.generation, Some(3));
        assert_eq!(
            sidex::formats::json::to_string(&entry.fields).unwrap(),
            r#"{"CODE_LINE":"7","REQUEST":["a","b"]}"#
        );
    }

    /// Verifies that systemd's messages about a unit carry no fields.
    #[test]
    fn entries_of_the_service_manager_have_no_fields() {
        let entry = parse_entry(
            br#"{"MESSAGE":"Started app.","_PID":"1","_COMM":"systemd","UNIT":"app.service"}"#,
        )
        .unwrap();
        assert_eq!(entry.source.as_deref(), Some("systemd"));
        assert!(entry.fields.is_empty());
    }
}
