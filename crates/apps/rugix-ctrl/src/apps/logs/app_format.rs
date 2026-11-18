//! Interpretation of the lines that a workload writes, according to the log format
//! declared in its app manifest.

use rugix_bundle::manifest::AppLogFormat;
use sidex::types::JsonValue;
use sidex::types::Map;
use sidex::types::Str;

use crate::config::output::AppLogRecord;
use crate::config::output::AppLogSeverity;

/// Keys of JSON log lines holding the message, in order of precedence.
const MESSAGE_KEYS: &[&str] = &["msg", "message"];

/// Keys of JSON log lines holding the severity, in order of precedence.
const SEVERITY_KEYS: &[&str] = &["level", "severity", "lvl"];

/// Interpret the message of a record written by the workload.
///
/// With the JSON format, a message that is a JSON object becomes a structured record.
/// Its message and severity come from the keys listed above, and its other keys become
/// fields of the record. Other messages stay plain text.
pub(crate) fn apply(format: &AppLogFormat, record: &mut AppLogRecord) {
    match format {
        AppLogFormat::Text => {}
        AppLogFormat::Json => {
            let Ok(JsonValue::Map(mut object)) =
                sidex::formats::json::from_str::<JsonValue>(&record.message)
            else {
                return;
            };
            record.message =
                take_first_field(&mut object, MESSAGE_KEYS, |message| Some(message.clone()))
                    .unwrap_or_default();
            if let Some(severity) =
                take_first_field(&mut object, SEVERITY_KEYS, |level| severity(level))
            {
                record.severity = Some(severity);
            }
            if !object.is_empty() {
                let mut fields = record.fields.take().unwrap_or_default();
                for (key, value) in object.iter() {
                    fields.insert(key.clone(), value.clone());
                }
                record.fields = Some(fields);
            }
        }
    }
}

/// Remove the first of `keys` whose string value `interpret` accepts and return the
/// interpretation.
fn take_first_field<T>(
    object: &mut Map<Str, JsonValue>,
    keys: &[&str],
    interpret: impl Fn(&Str) -> Option<T>,
) -> Option<T> {
    let (key, value) = keys.iter().find_map(|key| match object.get(*key) {
        Some(JsonValue::String(value)) => Some((*key, interpret(value)?)),
        _ => None,
    })?;
    object.remove(key);
    Some(value)
}

/// Map a level name of a logging library to a severity.
fn severity(level: &str) -> Option<AppLogSeverity> {
    Some(match level.to_ascii_lowercase().as_str() {
        "trace" => AppLogSeverity::Trace,
        "debug" => AppLogSeverity::Debug,
        "info" | "notice" => AppLogSeverity::Info,
        "warn" | "warning" => AppLogSeverity::Warning,
        "error" | "err" => AppLogSeverity::Error,
        "critical" | "crit" | "fatal" | "panic" | "alert" | "emerg" | "emergency" => {
            AppLogSeverity::Critical
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use rugix_bundle::manifest::AppLogFormat;

    use super::apply;
    use crate::config::output::AppLogRecord;
    use crate::config::output::AppLogSeverity;

    fn interpret(message: &str) -> AppLogRecord {
        let mut record = AppLogRecord::new(message);
        apply(&AppLogFormat::Json, &mut record);
        record
    }

    /// Verifies that JSON objects become structured records, that keys with values
    /// that are no message or known level stay fields, and that other JSON values
    /// stay plain text.
    #[test]
    fn json_objects_become_structured_records() {
        let record = interpret(r#"{"level":"WARN","msg":"disk almost full","free":3,"message":7}"#);
        assert_eq!(&*record.message, "disk almost full");
        assert_eq!(record.severity, Some(AppLogSeverity::Warning));
        assert_eq!(
            sidex::formats::json::to_string(record.fields.as_ref().unwrap()).unwrap(),
            r#"{"free":3,"message":7}"#
        );

        let record = interpret(r#"{"level":"verbose"}"#);
        assert_eq!(&*record.message, "");
        assert_eq!(record.severity, None);
        assert!(record.fields.unwrap().contains_key("level"));

        let record = interpret("[1, 2]");
        assert_eq!(&*record.message, "[1, 2]");
        assert!(record.fields.is_none());
    }
}
