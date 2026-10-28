//! Go's `json.Unmarshal`, for the wire types that come back off disk.
//!
//! The marshal side lives in [`crate`]; this is the direction a session file is
//! read. It is a separate module rather than a `serde` `Deserialize` derive
//! because the two disagree in ways that decide whether a user's history loads:
//!
//! * **A field name matches case-insensitively.** `encoding/json` takes an exact
//!   tag match first and falls back to a case-folded one, so a file written by an
//!   older or hand-edited tool with `"Role"` still populates [`Message::role`].
//!   `serde` refuses it.
//! * **`null` into a value is a no-op, not an error.** `"role": null` leaves the
//!   empty string and the line still counts as read; `serde` calls it invalid
//!   type. A store that treats it as corruption silently drops a message Go keeps.
//! * **One bad field corrupts the whole line.** Go returns an error for the value,
//!   and `pkg/memory`'s reader logs and skips the line -- so a wrong type is not
//!   "that field is missing", it is "that message never existed".
//! * **Unknown fields are ignored**, which is what lets a file written by a newer
//!   release still load.
//!
//! The error text follows Go's shape because it reaches the log line
//! `memory: skipping corrupt line %d in %s: %v`, but the conformance corpus
//! records only *which* op failed, so the wording is for operators, not for the
//! fixture.

use crate::{
    Attachment, CacheControl, ContentBlock, ExtraContent, FunctionCall, GoTime, GoogleExtra,
    Message, ToolCall,
};
use serde_json::Value;
use std::fmt;

/// A value that could not be decoded into the Go type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DecodeError {}

/// Decodes one JSONL line into a [`Message`].
///
/// # Errors
///
/// [`DecodeError`] when the bytes are not one JSON object, or when any field has
/// a type the Go struct cannot hold. Both make `pkg/memory` skip the line.
pub fn message(src: &[u8]) -> Result<Message, DecodeError> {
    let raw: Value = serde_json::from_slice(src)
        .map_err(|e| DecodeError(format!("invalid character decoding JSON: {e}")))?;
    // `null` unmarshals into a zeroed struct without error, so a line of `null`
    // reads as an empty message rather than a corrupt one.
    if raw.is_null() {
        return Ok(Message::default());
    }
    let obj = expect_object(&raw, "protocoltypes.Message")?;
    let mut m = Message::default();
    for (key, val) in obj {
        // Every wire tag on these types is lower-case, so folding the incoming
        // name is equivalent to Go's "exact match, then case-folded match". A
        // `json:"-"` field folds to a name that is not in this list, so the file
        // can carry `name` or `arguments` and they change nothing, as in Go.
        match Field::of(key) {
            Field::Role => m.role = string(val, "Message.role")?,
            Field::Content => m.content = string(val, "Message.content")?,
            Field::ModelName => m.model_name = string(val, "Message.model_name")?,
            Field::CreatedAt => m.created_at = time(val, "Message.created_at")?,
            Field::Media => m.media = opt_string_slice(val, "Message.media")?,
            Field::Attachments => {
                m.attachments = opt_struct_slice(val, "Message.attachments", attachment)?;
            }
            Field::ReasoningContent => {
                m.reasoning_content = string(val, "Message.reasoning_content")?;
            }
            Field::SystemParts => {
                m.system_parts = opt_struct_slice(val, "Message.system_parts", content_block)?;
            }
            Field::ToolCalls => {
                m.tool_calls = opt_struct_slice(val, "Message.tool_calls", tool_call)?;
            }
            Field::ToolCallID => m.tool_call_id = string(val, "Message.tool_call_id")?,
            Field::Unknown => {}
        }
    }
    Ok(m)
}

/// The wire fields of [`Message`], resolved the way `encoding/json` resolves a
/// name: case-folded, with anything unrecognized skipped.
enum Field {
    Role,
    Content,
    ModelName,
    CreatedAt,
    Media,
    Attachments,
    ReasoningContent,
    SystemParts,
    ToolCalls,
    ToolCallID,
    Unknown,
}

impl Field {
    fn of(key: &str) -> Self {
        // `to_ascii_lowercase` rather than `to_lowercase`: Go folds ASCII case in
        // the decoder, and a non-ASCII name cannot match a tag anyway.
        match key.to_ascii_lowercase().as_str() {
            "role" => Field::Role,
            "content" => Field::Content,
            "model_name" => Field::ModelName,
            "created_at" => Field::CreatedAt,
            "media" => Field::Media,
            "attachments" => Field::Attachments,
            "reasoning_content" => Field::ReasoningContent,
            "system_parts" => Field::SystemParts,
            "tool_calls" => Field::ToolCalls,
            "tool_call_id" => Field::ToolCallID,
            _ => Field::Unknown,
        }
    }
}

fn expect_object<'a>(
    v: &'a Value,
    go_type: &str,
) -> Result<&'a serde_json::Map<String, Value>, DecodeError> {
    match v {
        Value::Object(map) => Ok(map),
        other => Err(DecodeError(format!(
            "json: cannot unmarshal {} into Go value of type {go_type}",
            kind(other)
        ))),
    }
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// A `string` field. `null` leaves the zero value; anything else must be a string.
fn string(v: &Value, go_field: &str) -> Result<String, DecodeError> {
    match v {
        Value::Null => Ok(String::new()),
        Value::String(s) => Ok(s.clone()),
        other => Err(DecodeError(format!(
            "json: cannot unmarshal {} into Go struct field {go_field} of type string",
            kind(other)
        ))),
    }
}

/// A `[]string` field: nil for `null`, otherwise every element decoded.
fn opt_string_slice(v: &Value, go_field: &str) -> Result<Option<Vec<String>>, DecodeError> {
    match v {
        Value::Null => Ok(None),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(string(item, go_field)?);
            }
            Ok(Some(out))
        }
        other => Err(DecodeError(format!(
            "json: cannot unmarshal {} into Go struct field {go_field} of type []string",
            kind(other)
        ))),
    }
}

/// A `[]T` field for a struct element type.
fn opt_struct_slice<T>(
    v: &Value,
    go_field: &str,
    each: impl Fn(&Value) -> Result<T, DecodeError>,
) -> Result<Option<Vec<T>>, DecodeError> {
    match v {
        Value::Null => Ok(None),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(each(item)?);
            }
            Ok(Some(out))
        }
        other => Err(DecodeError(format!(
            "json: cannot unmarshal {} into Go struct field {go_field} of type slice",
            kind(other)
        ))),
    }
}

/// One struct field: `null` leaves it nil, an object decodes it.
fn opt_struct<T>(
    v: &Value,
    each: impl Fn(&Value) -> Result<T, DecodeError>,
) -> Result<Option<T>, DecodeError> {
    match v {
        Value::Null => Ok(None),
        _ => each(v).map(Some),
    }
}

fn sub_object<'a>(
    v: &'a Value,
    go_type: &str,
) -> Result<&'a serde_json::Map<String, Value>, DecodeError> {
    expect_object(v, go_type)
}

fn attachment(v: &Value) -> Result<Attachment, DecodeError> {
    let obj = sub_object(v, "protocoltypes.Attachment")?;
    let mut a = Attachment::default();
    for (key, val) in obj {
        match key.as_str() {
            "type" => a.attachment_type = string(val, "Attachment.type")?,
            "ref" => a.ref_ = string(val, "Attachment.ref")?,
            "url" => a.url = string(val, "Attachment.url")?,
            "filename" => a.filename = string(val, "Attachment.filename")?,
            "content_type" => a.content_type = string(val, "Attachment.content_type")?,
            _ => {}
        }
    }
    Ok(a)
}

fn content_block(v: &Value) -> Result<ContentBlock, DecodeError> {
    let obj = sub_object(v, "protocoltypes.ContentBlock")?;
    let mut b = ContentBlock::default();
    for (key, val) in obj {
        match key.as_str() {
            "type" => b.block_type = string(val, "ContentBlock.type")?,
            "text" => b.text = string(val, "ContentBlock.text")?,
            "cache_control" => {
                b.cache_control = opt_struct(val, |v| {
                    let obj = sub_object(v, "protocoltypes.CacheControl")?;
                    let mut c = CacheControl::default();
                    for (k, val) in obj {
                        if k == "type" {
                            c.control_type = string(val, "CacheControl.type")?;
                        }
                    }
                    Ok(c)
                })?;
            }
            _ => {}
        }
    }
    Ok(b)
}

fn tool_call(v: &Value) -> Result<ToolCall, DecodeError> {
    let obj = sub_object(v, "protocoltypes.ToolCall")?;
    let mut t = ToolCall::default();
    for (key, val) in obj {
        match key.as_str() {
            "id" => t.id = string(val, "ToolCall.id")?,
            "type" => t.call_type = string(val, "ToolCall.type")?,
            "function" => {
                t.function = opt_struct(val, |v| {
                    let obj = sub_object(v, "protocoltypes.FunctionCall")?;
                    let mut f = FunctionCall::default();
                    for (k, val) in obj {
                        match k.as_str() {
                            "name" => f.name = string(val, "FunctionCall.name")?,
                            "arguments" => f.arguments = string(val, "FunctionCall.arguments")?,
                            "thought_signature" => {
                                f.thought_signature = string(val, "FunctionCall.thought_signature")?
                            }
                            _ => {}
                        }
                    }
                    Ok(f)
                })?;
            }
            "extra_content" => {
                t.extra_content = opt_struct(val, |v| {
                    let obj = sub_object(v, "protocoltypes.ExtraContent")?;
                    let mut e = ExtraContent::default();
                    for (k, val) in obj {
                        match k.as_str() {
                            "google" => {
                                e.google = opt_struct(val, |v| {
                                    let obj = sub_object(v, "protocoltypes.GoogleExtra")?;
                                    let mut g = GoogleExtra::default();
                                    for (k, val) in obj {
                                        if k == "thought_signature" {
                                            g.thought_signature =
                                                string(val, "GoogleExtra.thought_signature")?;
                                        }
                                    }
                                    Ok(g)
                                })?;
                            }
                            "tool_feedback_explanation" => {
                                e.tool_feedback_explanation =
                                    string(val, "ExtraContent.tool_feedback_explanation")?
                            }
                            _ => {}
                        }
                    }
                    Ok(e)
                })?;
            }
            // name, arguments and thought_signature are json:"-": Go never reads
            // them, so a file that carries them changes nothing.
            _ => {}
        }
    }
    Ok(t)
}

/// A `time.Time` field, i.e. an RFC3339Nano string.
fn time(v: &Value, go_field: &str) -> Result<Option<GoTime>, DecodeError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => match parse_rfc3339_nano(s) {
            Some(t) => Ok(Some(t)),
            None => Err(DecodeError(format!(
                "parsing time \"{s}\" as \"2006-01-02T15:04:05Z07:00\": cannot parse"
            ))),
        },
        other => Err(DecodeError(format!(
            "json: cannot unmarshal {} into Go struct field {go_field} of type time.Time",
            kind(other)
        ))),
    }
}

/// Go's `time.Parse(time.RFC3339Nano, s)`.
///
/// Returns the instant as seconds plus the nanosecond remainder plus the zone's
/// offset in seconds, which is all [`GoTime`] keeps and all `MarshalJSON` writes
/// back. The offset is preserved rather than normalized to UTC because a session
/// file stamped `+05:30` has to marshal out as `+05:30`.
///
/// Fractional seconds are positional, not "read the digits as an integer": `.25`
/// is 250 ms, and Go accepts between one and nine digits. The layout's `.` also
/// matches a `,`, which Go's `nextStdChunk` allows.
#[must_use]
pub fn parse_rfc3339_nano(s: &str) -> Option<GoTime> {
    let bytes = s.as_bytes();
    // `2006-01-02T15:04:05Z` is 20 bytes, and that is the shortest legal input:
    // the zone is mandatory in this layout.
    if bytes.len() < 20 {
        return None;
    }
    let digit = |i: usize| bytes[i].is_ascii_digit();
    if !(digit(0)
        && digit(1)
        && digit(2)
        && digit(3)
        && bytes[4] == b'-'
        && digit(5)
        && digit(6)
        && bytes[7] == b'-'
        && digit(8)
        && digit(9))
    {
        return None;
    }
    // The layout says `T`; Go's parser accepts any single byte as the date/time
    // separator, and `time.RFC3339Nano` is only ever handed `T`.
    if bytes[10] != b'T' && bytes[10] != b't' {
        return None;
    }
    if !(digit(11)
        && digit(12)
        && bytes[13] == b':'
        && digit(14)
        && digit(15)
        && bytes[16] == b':'
        && digit(17)
        && digit(18))
    {
        return None;
    }
    let (year, month, day) = (number(s, 0, 4)?, number(s, 5, 7)?, number(s, 8, 10)?);
    let (hour, minute, sec) = (number(s, 11, 13)?, number(s, 14, 16)?, number(s, 17, 19)?);
    if !(1..=12).contains(&month) || !(0..=23).contains(&hour) || minute > 59 {
        return None;
    }
    if day < 1 || day > days_in_month(year, month) {
        return None;
    }
    if sec > 60 {
        // Go accepts the leap second as :60.
        return None;
    }
    let mut rest = &s[19..];

    let mut nanos: u32 = 0;
    if rest.starts_with('.') || rest.starts_with(',') {
        // The layout's `.` matches a `,` too, which is why both are accepted.
        let digits: usize = rest[1..].bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || digits > 9 {
            return None;
        }
        // Positional, not "read the digits as an integer": `.25` is 250 ms, so the
        // run is padded out to nine places before it is read.
        let mut padded = rest[1..1 + digits].to_string();
        while padded.len() < 9 {
            padded.push('0');
        }
        nanos = padded.parse().ok()?;
        rest = &rest[1 + digits..];
    }

    let offset = parse_zone_offset(rest)?;
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + sec
        - i64::from(offset);
    Some(GoTime {
        unix_seconds: seconds,
        nanos,
        offset_seconds: offset,
    })
}

/// `+hh:mm` / `-hh:mm` / `Z`. The name is not part of the value: Go's
/// `MarshalJSON` writes the offset and never the zone name.
fn parse_zone_offset(rest: &str) -> Option<i32> {
    if rest == "Z" || rest == "z" {
        return Some(0);
    }
    let bytes = rest.as_bytes();
    if bytes.len() != 6 || !matches!(bytes[0], b'+' | b'-') {
        return None;
    }
    if !(bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && bytes[3] == b':'
        && bytes[4].is_ascii_digit()
        && bytes[5].is_ascii_digit())
    {
        return None;
    }
    let hours: i32 = rest[1..3].parse().ok()?;
    let minutes: i32 = rest[4..6].parse().ok()?;
    // 24 and 60, not 23 and 59. Go's fast RFC 3339 scanner is stricter than its
    // general layout parser, and a string the scanner refuses falls through to
    // the general one, whose range test is deliberately `> 24` / `> 60`: "some
    // people do write offsets of 24 hours or 60 minutes". So `+24:00` and
    // `+23:60` *parse* -- and then `MarshalJSON` refuses them, because the hour
    // it prints back is 24. A port that validates the offset on the way in
    // refuses a session file the Go store reads; one that validates it nowhere
    // writes a stamp it can never read back. Both halves are pinned:
    // `compact_with_unwritable_meta_leaves_the_file_alone` here, and the
    // refusal in `format_rfc3339_nano`.
    if hours > 24 || minutes > 60 {
        return None;
    }
    let sign = if bytes[0] == b'+' { 1 } else { -1 };
    Some(sign * (hours * 3600 + minutes * 60))
}

/// Two or four ASCII digits as a number, refusing anything else in the span.
fn number(s: &str, from: usize, to: usize) -> Option<i64> {
    let span = s.get(from..to)?;
    if span.is_empty() || !span.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    span.parse().ok()
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(y) => 29,
        _ => 28,
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format_rfc3339_nano;

    fn msg(s: &str) -> Result<Message, DecodeError> {
        message(s.as_bytes())
    }

    #[test]
    fn a_plain_line_reads_back() {
        let m = msg(r#"{"role":"user","content":"hi","created_at":"2023-11-14T22:13:20.25Z"}"#)
            .unwrap();
        assert_eq!(m.role, "user");
        assert_eq!(m.content, "hi");
        assert_eq!(
            m.created_at,
            Some(GoTime {
                unix_seconds: 1_700_000_000,
                nanos: 250_000_000,
                offset_seconds: 0
            })
        );
        // Absent slices stay nil, which is what keeps `omitempty` silent.
        assert_eq!(m.media, None);
        assert_eq!(m.tool_calls, None);
    }

    #[test]
    fn null_is_a_no_op_and_unknown_fields_are_ignored() {
        let m = msg(r#"{"role":null,"content":"x","bogus":[1,2],"extra":{"deep":true}}"#).unwrap();
        assert_eq!(m.role, "");
        assert_eq!(m.content, "x");
    }

    #[test]
    fn a_field_name_matches_ignoring_case() {
        let m = msg(r#"{"Role":"user","CONTENT":"x"}"#).unwrap();
        assert_eq!(m.role, "user");
        assert_eq!(m.content, "x");
    }

    #[test]
    fn the_wrong_type_corrupts_the_line() {
        for bad in [
            "[1,2,3]",
            "5",
            "\"a string\"",
            "true",
            r#"{"role":5}"#,
            r#"{"media":"not an array"}"#,
            r#"{"media":[5]}"#,
            r#"{"created_at":"yesterday"}"#,
            r#"{"created_at":1700000000}"#,
            r#"{"tool_calls":{"id":"x"}}"#,
            "{",
            r#"{"role":"user",}"#,
        ] {
            assert!(msg(bad).is_err(), "decoded a corrupt line: {bad}");
        }
        // `null` alone is a zeroed value, not an error.
        assert_eq!(msg("null").unwrap(), Message::default());
    }

    #[test]
    fn nested_structs_decode() {
        let m = msg(
            r#"{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{}"},"extra_content":{"google":{"thought_signature":"sig"}}}],"attachments":[{"type":"image","ref":"r","url":"u","filename":"f.png","content_type":"image/png"}],"system_parts":[{"type":"text","text":"t","cache_control":{"type":"ephemeral"}}]}"#,
        )
        .unwrap();
        let calls = m.tool_calls.as_ref().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "c1");
        assert_eq!(calls[0].function.as_ref().unwrap().name, "f");
        assert_eq!(
            calls[0]
                .extra_content
                .as_ref()
                .unwrap()
                .google
                .as_ref()
                .unwrap()
                .thought_signature,
            "sig"
        );
        assert_eq!(m.attachments.as_ref().unwrap()[0].filename, "f.png");
        assert_eq!(
            m.system_parts.as_ref().unwrap()[0]
                .cache_control
                .as_ref()
                .unwrap()
                .control_type,
            "ephemeral"
        );
    }

    #[test]
    fn timestamps_keep_their_offset_and_fraction() {
        let t = parse_rfc3339_nano("2023-11-14T22:13:20.25+05:30").unwrap();
        assert_eq!(t.nanos, 250_000_000);
        assert_eq!(t.offset_seconds, 5 * 3600 + 30 * 60);
        // The instant is the wall clock minus the offset.
        assert_eq!(
            t.unix_seconds,
            parse_rfc3339_nano("2023-11-14T16:43:20.25Z")
                .unwrap()
                .unix_seconds
        );
        assert_eq!(parse_rfc3339_nano("2023-11-14T22:13:21Z").unwrap().nanos, 0);
        assert_eq!(
            parse_rfc3339_nano("2023-11-14T22:13:20,5Z").unwrap().nanos,
            500_000_000
        );
        assert_eq!(
            parse_rfc3339_nano("2023-11-14T22:13:20.123456789Z")
                .unwrap()
                .nanos,
            123_456_789
        );
    }

    #[test]
    fn an_out_of_range_offset_loads_and_then_refuses_to_marshal() {
        // Go's general layout parser, which the strict RFC 3339 scanner falls
        // through to, allows hour 24 and minute 60: "some people do write offsets
        // of 24 hours or 60 minutes". MarshalJSON then refuses what it printed.
        // Both halves have to move together -- refusing the parse would drop a
        // session file the Go store loads, and marshalling the value would write
        // a stamp nothing can read back.
        for ok in [
            "2023-11-14T22:13:20+24:00",
            "2023-11-14T22:13:20-24:00",
            "2023-11-14T22:13:20+23:60",
            "2023-11-14T22:13:20-23:60",
            "2023-11-14T22:13:20+24:60",
        ] {
            let t = parse_rfc3339_nano(ok).unwrap_or_else(|| panic!("refused {ok:?}"));
            let err = format_rfc3339_nano(t.unix_seconds, t.nanos, t.offset_seconds)
                .expect_err("MarshalJSON must refuse an offset it cannot print");
            assert!(err.to_string().contains("timezone hour"), "{ok}: {err}");
        }
        // One hour further and Go's parser itself refuses, so the value never
        // exists to be marshalled.
        for bad in [
            "2023-11-14T22:13:20+25:00",
            "2023-11-14T22:13:20-99:00",
            "2023-11-14T22:13:20+24:61",
        ] {
            assert!(parse_rfc3339_nano(bad).is_none(), "parsed {bad:?}");
        }
        // The boundary that is not a boundary: 23:59 is the largest offset that
        // survives a round trip.
        let t = parse_rfc3339_nano("2023-11-14T22:13:20-23:59").unwrap();
        assert_eq!(
            format_rfc3339_nano(t.unix_seconds, t.nanos, t.offset_seconds).unwrap(),
            "2023-11-14T22:13:20-23:59"
        );
    }

    #[test]
    fn impossible_instants_are_refused() {
        for bad in [
            "",
            "2023-11-14T22:13:20",
            "2023-13-01T00:00:00Z",
            "2023-02-30T00:00:00Z",
            "2023-11-14T25:00:00Z",
            "2023-11-14T22:60:00Z",
            "2023-11-14T22:13:20.1234567890Z",
            "2023-11-14T22:13:20+0500",
            "2023-11-14T22:13:20.Z",
            "not a time",
        ] {
            assert!(parse_rfc3339_nano(bad).is_none(), "parsed {bad:?}");
        }
        // 2024 is a leap year and 2100 is not.
        assert!(parse_rfc3339_nano("2024-02-29T00:00:00Z").is_some());
        assert!(parse_rfc3339_nano("2100-02-29T00:00:00Z").is_none());
    }
}
