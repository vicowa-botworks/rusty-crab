//! Turns a fixture's JSON into the value model Go's `map[string]any` holds.
//!
//! Lives in the harness rather than in `crab-gojson` because it knows two things
//! that are conventions of the fixtures, not of Go:
//!
//! * the `$go_marshal_error` marker, and
//! * that a JSON number in a fixture has lost the int/float distinction the Go
//!   value had.

use std::collections::BTreeMap;

use crab_gojson::Value as GoValue;
use serde_json::Value;

/// The marker `cmd/oracle` writes for a value Go's `json.Marshal` refuses. It
/// cannot be represented in JSON, and the estimator's behaviour on it -- skip the
/// whole enclosing map -- is not the same as encoding the fields that were fine.
pub const MARSHAL_ERROR: &str = "$go_marshal_error";

pub fn to_go_value(v: &Value) -> GoValue {
    match v {
        Value::Null => GoValue::Null,
        Value::Bool(b) => GoValue::Bool(*b),
        Value::String(s) => GoValue::Str(s.clone()),
        Value::Number(n) => go_number(n),
        Value::Array(items) => GoValue::Array(items.iter().map(to_go_value).collect()),
        Value::Object(map) => {
            if let Some(kind) = marshal_error_marker(map) {
                return GoValue::Unsupported(kind);
            }
            let mut out = BTreeMap::new();
            for (k, val) in map {
                out.insert(k.clone(), to_go_value(val));
            }
            GoValue::Object(out)
        }
    }
}

/// A JSON number that came from Go is either an integer kind or a float, and the
/// fixture cannot tell them apart -- Go writes `float64(7)` as `7`, exactly as it
/// writes `int(7)`. That is harmless for every value except negative zero: Go
/// writes `float64(-0.0)` as `-0`, which JSON parses back to the integer `0`, and
/// `0` encodes to one byte instead of two.
///
/// Floats go through [`serde_json::Number::as_f64`], which is only correctly
/// rounded because the workspace enables serde_json's `arbitrary_precision`
/// feature. Without it serde_json accumulates decimal digits straight into an
/// `f64`, which lands one ULP away from the correct value on some
/// shortest-round-trip literals: with the feature off this suite reported 27
/// encoder mismatches across 676 encoded parameter values, every one of them the
/// harness mis-parsing the fixture rather than the port encoding wrongly. Any code
/// here that turns provider JSON into an `f64` needs the same feature, or it will
/// disagree with Go about which number it has.
pub fn go_number(n: &serde_json::Number) -> GoValue {
    if n.to_string() == "-0" {
        return GoValue::Float(-0.0);
    }
    if let Some(i) = n.as_i64() {
        return GoValue::Int(i);
    }
    if let Some(u) = n.as_u64() {
        return GoValue::UInt(u);
    }
    GoValue::Float(n.as_f64().expect("a JSON number is representable as f64"))
}

fn marshal_error_marker(map: &serde_json::Map<String, Value>) -> Option<&'static str> {
    if map.len() != 1 {
        return None;
    }
    match map.get(MARSHAL_ERROR) {
        Some(Value::String(kind)) => Some(leak(kind)),
        _ => None,
    }
}

/// [`crab_gojson::Value::Unsupported`] carries a `&'static str` so the value type
/// stays cheap to clone; fixture strings live for the whole test run anyway.
fn leak(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}
