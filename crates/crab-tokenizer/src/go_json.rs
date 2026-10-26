//! A re-implementation of Go's `encoding/json` for the subset of values that
//! reach the tokenizer.
//!
//! This is not "JSON". It is the byte-for-byte output of `json.Marshal`, because
//! the ported code measures that output with `len()` -- the number is a token
//! estimate, so the exact bytes are the contract, not an implementation detail.
//! Three places where a generic JSON serialiser disagrees with Go:
//!
//! * **Map keys are sorted.** Go sorts them by raw byte order, which puts
//!   `"M"` before `"_"` before `"a"` and puts non-ASCII keys last.
//! * **`<`, `>` and `&` are escaped** to `\u003c`, `\u003e`, `\u0026`. Go's
//!   encoder does this by default so its output is safe inside a `<script>` tag;
//!   `serde_json` does not, and the escaped form is three times longer.
//! * **Floats use Go's format rules**, not Rust's: shortest round-trip digits,
//!   positional below 1e21 and at or above 1e-6, exponent form otherwise, and an
//!   exponent that always carries a sign and at least two digits (`1e+21`,
//!   `1e-07`).
//!
//! Values Go refuses to encode -- `NaN`, `±Inf`, and the Go-only kinds that
//! cannot appear in a Rust value at all -- return [`MarshalError`] rather than
//! producing something approximate, because the caller's behaviour on error is to
//! skip the value entirely.

use std::collections::BTreeMap;

/// A value as Go's `map[string]any` can hold it.
///
/// `serde_json::Value` is deliberately not used: it cannot represent `NaN` or an
/// infinity, and those are load-bearing here -- `json.Marshal` fails on them and
/// the caller then ignores the whole enclosing map. `Float` therefore accepts
/// non-finite values and [`Value::Unsupported`] stands for the Go types
/// (`func`, `chan`, `complex`) that a JSON document cannot even express.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    /// Accepts NaN and infinities; both make [`marshal`] fail.
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    /// Sorted by byte order on encode, like Go's `sort.Strings` over map keys.
    Object(BTreeMap<String, Value>),
    /// A value `json.Marshal` refuses on type grounds. The payload is only for
    /// error messages.
    Unsupported(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarshalError(pub String);

/// Deserialises from any JSON document.
///
/// Written by hand rather than derived so integers stay integers: `1` must not
/// become `1.0`, because the two are encoded the same way by Go but only one of
/// them round-trips through a Rust `f64` without changing the byte count of
/// values like `1e15`.
///
/// The reverse direction is not provided on purpose -- [`marshal`] is the
/// serialiser, and `serde_json::to_*` would not agree with it.
impl<'de> serde::Deserialize<'de> for Value {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor;

        impl<'a> serde::de::Visitor<'a> for ValueVisitor {
            type Value = Value;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
                Ok(Value::Int(v))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
                Ok(Value::UInt(v))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
                Ok(Value::Float(v))
            }
            fn visit_str<E>(self, v: &str) -> Result<Value, E> {
                Ok(Value::Str(v.to_owned()))
            }
            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Value, A::Error>
            where
                A: serde::de::SeqAccess<'a>,
            {
                let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Value::Array(items))
            }
            fn visit_map<A>(self, mut map: A) -> Result<Value, A::Error>
            where
                A: serde::de::MapAccess<'a>,
            {
                let mut out = BTreeMap::new();
                while let Some((k, v)) = map.next_entry::<String, Value>()? {
                    out.insert(k, v);
                }
                Ok(Value::Object(out))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

impl std::fmt::Display for MarshalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "json: unsupported value: {}", self.0)
    }
}

impl std::error::Error for MarshalError {}

/// Encodes `value` exactly as `json.Marshal` would.
pub fn marshal(value: &Value) -> Result<Vec<u8>, MarshalError> {
    let mut out = Vec::new();
    encode(value, &mut out)?;
    Ok(out)
}

/// `len(marshal(value)?)` without keeping the bytes.
pub fn encoded_len(value: &Value) -> Result<usize, MarshalError> {
    let mut out = Vec::new();
    encode(value, &mut out)?;
    Ok(out.len())
}

fn encode(value: &Value, out: &mut Vec<u8>) -> Result<(), MarshalError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Int(i) => {
            let mut buf = i.to_string().into_bytes();
            out.append(&mut buf);
        }
        Value::UInt(u) => {
            let mut buf = u.to_string().into_bytes();
            out.append(&mut buf);
        }
        Value::Float(f) => {
            let mut buf = format_go_float(*f)?;
            out.append(&mut buf);
        }
        Value::Str(s) => encode_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // BTreeMap<String, _> iterates in byte order, which is what Go's
            // sort.Strings does over the same keys.
            out.push(b'{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_string(k, out);
                out.push(b':');
                encode(v, out)?;
            }
            out.push(b'}');
        }
        Value::Unsupported(kind) => {
            return Err(MarshalError((*kind).to_string()));
        }
    }
    Ok(())
}

/// Appends `s` as a Go-encoded JSON string.
///
/// Go escapes for two reasons a Rust writer will not match by default: the HTML
/// significant trio, and U+2028/U+2029, which are valid JSON but terminate a
/// JavaScript string literal. Everything else above 0x1f is emitted as raw UTF-8
/// -- Go does not escape non-ASCII.
fn encode_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            // Go has short forms for these two as well. JSON permits them raw,
            // so a writer that only handles the three above is four bytes longer
            // per occurrence.
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '<' => out.extend_from_slice(b"\\u003c"),
            '>' => out.extend_from_slice(b"\\u003e"),
            '&' => out.extend_from_slice(b"\\u0026"),
            '\u{2028}' => out.extend_from_slice(b"\\u2028"),
            '\u{2029}' => out.extend_from_slice(b"\\u2029"),
            c if (c as u32) < 0x20 => {
                let code = c as u32;
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u");
                out.push(b'0');
                out.push(b'0');
                out.push(HEX[((code >> 4) & 0xf) as usize]);
                out.push(HEX[(code & 0xf) as usize]);
            }
            // Everything else is emitted as raw UTF-8: Go does not escape
            // non-ASCII, and neither do we.
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Formats `f` the way `strconv.AppendFloat(b, f, 'f'|'e', -1, 64)` does, with
/// the format chosen the way `encoding/json` chooses it.
fn format_go_float(f: f64) -> Result<Vec<u8>, MarshalError> {
    if f.is_nan() {
        return Err(MarshalError("NaN".into()));
    }
    if f.is_infinite() {
        return Err(MarshalError(if f > 0.0 { "+Inf" } else { "-Inf" }.into()));
    }

    let abs = f.abs();
    // Go: 'e' when the magnitude is outside [1e-6, 1e21), except for zero.
    let use_exponent = abs != 0.0 && (abs < 1e-6 || abs >= 1e21);

    if !use_exponent {
        // Rust's Display for f64 is shortest-round-trip and always positional,
        // which is the same digit string Go's 'f' format with precision -1
        // produces.
        Ok(f.to_string().into_bytes())
    } else {
        // Rust's LowerExp gives the same shortest mantissa but renders the
        // exponent without a sign and without padding: "1e21" where Go writes
        // "1e+21".
        let rust = format!("{f:e}");
        let (mantissa, exponent) = rust.split_once('e').expect("LowerExp always emits 'e'");
        let exp: i32 = exponent.parse().expect("LowerExp emits a decimal exponent");
        let digits = exp.abs().to_string();
        let mut out = mantissa.as_bytes().to_vec();
        out.push(b'e');
        if exp < 0 {
            out.push(b'-');
            // encoding/json post-processes strconv's output to drop a single
            // leading zero from a negative exponent: AppendFloat gives "1e-07"
            // and json.Marshal emits "1e-7". Positive exponents keep the padding
            // ("1e+21"), and three-digit exponents are untouched ("5e-324"), so
            // this strip is exactly one character and only in this branch.
            out.extend_from_slice(strip_leading_zero(&digits).as_bytes());
        } else {
            out.push(b'+');
            if digits.len() < 2 {
                out.push(b'0');
            }
            out.extend_from_slice(digits.as_bytes());
        }
        Ok(out)
    }
}

/// Drops one leading `0` from a decimal exponent, the way `encoding/json`'s
/// `appendFloat` does ("e-07" becomes "e-7", "e-324" stays). strconv always
/// emits at least two exponent digits, so the guard is really "the first digit
/// is a zero".
fn strip_leading_zero(digits: &str) -> &str {
    if digits.len() >= 2 && digits.starts_with('0') {
        &digits[1..]
    } else {
        digits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(pairs: &[(&str, Value)]) -> Value {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), v.clone());
        }
        Value::Object(m)
    }

    fn round(v: &Value) -> String {
        String::from_utf8(marshal(v).unwrap()).unwrap()
    }

    #[test]
    fn keys_are_sorted_by_byte() {
        // Go's sort.Strings is a byte comparison: 'M' (0x4d) < '_' (0x5f) <
        // 'a' (0x61) < 'z' (0x7a) < any non-ASCII lead byte.
        assert_eq!(
            round(&obj(&[
                ("z", Value::UInt(1)),
                ("a", Value::UInt(2)),
                ("M", Value::UInt(3)),
                ("0", Value::UInt(4)),
                ("\u{884c}", Value::UInt(5)),
                ("_", Value::UInt(6)),
            ])),
            r#"{"0":4,"M":3,"_":6,"a":2,"z":1,"行":5}"#
        );
    }

    #[test]
    fn html_trio_is_escaped_in_values_and_keys() {
        assert_eq!(
            round(&obj(&[("a<b>&", Value::Str("x<y>&z".into()))])),
            r#"{"a\u003cb\u003e\u0026":"x\u003cy\u003e\u0026z"}"#
        );
    }

    #[test]
    fn non_ascii_is_not_escaped_but_line_separators_are() {
        assert_eq!(
            round(&Value::Str("行🦐\u{2028}\u{2029}".into())),
            r#""行🦐\u2028\u2029""#
        );
    }

    #[test]
    fn control_characters_use_go_escapes() {
        // Go has short forms for \n \r \t \b \f and writes the rest as
        // \u00XX with lower-case hex -- including \v, which JSON permits raw.
        assert_eq!(
            round(&Value::Str("\u{00}\u{08}\u{0b}\u{0c}\u{1f}\n\r\t".into())),
            r#""\u0000\b\u000b\f\u001f\n\r\t""#
        );
    }

    #[test]
    fn floats_follow_go_format_boundaries() {
        let cases = [
            (1.0f64, "1"),
            (0.5, "0.5"),
            (-0.0, "-0"),
            (1.0 / 3.0, "0.3333333333333333"),
            (1e-6, "0.000001"),
            (9.999e-7, "9.999e-7"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1e-7, "1e-7"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (1_234_567_890_123_456_789.0, "1234567890123456800"),
            (1e15, "1000000000000000"),
            (1e16, "10000000000000000"),
        ];
        for (input, want) in cases {
            assert_eq!(round(&Value::Float(input)), want, "for {input}");
        }
    }

    #[test]
    fn non_finite_floats_are_refused() {
        for v in [
            Value::Float(f64::NAN),
            Value::Float(f64::INFINITY),
            Value::Float(f64::NEG_INFINITY),
            Value::Unsupported("complex128"),
        ] {
            assert!(marshal(&v).is_err(), "{v:?} should not marshal");
        }
    }

    #[test]
    fn a_failure_anywhere_in_the_tree_fails_the_whole_call() {
        // The caller counts zero bytes for the entire map in this case, not the
        // bytes it managed to produce before the bad field.
        let deep = obj(&[
            ("ok", Value::Str("yes".into())),
            ("bad", Value::Array(vec![Value::Float(f64::NAN)])),
        ]);
        assert!(marshal(&deep).is_err());
    }

    #[test]
    fn containers_encode_without_whitespace() {
        assert_eq!(round(&Value::Array(vec![])), "[]");
        assert_eq!(round(&obj(&[])), "{}");
        assert_eq!(
            round(&Value::Array(vec![
                Value::UInt(1),
                Value::Str("two".into()),
                Value::Null,
                Value::Bool(true),
            ])),
            r#"[1,"two",null,true]"#
        );
    }
}
