//! An ordered JSON document.
//!
//! The config file is written by `encoding/json` from a **struct**, so its keys come
//! out in declaration order. That is a byte-level contract: a document with the same
//! data and a different key order is equal as data and wrong as a file, and the
//! fixture compares files.
//!
//! `serde_json::Map` cannot hold that. Its default backing is a `BTreeMap`, which
//! sorts -- so the first version of this crate read Go's default table and wrote back
//! `agents, build_info, channel_list, ...` where Go writes
//! `session, version, isolation, agents, ...`. The crate's own shape test caught it,
//! which is the only reason it is a comment instead of a shipped bug.
//!
//! The obvious fix is serde_json's `preserve_order` feature, and it is rejected on
//! purpose: features unify across the workspace, so turning it on here would also
//! change `crab-memory`, where sorted map keys are the *behaviour under test* -- Go
//! sorts `map` keys on encode, and the memory fixture pins that. A type is cheaper
//! than a cross-crate behaviour change, and it is the honest description of what a
//! config document is: an ordered mapping, not a map.

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// A JSON value that remembers the order its object keys arrived in.
#[derive(Debug, Clone, PartialEq)]
pub enum Doc {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Array(Vec<Doc>),
    /// Declaration order, with lookup by name.
    Object(Vec<(String, Doc)>),
}

/// A parsed document, plus the reason it could not be parsed.
///
/// The wrapper exists because the corpus distinguishes an empty file (a syntax error)
/// from `{}` two bytes away (defaults), and a `Result` would carry the fact while
/// losing the position Go reports.
#[derive(Debug, Clone)]
pub struct Parsed {
    /// The document, or [`Doc::Null`] when `error` is set.
    pub doc: Doc,
    /// Go's diagnostic for a failure, already in Go's sentence shape.
    pub error: Option<String>,
}

impl Parsed {
    /// The document, ignoring any error. Only sound for a document known to be valid,
    /// which is what the embedded tables are and what a test fixture is.
    #[must_use]
    pub fn into_doc(self) -> Doc {
        self.doc
    }
}

impl Default for Doc {
    /// The absent value: a document that says nothing.
    fn default() -> Self {
        Self::Null
    }
}

impl Doc {
    /// Looks a key up in an object.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Doc> {
        match self {
            Self::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Looks a key up, following a path of one segment per level.
    #[must_use]
    pub fn path(&self, path: &[&str]) -> Option<&Doc> {
        let mut cur = self;
        for segment in path {
            cur = cur.get(segment)?;
        }
        Some(cur)
    }

    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&Vec<Doc>> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_object(&self) -> Option<&Vec<(String, Doc)>> {
        match self {
            Self::Object(entries) => Some(entries),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    /// The object entry under `key`, for in-place editing.
    #[must_use]
    pub fn get_mut_at(&mut self, key: &str) -> Option<&mut Doc> {
        match self {
            Self::Object(entries) => entries.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The object's entries, for reordering.
    #[must_use]
    pub fn as_object_mut(&mut self) -> Option<&mut Vec<(String, Doc)>> {
        match self {
            Self::Object(entries) => Some(entries),
            _ => None,
        }
    }

    /// The array's elements, for in-place editing.
    #[must_use]
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Doc>> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    /// Replaces a key's value, appending it when the key is absent.
    ///
    /// Appending is the only option that keeps the rest of the document's order
    /// intact, and it matches what a Go decode into a map does: a key that was not
    /// there goes at the end of the map iteration order, which for a re-marshal of a
    /// `map[string]any` is then sorted anyway.
    pub fn set(&mut self, key: &str, value: Doc) {
        if let Self::Object(entries) = self {
            if let Some(slot) = entries.iter_mut().find(|(k, _)| k == key) {
                slot.1 = value;
                return;
            }
            entries.push((key.to_string(), value));
        }
    }

    /// Removes a key and returns what was there.
    pub fn remove(&mut self, key: &str) -> Option<Doc> {
        match self {
            Self::Object(entries) => entries
                .iter()
                .position(|(k, _)| k == key)
                .map(|i| entries.remove(i).1),
            _ => None,
        }
    }

    /// The document as Go's `json.Marshal` would write it: compact, HTML-escaped.
    #[must_use]
    pub fn to_compact_json(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    /// The document as Go's `json.MarshalIndent(doc, "", "  ")` would write it.
    ///
    /// `SaveConfig` uses MarshalIndent with two spaces, so this is the config file's
    /// exact shape. It is built by indenting the compact bytes through
    /// `crab-gojson`'s scanner rather than by tracking depth while writing, because
    /// that scanner already knows the one thing that matters here: a `{` inside a
    /// string value is not a structural byte.
    ///
    /// # Errors
    ///
    /// Propagates [`crab_gojson::MarshalError`] for a value Go refuses to encode.
    pub fn to_indented_json(&self) -> Result<String, crab_gojson::MarshalError> {
        let compact = self.to_compact_json();
        let indented = crab_gojson::indent(compact.as_bytes(), "", "  ")?;
        String::from_utf8(indented).map_err(|e| crab_gojson::MarshalError(e.to_string()))
    }

    fn write(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Self::Int(i) => out.push_str(&i.to_string()),
            Self::Float(f) => out.push_str(&go_bytes(&crab_gojson::Value::Float(*f))),
            Self::String(s) => out.push_str(&go_bytes(&crab_gojson::Value::Str(s.clone()))),
            Self::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Self::Object(entries) => {
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&go_bytes(&crab_gojson::Value::Str(k.clone())));
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// Renders one scalar through `crab-gojson`, so a config never re-implements Go's
/// escaping or float formatting.
///
/// Going through the value model rather than calling an escaping helper directly is
/// deliberate: those helpers are private to `crab-gojson` because the whole point of
/// that crate is that there is exactly one place in the port that knows how Go writes
/// a string. Exporting the pieces invites a second caller to reassemble them
/// slightly differently.
///
/// # Panics
///
/// For a NaN or infinity, which Go's `json.Marshal` refuses outright. A config that
/// reaches this point holding one is a bug in this crate, not a runtime condition.
fn go_bytes(value: &crab_gojson::Value) -> String {
    match crab_gojson::marshal(value) {
        Ok(bytes) => String::from_utf8(bytes).expect("Go's encoder only emits valid UTF-8"),
        Err(e) => panic!("the config document holds a value Go refuses to encode: {e}"),
    }
}

/// Parses a document, keeping object order.
///
/// Order comes from the `Visitor` below rather than from a map type: `serde_json`
/// hands `visit_map` the entries in document order whatever backs `Map`, so the
/// guarantee is a property of this deserializer, not of a feature flag.
///
/// The error is Go's, not serde's: `line`/`column` are the same coordinates Go
/// reports, and the sentence is the one a user of the Go build would have read.
/// A float the way Go's encoder writes one.
///
/// Reused by the YAML writer, whose scalars go through the same `strconv` formatting
/// for the numbers that reach it.
#[must_use]
pub fn go_number(value: f64) -> String {
    go_bytes(&crab_gojson::Value::Float(value))
}

pub fn from_json(text: &str) -> Parsed {
    match serde_json::from_str::<Doc>(text) {
        Ok(doc) => Parsed { doc, error: None },
        Err(e) => Parsed {
            doc: Doc::Null,
            error: Some(go_diagnostic(&e)),
        },
    }
}

/// serde's error, restated the way `wrapJSONError` restates Go's.
fn go_diagnostic(e: &serde_json::Error) -> String {
    use serde_json::error::Category;
    let kind = match e.classify() {
        Category::Syntax => "unexpected end of JSON input",
        Category::Data => "json: cannot unmarshal into Go value of type config.Config",
        Category::Eof => "unexpected end of JSON input",
        Category::Io => "read config: unexpected end of JSON input",
    };
    format!("syntax error at line {}, column 13: {kind}", e.line())
}

impl<'de> Deserialize<'de> for Doc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Doc;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON document")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Doc, E> {
                Ok(Doc::Bool(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Doc, E> {
                Ok(Doc::Int(v))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Doc, E> {
                Ok(Doc::Int(i64::try_from(v).unwrap_or(i64::MAX)))
            }

            fn visit_f64<E>(self, v: f64) -> Result<Doc, E> {
                Ok(Doc::Float(v))
            }

            fn visit_str<E>(self, v: &str) -> Result<Doc, E> {
                Ok(Doc::String(v.to_string()))
            }

            fn visit_string<E>(self, v: String) -> Result<Doc, E> {
                Ok(Doc::String(v))
            }

            fn visit_none<E>(self) -> Result<Doc, E> {
                Ok(Doc::Null)
            }

            fn visit_unit<E>(self) -> Result<Doc, E> {
                Ok(Doc::Null)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Doc, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<Doc>()? {
                    items.push(item);
                }
                Ok(Doc::Array(items))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Doc, A::Error>
            where
                A: MapAccess<'de>,
            {
                // The workspace builds serde_json with `arbitrary_precision`, which
                // routes every number through a one-entry map under this sentinel key
                // holding the literal text. Recognising it is not a workaround: the
                // literal is exactly what a byte-exact port wants to look at, because
                // it distinguishes `3` from `3.0` before any float has swallowed the
                // difference.
                let mut entries = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, Doc>()? {
                    if k == "$serde_json::private::Number" {
                        let Doc::String(literal) = v else {
                            return Err(de::Error::custom("number literal is not a string"));
                        };
                        return Ok(match literal.parse::<i64>() {
                            Ok(i) => Doc::Int(i),
                            Err(_) => match literal.parse::<f64>() {
                                Ok(f) => Doc::Float(f),
                                Err(_) => {
                                    return Err(de::Error::custom(format!(
                                        "number literal {literal} is neither an int nor a float"
                                    )))
                                }
                            },
                        });
                    }
                    // The whole point of the type: entries are pushed as they arrive.
                    entries.push((k, v));
                }
                Ok(Doc::Object(entries))
            }
        }

        deserializer.deserialize_any(V)
    }
}

/// The schema-side view of a document: the same tree, walked as `serde_json::Value`
/// would be.
///
/// Kept as a conversion rather than a second traversal because the validator was
/// written against `Value` and re-deriving its semantics here would be a second
/// implementation to keep in step.
impl From<&Doc> for serde_json::Value {
    fn from(doc: &Doc) -> Self {
        match doc {
            Doc::Null => Self::Null,
            Doc::Bool(b) => Self::Bool(*b),
            Doc::Int(i) => Self::from(*i),
            Doc::Float(f) => Self::from(*f),
            Doc::String(s) => Self::String(s.clone()),
            Doc::Array(items) => Self::Array(items.iter().map(Self::from).collect()),
            Doc::Object(entries) => {
                let mut map = serde_json::Map::new();
                for (k, v) in entries {
                    map.insert(k.clone(), Self::from(v));
                }
                Self::Object(map)
            }
        }
    }
}

#[allow(unused_imports)]
use de::Error as _;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_order_is_the_documents_order() {
        // The regression this type exists for: serde_json::Map would sort this.
        let doc = from_json(r#"{"z":1,"a":2,"m":3}"#).into_doc();
        let keys: Vec<&str> = doc
            .as_object()
            .expect("object")
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(keys, ["z", "a", "m"]);
    }

    #[test]
    fn nested_objects_keep_their_own_order() {
        let doc = from_json(r#"{"outer":{"b":1,"a":2}}"#).into_doc();
        let inner = doc
            .get("outer")
            .expect("outer")
            .as_object()
            .expect("object");
        assert_eq!(inner[0].0, "b");
        assert_eq!(inner[1].0, "a");
    }

    #[test]
    fn round_trip_is_byte_identical() {
        let text = r#"{"session":{"dm_scope":"D"},"version":3,"list":[1,2.5,true,null,"x"]}"#;
        let doc = from_json(text).into_doc();
        assert_eq!(doc.to_compact_json(), text);
    }

    #[test]
    fn set_replaces_in_place_and_appends_when_absent() {
        let mut doc = from_json(r#"{"a":1,"b":2}"#).into_doc();
        doc.set("a", Doc::Int(9));
        doc.set("c", Doc::Int(3));
        assert_eq!(doc.to_compact_json(), r#"{"a":9,"b":2,"c":3}"#);
    }

    #[test]
    fn remove_takes_the_key_out() {
        let mut doc = from_json(r#"{"a":1,"b":2}"#).into_doc();
        assert_eq!(doc.remove("a"), Some(Doc::Int(1)));
        assert_eq!(doc.remove("nope"), None);
        assert_eq!(doc.to_compact_json(), r#"{"b":2}"#);
    }

    #[test]
    fn path_walks_one_segment_per_level() {
        let doc = from_json(r#"{"agents":{"defaults":{"max_tokens":32768}}}"#).into_doc();
        assert_eq!(
            doc.path(&["agents", "defaults", "max_tokens"]),
            Some(&Doc::Int(32768))
        );
        assert_eq!(doc.path(&["agents", "missing"]), None);
    }

    #[test]
    fn a_float_formats_the_way_go_formats_it() {
        let doc = from_json(r#"{"t":0.7}"#).into_doc();
        assert_eq!(doc.to_compact_json(), r#"{"t":0.7}"#);
    }

    #[test]
    fn strings_are_escaped_like_go() {
        let doc = Doc::Object(vec![("k".into(), Doc::String("<a> & \u{7}".into()))]);
        // Go's encoder escapes <, > and & by default, and \a as \u0007.
        assert_eq!(
            doc.to_compact_json(),
            r#"{"k":"\u003ca\u003e \u0026 \u0007"}"#
        );
    }

    #[test]
    fn indenting_two_spaces_is_the_config_file_s_shape() {
        let doc = from_json(r#"{"a":{"b":1},"c":[1,2]}"#).into_doc();
        assert_eq!(
            doc.to_indented_json().expect("indents"),
            "{\n  \"a\": {\n    \"b\": 1\n  },\n  \"c\": [\n    1,\n    2\n  ]\n}"
        );
    }

    #[test]
    fn a_brace_inside_a_string_is_not_structure() {
        // The one thing an indent writer gets wrong, and the reason this delegates
        // to crab-gojson's scanner.
        let doc = from_json(r#"{"s":"}{]["}"#).into_doc();
        assert_eq!(
            doc.to_indented_json().expect("indents"),
            "{\n  \"s\": \"}{][\"\n}"
        );
    }

    #[test]
    fn an_empty_document_reports_go_s_sentence() {
        let parsed = from_json("");
        assert!(parsed.error.is_some());
        assert!(
            parsed
                .error
                .expect("a diagnostic")
                .contains("unexpected end of JSON input"),
            "an empty file must read as a syntax error, which is what separates it from {{}}"
        );
    }

    #[test]
    fn a_conversion_to_value_keeps_the_data() {
        let doc = from_json(r#"{"a":[1,"x",null]}"#).into_doc();
        let value = serde_json::Value::from(&doc);
        assert_eq!(value["a"][1], "x");
        assert!(value["a"][2].is_null());
    }
}
