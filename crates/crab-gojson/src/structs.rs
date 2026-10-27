//! Struct-level encoding: the part of `encoding/json` that a Go struct reaches.
//!
//! A Go struct is marshalled by reflection, so the source shows no encoding code
//! at all -- which is exactly why a port of it has to write some. What the
//! reflection does, and what this module reproduces:
//!
//! * keys are emitted in **declaration order**, not sorted (sorting is only what
//!   happens to a `map`);
//! * a field tagged `json:"-"` is not visited;
//! * a field tagged `,omitempty` is skipped when its value is *empty* by Go's
//!   definition -- zero number, `""`, `false`, nil pointer or interface, and a
//!   nil **or empty** slice or map. Note that a non-pointer struct value is never
//!   empty, so `omitempty` on one does nothing;
//! * everything else is always emitted, including `null`.
//!
//! [`GoMarshal`] rather than `serde::Serialize` because serde hands escaping and
//! number formatting to the serializer, and the whole point here is that Go's
//! answers -- `\u003c`, `1e-7`, `\b` -- are not the answers a Rust serializer
//! gives.

use std::collections::BTreeMap;

use crate::{encode_string, format_go_float, marshal, MarshalError, Value};

/// Encodes `self` as Go's `json.Marshal` would encode it.
pub trait GoMarshal {
    /// # Errors
    ///
    /// Propagates [`MarshalError`] for a value Go refuses to encode: a non-finite
    /// float, or a [`Value::Unsupported`]. Go fails the **whole** call, so a
    /// caller must not keep the bytes written before the failure -- see
    /// [`crate::marshal`], which discards them.
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError>;
}

impl GoMarshal for Value {
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError> {
        // Reuse the value-model encoder rather than duplicating it; marshal()
        // allocates a fresh buffer, so write into it and append.
        let bytes = marshal(self)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl GoMarshal for str {
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError> {
        encode_string(self, out);
        Ok(())
    }
}

/// A Go pointer is marshalled by dereferencing it, so a reference encodes exactly
/// like the value it points at. (`Option` is the different case: a nil pointer is
/// `null`, and that is what [`Option`]'s own impl does.)
impl<T: GoMarshal + ?Sized> GoMarshal for &T {
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError> {
        (**self).marshal_go(out)
    }
}

impl GoMarshal for String {
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError> {
        encode_string(self, out);
        Ok(())
    }
}

impl GoMarshal for bool {
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError> {
        out.extend_from_slice(if *self { b"true" } else { b"false" });
        Ok(())
    }
}

impl GoMarshal for i64 {
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError> {
        out.extend_from_slice(self.to_string().as_bytes());
        Ok(())
    }
}

impl GoMarshal for u64 {
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError> {
        out.extend_from_slice(self.to_string().as_bytes());
        Ok(())
    }
}

impl GoMarshal for f64 {
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError> {
        let bytes = format_go_float(*self)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// A Go pointer: `nil` is the literal `null`, not an absent field. `omitempty`
/// is what turns nil into absent, and that decision stays with the struct.
impl<T: GoMarshal> GoMarshal for Option<T> {
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError> {
        match self {
            Some(v) => v.marshal_go(out),
            None => {
                out.extend_from_slice(b"null");
                Ok(())
            }
        }
    }
}

impl<T: GoMarshal> GoMarshal for Vec<T> {
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError> {
        out.push(b'[');
        for (i, item) in self.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            item.marshal_go(out)?;
        }
        out.push(b']');
        Ok(())
    }
}

/// A Go `map[string]…`: keys sorted by byte, which `BTreeMap` already gives.
impl<T: GoMarshal> GoMarshal for BTreeMap<String, T> {
    fn marshal_go(&self, out: &mut Vec<u8>) -> Result<(), MarshalError> {
        out.push(b'{');
        for (i, (k, v)) in self.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            encode_string(k, out);
            out.push(b':');
            v.marshal_go(out)?;
        }
        out.push(b'}');
        Ok(())
    }
}

/// Writes one JSON object, inserting the separators so a struct's
/// [`GoMarshal`] impl only says which fields exist and in what order.
///
/// The closing brace is written by [`Self::finish`], not by `Drop`: a failed
/// field must leave the caller in control of the buffer, because Go discards the
/// entire result when any part of it fails.
pub struct ObjectWriter<'a> {
    out: &'a mut Vec<u8>,
    first: bool,
}

impl<'a> ObjectWriter<'a> {
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        out.push(b'{');
        ObjectWriter { out, first: true }
    }

    /// Writes `"key":` and then the value.
    ///
    /// # Errors
    ///
    /// Propagates the value's own [`MarshalError`].
    pub fn field<T: GoMarshal + ?Sized>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), MarshalError> {
        if !self.first {
            self.out.push(b',');
        }
        self.first = false;
        encode_string(key, self.out);
        self.out.push(b':');
        value.marshal_go(self.out)
    }

    /// Writes a field whose value is already encoded bytes -- for a type that
    /// produces its own text, such as a formatted timestamp.
    ///
    /// # Errors
    ///
    /// Never fails; present so struct impls can use `?` uniformly.
    pub fn raw(&mut self, key: &str, bytes: &[u8]) -> Result<(), MarshalError> {
        if !self.first {
            self.out.push(b',');
        }
        self.first = false;
        encode_string(key, self.out);
        self.out.push(b':');
        self.out.extend_from_slice(bytes);
        Ok(())
    }

    pub fn finish(&mut self) {
        self.out.push(b'}');
    }
}

/// Go's `isEmpty`, per kind. Each is a separate function because the tag is
/// written per field and the rule differs: an `omitempty` slice is skipped when
/// empty *or* nil, while an `omitempty` pointer is skipped only when nil.
pub mod omit {
    use std::collections::BTreeMap;

    /// `len(v) == 0`, which in Go covers both a nil slice and an empty one.
    pub fn slice<T>(v: &[T]) -> bool {
        v.is_empty()
    }

    /// A nil-or-empty `Option<Vec<_>>`, the shape a port uses when it has to keep
    /// nil and empty distinguishable for decoding even though `omitempty` erases
    /// the difference on the way out.
    pub fn maybe_slice<T>(v: &Option<Vec<T>>) -> bool {
        v.as_ref().is_none_or(|s| s.is_empty())
    }

    /// A nil-or-empty map. Nothing in `crab-protocoltypes` uses this because no
    /// map field there carries `omitempty` -- and it must not be reached for
    /// `ToolFunctionDefinition.parameters`, where Go distinguishes the two:
    /// nil marshals as `null` and an empty map as `{}`.
    pub fn map<K, V>(v: &Option<BTreeMap<K, V>>) -> bool {
        v.as_ref().is_none_or(|m| m.is_empty())
    }

    /// A pointer is empty only when nil: a pointer to a zero value is emitted.
    pub fn pointer<T>(v: &Option<T>) -> bool {
        v.is_none()
    }

    pub fn str(v: &str) -> bool {
        v.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<T: GoMarshal>(v: &T) -> String {
        let mut out = Vec::new();
        v.marshal_go(&mut out).expect("encodable");
        String::from_utf8(out).expect("UTF-8")
    }

    #[test]
    fn a_nil_pointer_is_null_not_absent() {
        let none: Option<String> = None;
        assert_eq!(bytes(&none), "null");
        assert_eq!(bytes(&Some("x".to_string())), r#""x""#);
    }

    #[test]
    fn declaration_order_is_not_key_order() {
        // ObjectWriter must not sort: sorting is what a Go *map* gets, and a
        // struct whose keys came out sorted would differ from the wire format
        // for every provider payload.
        let mut out = Vec::new();
        let mut o = ObjectWriter::new(&mut out);
        o.field("z", &1i64).unwrap();
        o.field("a", &2i64).unwrap();
        o.raw("M", b"3").unwrap();
        o.finish();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"z":1,"a":2,"M":3}"#);
    }

    #[test]
    fn map_keys_are_still_sorted() {
        let mut m = BTreeMap::new();
        m.insert("z".to_string(), 1i64);
        m.insert("a".to_string(), 2i64);
        assert_eq!(bytes(&m), r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn keys_are_escaped_like_values() {
        let mut out = Vec::new();
        let mut o = ObjectWriter::new(&mut out);
        o.field("a<b>&c", &0i64).unwrap();
        o.finish();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"{"a\u003cb\u003e\u0026c":0}"#
        );
    }

    #[test]
    fn a_non_finite_float_fails_the_object() {
        let mut out = Vec::new();
        let mut o = ObjectWriter::new(&mut out);
        assert!(o.field("ok", &"yes").is_ok());
        assert!(o.field("bad", &f64::NAN).is_err());
    }

    #[test]
    fn omitempty_rules_differ_by_kind() {
        let empty: Vec<String> = vec![];
        let empty_map: Option<BTreeMap<String, i64>> = None;
        assert!(omit::slice(&empty));
        assert!(omit::maybe_slice::<String>(&None));
        assert!(omit::map(&empty_map));
        // A pointer to a zero value is NOT empty.
        assert!(!omit::pointer(&Some(0i64)));
    }
}
