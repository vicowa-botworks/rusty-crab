//! `json.Indent` and the compaction `json.RawMessage` gets on the way out.
//!
//! `pkg/memory` writes `SessionMeta` with `json.MarshalIndent(meta, "", "  ")`,
//! and `SessionMeta.Scope` is a `json.RawMessage`. That combination has two
//! consequences a generic pretty-printer does not reproduce, and both are on
//! every session file's `.meta.json` on disk:
//!
//! * the raw scope is **re-indented to the enclosing document**, so its members
//!   sit at four spaces under a two-space meta, and
//! * the raw scope is **re-escaped**, so `{"q":"<b> &"}` lands as
//!   `{"q":"\u003cb\u003e \u0026"}`.
//!
//! The pinned cases are `meta_scope_is_reindented_by_marshal_indent` and
//! `meta_scope_is_reindented_and_reescaped` in `memory_jsonl_store.json`.
//!
//! An empty container stays on its line (`{}` and `[]` are never split), which is
//! what Go does and what makes `{"a":{}}` three lines rather than five.

use crate::MarshalError;

/// Go's `json.Indent(src, "", indent_str)`.
///
/// Input is expected to be compact JSON, which is the only thing this workspace
/// feeds it: the meta document is built by [`crate::GoMarshal`] and the scope by
/// [`compact_html`]. Whitespace outside strings is dropped rather than preserved,
/// like Go's.
///
/// # Errors
///
/// If `src` is not one valid JSON value. Go refuses to encode a struct whose
/// `RawMessage` field holds invalid JSON, and `pkg/memory` turns that into
/// `memory: encode meta`, so the refusal has to happen here too -- see
/// `meta_scope_invalid_json_is_refused`.
pub fn indent(src: &[u8], prefix: &str, indent_str: &str) -> Result<Vec<u8>, MarshalError> {
    let mut out = Vec::with_capacity(src.len() + src.len() / 8);
    let mut depth: usize = 0;
    // Set after `{`, `[` or `,`: the next significant byte is preceded by a
    // newline plus the current indentation. It is flushed lazily so an immediate
    // closing bracket -- the empty container -- cancels it instead.
    let mut pending = false;
    let mut scan = ValueScan::new();

    for &c in src {
        if scan.in_string {
            out.push(c);
            scan.step_string(c);
            continue;
        }
        match c {
            b'{' | b'[' => {
                flush(&mut out, prefix, indent_str, pending, depth);
                pending = true;
                depth += 1;
                out.push(c);
            }
            b'}' | b']' => {
                if pending {
                    // Empty container: no line break, and the depth we just
                    // entered is the one being left.
                    pending = false;
                } else {
                    out.push(b'\n');
                    out.extend_from_slice(prefix.as_bytes());
                    for _ in 0..depth.saturating_sub(1) {
                        out.extend_from_slice(indent_str.as_bytes());
                    }
                }
                depth -= 1;
                out.push(c);
            }
            b',' => {
                flush(&mut out, prefix, indent_str, pending, depth);
                pending = true;
                out.push(c);
            }
            b':' => {
                flush(&mut out, prefix, indent_str, pending, depth);
                pending = false;
                out.push(c);
                // Go writes `"key": value`, with the space.
                out.push(b' ');
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                // Insignificant between tokens; dropped like Go's Indent drops it.
            }
            _ => {
                flush(&mut out, prefix, indent_str, pending, depth);
                pending = false;
                out.push(c);
                if c == b'"' {
                    scan.in_string = true;
                }
            }
        }
    }

    if scan.in_string {
        return Err(MarshalError(
            "unexpected end of JSON input (unterminated string)".to_string(),
        ));
    }
    if depth != 0 {
        return Err(MarshalError(format!(
            "syntax error: unexpected end of JSON input ({depth} unclosed containers)"
        )));
    }
    Ok(out)
}

fn flush(out: &mut Vec<u8>, prefix: &str, indent_str: &str, pending: bool, depth: usize) {
    if !pending {
        return;
    }
    out.push(b'\n');
    out.extend_from_slice(prefix.as_bytes());
    for _ in 0..depth {
        out.extend_from_slice(indent_str.as_bytes());
    }
}

/// Go's `compact(dst, src, opts{escapeHTML: true})`: the transformation
/// `json.Marshal` applies to a `json.RawMessage` before writing it.
///
/// Drops whitespace between tokens and escapes `<`, `>`, `&`, U+2028 and U+2029
/// inside strings. Everything else is copied byte for byte, so a number keeps the
/// digits the caller wrote -- `1.0` does not become `1`, which is the difference
/// between this and parsing the value and re-encoding it.
///
/// # Errors
///
/// If `src` is not one valid JSON value. Structure is checked the way Go checks
/// it, and a bare literal is validated as a token by [`check_literal`] rather than
/// copied: `{"a": <1>}` and `nul` are refused here exactly as Go refuses them, so
/// a corrupt `scope` in a memory file fails to load here on the same file that
/// fails to load there. A port that reads further than Go turns one unreadable
/// file into a silently different session.
pub fn compact_html(src: &[u8]) -> Result<Vec<u8>, MarshalError> {
    let mut out = Vec::with_capacity(src.len());
    // Where the document structure says the next token has to be. Empty stack
    // means top level.
    let mut stack: Vec<Frame> = Vec::new();
    // A complete value has been emitted at top level, so only whitespace may
    // follow. This is what rejects `{"a":1} {"b":2}` and `12 3`.
    let mut top_done = false;
    let mut scan = ValueScan::new();
    // A bare literal (`true`, `5`, `-1e9`) runs until whitespace or a structural
    // byte, and is one value however many bytes it takes.
    let mut in_literal = false;
    // Where the literal now being read started in `out`, so it can be validated as
    // one token when it ends.
    let mut literal_start = 0usize;
    // Whether the string literal currently open is an object key rather than a
    // value. Only meaningful while `scan.in_string`.
    let mut string_is_key = false;
    let mut started = false;

    for &c in src {
        if scan.in_string {
            push_escaped(c, &mut out);
            let was_escaping = scan.escaping;
            scan.step_string(c);
            if !scan.in_string && !was_escaping {
                // The literal closed: a key moves its frame to "expecting `:`",
                // a value closes out the member.
                if string_is_key {
                    if let Some(frame) = stack.last_mut() {
                        *frame = Frame::ObjKey;
                    }
                } else {
                    after_value(&mut stack, &mut top_done);
                }
            }
            continue;
        }

        if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
            if in_literal {
                in_literal = false;
                check_literal(&out, literal_start)?;
                after_value(&mut stack, &mut top_done);
            }
            continue;
        }
        // A bare literal runs to the next whitespace or structural byte, and
        // closing it is what tells the frame a value has been read. Without this
        // step `[1,2]` reads as two values in a row with no comma between them.
        if in_literal {
            if !matches!(c, b',' | b'}' | b']') {
                out.push(c);
                continue;
            }
            in_literal = false;
            check_literal(&out, literal_start)?;
            after_value(&mut stack, &mut top_done);
        }

        match c {
            b'{' | b'[' => {
                if !may_open(&stack, top_done) {
                    return Err(invalid(c));
                }
                started = true;
                stack.push(if c == b'{' {
                    Frame::ObjStart
                } else {
                    Frame::ArrStart
                });
                out.push(c);
            }
            b'}' | b']' => {
                let Some(frame) = stack.last().copied() else {
                    return Err(invalid(c));
                };
                let ok = if c == b'}' {
                    matches!(frame, Frame::ObjStart | Frame::ObjComma)
                } else {
                    matches!(frame, Frame::ArrStart | Frame::ArrComma)
                };
                if !ok {
                    return Err(invalid(c));
                }
                stack.pop();
                after_value(&mut stack, &mut top_done);
                out.push(c);
            }
            b',' => {
                let Some(frame) = stack.last_mut() else {
                    return Err(invalid(c));
                };
                match frame {
                    Frame::ObjComma => *frame = Frame::ObjExpectKey,
                    Frame::ArrComma => *frame = Frame::ArrVal,
                    _ => return Err(invalid(c)),
                }
                out.push(c);
            }
            b':' => {
                if stack.last() != Some(&Frame::ObjKey) {
                    return Err(invalid(c));
                }
                *stack.last_mut().unwrap() = Frame::ObjVal;
                out.push(c);
            }
            b'"' => {
                string_is_key = match stack.last() {
                    None => {
                        if top_done {
                            return Err(invalid(c));
                        }
                        false
                    }
                    Some(Frame::ObjStart) | Some(Frame::ObjExpectKey) => true,
                    Some(Frame::ObjVal) | Some(Frame::ArrStart) | Some(Frame::ArrVal) => false,
                    Some(Frame::ObjComma) | Some(Frame::ObjKey) | Some(Frame::ArrComma) => {
                        return Err(invalid(c))
                    }
                };
                started = true;
                scan.in_string = true;
                out.push(c);
            }
            _ => {
                // A bare literal: only legal where a value is legal.
                if !may_open(&stack, top_done) {
                    return Err(invalid(c));
                }
                started = true;
                in_literal = true;
                literal_start = out.len();
                out.push(c);
            }
        }
    }

    if scan.in_string {
        return Err(MarshalError(
            "unexpected end of JSON input (unterminated string)".to_string(),
        ));
    }
    if in_literal {
        check_literal(&out, literal_start)?;
        after_value(&mut stack, &mut top_done);
    }
    if !stack.is_empty() || !started {
        return Err(MarshalError("unexpected end of JSON input".to_string()));
    }
    Ok(out)
}

/// Rejects a bare literal that is not one of Go's three keywords or a JSON
/// number.
///
/// This is the difference between copying bytes and scanning them: `{"a": <1>}`
/// has no value where `<1>` is, and Go's decoder says so at the `<`. Without this
/// check the compact copy accepts anything that is not a structural byte, so a
/// corrupt `scope` in a memory file would load here and fail to load in Go.
fn check_literal(out: &[u8], start: usize) -> Result<(), MarshalError> {
    let token = &out[start..];
    if valid_literal(token) {
        Ok(())
    } else {
        let at = String::from_utf8_lossy(token);
        Err(MarshalError(format!(
            "invalid character {at:?} looking for beginning of value"
        )))
    }
}

fn valid_literal(token: &[u8]) -> bool {
    matches!(token, b"true" | b"false" | b"null") || valid_number(token)
}

/// RFC 8259's number grammar, which is Go's scanner's for numbers: no leading
/// `+`, no leading zeros, and a fraction or exponent that actually has digits.
fn valid_number(token: &[u8]) -> bool {
    let mut i = 0usize;
    if token.first() == Some(&b'-') {
        i = 1;
    }
    match token.get(i) {
        Some(b'0') => i += 1,
        Some(c) if c.is_ascii_digit() => {
            while matches!(token.get(i), Some(c) if c.is_ascii_digit()) {
                i += 1;
            }
        }
        _ => return false,
    }
    if token.get(i) == Some(&b'.') {
        i += 1;
        let digits = i;
        while matches!(token.get(i), Some(c) if c.is_ascii_digit()) {
            i += 1;
        }
        if i == digits {
            return false;
        }
    }
    if matches!(token.get(i), Some(b'e') | Some(b'E')) {
        i += 1;
        if matches!(token.get(i), Some(b'+') | Some(b'-')) {
            i += 1;
        }
        let digits = i;
        while matches!(token.get(i), Some(c) if c.is_ascii_digit()) {
            i += 1;
        }
        if i == digits {
            return false;
        }
    }
    i == token.len()
}

/// Where the next token has to go once a value has just closed.
fn after_value(stack: &mut [Frame], top_done: &mut bool) {
    match stack.last_mut() {
        Some(Frame::ObjVal) => *stack.last_mut().unwrap() = Frame::ObjComma,
        Some(Frame::ArrStart) | Some(Frame::ArrVal) => {
            let n = stack.len() - 1;
            stack[n] = Frame::ArrComma;
        }
        _ => *top_done = true,
    }
}

/// Can a value (container or literal) start here?
fn may_open(stack: &[Frame], top_done: bool) -> bool {
    if let Some(frame) = stack.last() {
        return matches!(frame, Frame::ObjVal | Frame::ArrStart | Frame::ArrVal);
    }
    !top_done
}

/// The structural position the next token occupies, one frame per open container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// `{`, nothing yet: a key or `}`.
    ObjStart,
    /// A key has been read; `:` must follow.
    ObjKey,
    /// `:` has been read; a value must follow.
    ObjVal,
    /// A member's value has been read; `,` or `}`.
    ObjComma,
    /// After a `,` in an object: another key.
    ObjExpectKey,
    /// `[`, nothing yet: a value or `]`.
    ArrStart,
    /// After a `,` in an array: a value.
    ArrVal,
    /// A value has been read; `,` or `]`.
    ArrComma,
}

fn push_escaped(c: u8, out: &mut Vec<u8>) {
    match c {
        b'<' => out.extend_from_slice(b"\\u003c"),
        b'>' => out.extend_from_slice(b"\\u003e"),
        b'&' => out.extend_from_slice(b"\\u0026"),
        _ => out.push(c),
    }
}

fn invalid(c: u8) -> MarshalError {
    // Go's wording, because the message reaches a user-visible error through
    // `memory: encode meta: %w`.
    MarshalError(format!(
        "invalid character {:?} looking for beginning of value",
        char::from(c)
    ))
}

/// The two pieces of state both transducers need: whether a byte is inside a
/// string literal, and whether a `\` escape is in progress.
struct ValueScan {
    in_string: bool,
    escaping: bool,
}

impl ValueScan {
    fn new() -> Self {
        ValueScan {
            in_string: false,
            escaping: false,
        }
    }

    fn step_string(&mut self, c: u8) {
        if self.escaping {
            self.escaping = false;
            return;
        }
        match c {
            b'\\' => self.escaping = true,
            b'"' => self.in_string = false,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ind(s: &str) -> String {
        String::from_utf8(indent(s.as_bytes(), "", "  ").unwrap()).unwrap()
    }

    #[test]
    fn empty_containers_stay_on_the_line() {
        assert_eq!(ind("{}"), "{}");
        assert_eq!(ind("[]"), "[]");
        assert_eq!(ind(r#"{"a":{}}"#), "{\n  \"a\": {}\n}");
        assert_eq!(ind(r#"{"a":[],"b":{}}"#), "{\n  \"a\": [],\n  \"b\": {}\n}");
    }

    #[test]
    fn nesting_indents_by_two_and_closes_at_the_parent() {
        assert_eq!(
            ind(r#"{"a":{"b":1}}"#),
            "{\n  \"a\": {\n    \"b\": 1\n  }\n}"
        );
        assert_eq!(ind("[1,2]"), "[\n  1,\n  2\n]");
        assert_eq!(
            ind(r#"{"a":[{"b":1}]}"#),
            "{\n  \"a\": [\n    {\n      \"b\": 1\n    }\n  ]\n}"
        );
    }

    #[test]
    fn a_scope_sits_one_level_below_its_meta() {
        // The shape SessionMeta produces: scope's own members at four spaces.
        let compact = r#"{"key":"s1","scope":{"q":"x"}}"#;
        assert_eq!(
            ind(compact),
            "{\n  \"key\": \"s1\",\n  \"scope\": {\n    \"q\": \"x\"\n  }\n}"
        );
    }

    #[test]
    fn compaction_drops_whitespace_and_escapes_html() {
        assert_eq!(
            String::from_utf8(compact_html(br#"{ "q" : "<b> &" }"#).unwrap()).unwrap(),
            r#"{"q":"\u003cb\u003e \u0026"}"#
        );
        // Numbers keep their digits: this is compaction, not a re-encode.
        assert_eq!(
            String::from_utf8(compact_html(b"[ 1.0 , 2e3 ]").unwrap()).unwrap(),
            "[1.0,2e3]"
        );
        // An escape sequence is copied, and the quote it protects does not end
        // the string.
        assert_eq!(
            String::from_utf8(compact_html(br#""a\"b <c>""#).unwrap()).unwrap(),
            r#""a\"b \u003cc\u003e""#
        );
    }

    #[test]
    fn invalid_raw_json_is_refused() {
        for bad in [
            "{\"key\": \"s1\", \"cou",
            "",
            "{",
            "}",
            "{\"a\":1} {\"b\":2}",
            "[1,2",
            "\"unterminated",
        ] {
            assert!(
                compact_html(bad.as_bytes()).is_err(),
                "compact_html accepted {bad:?}"
            );
        }
        // A scalar is a valid RawMessage, and `null` in particular: SessionMeta
        // stores the four bytes `null` and does not omit the field.
        assert_eq!(compact_html(b"null").unwrap(), b"null");
        assert_eq!(compact_html(b" 5 ").unwrap(), b"5");
    }

    #[test]
    fn indent_refuses_truncated_input() {
        assert!(indent(b"{\"a\":", "", "  ").is_err());
        assert!(indent(b"{\"a\": \"x", "", "  ").is_err());
    }

    #[test]
    fn a_literal_that_is_not_a_value_is_refused() {
        // Go's scanner stops at the `<`; a byte copier would not, and then a
        // corrupt scope would load here while Go refuses the same file.
        for bad in [
            "{\"a\": <1>}",
            "[nul]",
            "nul",
            "tru",
            "01",
            "+1",
            "1.",
            "1e",
            "-",
            "[1 2]",
            // One value at a time: the scanner's scanEndImperfect state, which
            // the frame stack alone does not give you.
            "12 3",
            "{\"a\":1} {\"b\":2}",
            // Truncated mid-literal. Go's loop breaks on the error, scan.eof()
            // reports it, and MarshalIndent discards the partial document.
            "{\"a\":tr",
            "[tru",
        ] {
            assert!(
                compact_html(bad.as_bytes()).is_err(),
                "compact_html accepted {bad:?}"
            );
        }
        for ok in [
            "true",
            "false",
            "null",
            "0",
            "-0",
            "1",
            "1.0",
            "1e5",
            "-1.5e-9",
            "{\"a\": true, \"b\": [null, 0.5]}",
        ] {
            let out = compact_html(ok.as_bytes()).unwrap_or_else(|e| panic!("{ok}: {e}"));
            assert_eq!(String::from_utf8(out).unwrap(), ok.replace(' ', ""));
        }
    }
}
