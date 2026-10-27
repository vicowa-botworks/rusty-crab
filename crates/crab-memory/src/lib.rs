//! `pkg/memory`'s JSONL session store, byte for byte.
//!
//! This is the on-disk half of the port that users notice: a session file written
//! by picoclaw's Go build has to be readable by this one, and a file written here
//! has to be readable by Go. `conformance/fixtures/memory_jsonl_store.json` pins
//! that -- 95 scripts of store calls whose expectation is the *directory* left
//! behind, every file's exact bytes plus every query's result.
//!
//! Three things about the Go store are load-bearing and none of them are obvious
//! from the field list:
//!
//! * **`Count` is a raw line count, not a message count.** [`Store::add_message`]
//!   increments it by one, but [`Store::truncate_history`] resets it to the count
//!   of *non-blank lines* in the file, torn and corrupt ones included. So a file
//!   whose last line was cut off mid-write reports `count: 2` while
//!   [`Store::get_history`] returns one message. `compact` is the only operation
//!   that brings the two back in step.
//! * **`Skip` is a raw-line offset, `keep_last` is a retained-line count.**
//!   Truncating to keep 1 message out of a file with a corrupt line and a torn
//!   line sets `skip` to the *raw* offset, which is not the same number.
//! * **`Scope` is a `json.RawMessage`, and `MarshalIndent` does not pass it
//!   through.** It is re-compacted with HTML escaping and then re-indented to the
//!   enclosing document, so `{"chat":  1}` lands as `"chat": 1` with `\u003c` for
//!   `<` and its members at four spaces under a two-space meta. See
//!   [`crab_gojson::indent`].
//! * **Promotion takes the alias's numbers, not the canonical's.**
//!   [`Store::promote_alias_history`] sets `count` from the *alias history's* length
//!   and `skip` to 0, while reading the alias from its *own* `skip` -- so a
//!   truncated alias contributes its retained tail and nothing more. It is also the
//!   only op that refuses based on what the destination already holds, and a summary
//!   alone counts as content there.
//!
//! Concurrency is the one deliberate simplification. Go guards each session with
//! one of 64 read-write locks and the directory listing with a mutex; this module
//! is single-threaded and takes no lock, because the conformance harness runs one
//! script at a time. A runtime that shares a [`Store`] across threads needs the
//! locks added back -- the file-level atomicity (`write` then `rename`) is
//! implemented, the in-process exclusion is not. Promotion is the op that will want
//! them most: Go takes both keys at once with `lockSessionPair`, in key order to
//! avoid inverting against a concurrent promotion in the other direction.

use crab_gojson::{compact_html, indent, omit, GoMarshal, ObjectWriter};
use crab_protocoltypes::unmarshal::{self, DecodeError};
use crab_protocoltypes::{GoTime, Message};
use serde_json::{Map, Value};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Go's `maxLineSize` in `pkg/memory/jsonl.go`: one line longer than this makes
/// the scanner fail, and the failure ends the read rather than skipping the line.
const MAX_LINE_SIZE: usize = 10 * 1024 * 1024;

/// A store failure. The corpus records *which* op refused, never the message, so
/// the text exists for logs -- it follows Go's wording where Go has one.
#[derive(Debug)]
pub struct Error(String);

impl Error {
    fn new(msg: impl Into<String>) -> Self {
        Error(msg.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error(format!("{e}"))
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        Error(e.0)
    }
}

type Result<T> = std::result::Result<T, Error>;

/// `sanitizeKey`: a session key becomes a file stem by replacing every path
/// separator with `_`.
///
/// The replacement is what makes `a:b` and `a/b` collide onto one file, which the
/// corpus pins on purpose (`name_collision_colon_and_slash`): the store has never
/// disambiguated them and existing directories contain the result.
#[must_use]
pub fn sanitize_key(key: &str) -> String {
    key.replace([':', '/', '\\'], "_")
}

/// `SessionMeta`, the `.meta.json` beside each `.jsonl`.
///
/// `created_at` and `updated_at` are Go `time.Time` *values*, not pointers, so
/// `None` here means the zero instant: it is still written out, as
/// `"0001-01-01T00:00:00Z"`, and it is what a reader reports as `null`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionMeta {
    pub key: String,
    pub summary: String,
    pub skip: i64,
    pub count: i64,
    pub created_at: Option<GoTime>,
    pub updated_at: Option<GoTime>,
    /// `json.RawMessage`: the stored bytes verbatim, or `None` for the omitted
    /// field. Kept as bytes rather than a parsed value because the whole point is
    /// that they are not re-encoded -- apart from what `MarshalIndent` does to
    /// them, which [`Store::write_meta`] reproduces.
    pub scope: Option<Vec<u8>>,
    pub aliases: Option<Vec<String>>,
}

impl SessionMeta {
    /// Go's `time.Time.IsZero`, which is the year-1 *instant* and nothing else.
    /// `t.sec() == 0 && t.nsec() == 0` -- the location is never consulted -- so
    /// `0001-01-01T01:00:00+01:00` and `0001-01-01T23:00:00+23:00` are both zero
    /// while `0001-01-01T00:00:00-24:00` is not. `unix_seconds` is already the
    /// instant, so no normalisation is needed; adding an offset test here makes a
    /// zero timestamp carried in a non-UTC zone look real, which changes both the
    /// bytes (`addMsg` refuses to stamp it) and `get_meta` (Go reports `null`,
    /// because `omitempty` fires on a zero time). Pinned by
    /// `meta_zero_in_a_non_utc_zone_reads_as_zero` and
    /// `meta_zero_in_a_non_utc_zone_is_stamped_by_a_write`.
    #[must_use]
    fn is_zero(t: &Option<GoTime>) -> bool {
        match t {
            None => true,
            Some(t) => t.unix_seconds == -62_135_596_800 && t.nanos == 0,
        }
    }
}

/// The zero instant as Go's `time.Time{}` marshals it.
const ZERO_TIME_JSON: &[u8] = b"\"0001-01-01T00:00:00Z\"";

impl GoMarshal for SessionMeta {
    /// Field order is declaration order, which is the order the bytes on disk
    /// have: key, summary, skip, count, created_at, updated_at, scope, aliases.
    fn marshal_go(&self, out: &mut Vec<u8>) -> std::result::Result<(), crab_gojson::MarshalError> {
        let mut o = ObjectWriter::new(out);
        o.field("key", &self.key)?;
        // `summary` has no omitempty: an empty summary is `"summary":""`, and a
        // session that never set one still writes it.
        o.field("summary", &self.summary)?;
        o.field("skip", &self.skip)?;
        o.field("count", &self.count)?;
        write_time(&mut o, "created_at", &self.created_at)?;
        write_time(&mut o, "updated_at", &self.updated_at)?;
        if let Some(scope) = &self.scope {
            // `omitempty` on a RawMessage means len == 0, so an empty scope is
            // omitted while the four bytes `null` are kept.
            if !scope.is_empty() {
                // What json.Marshal does to a RawMessage before writing it.
                let compact = compact_html(scope).map_err(|e| {
                    crab_gojson::MarshalError(format!("json: invalid raw message field: {e}"))
                })?;
                o.raw("scope", &compact)?;
            }
        }
        if !omit::maybe_slice(&self.aliases) {
            o.field("aliases", self.aliases.as_ref().unwrap())?;
        }
        o.finish();
        Ok(())
    }
}

fn write_time<'a>(
    o: &mut ObjectWriter<'a>,
    name: &'static str,
    t: &Option<GoTime>,
) -> std::result::Result<(), crab_gojson::MarshalError> {
    match t {
        // A zero time.Time is not omitted -- it is written as the year-1 string.
        None => o.raw(name, ZERO_TIME_JSON),
        Some(t) => o.field(name, t),
    }
}

impl SessionMeta {
    /// `json.Unmarshal` into the struct.
    ///
    /// Decoded through [`serde_json::value::RawValue`] rather than [`Value`]
    /// because `Scope` is a `json.RawMessage` and Go's RawMessage keeps the
    /// *source bytes*: read back from an indented meta file, the stored scope
    /// carries the four-space indentation `MarshalIndent` wrote, and describing it
    /// has to reproduce that. A parsed value would re-serialize it compactly and
    /// lose the assertion `meta_scope_is_reindented_and_reescaped` makes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        // Option absorbs the `null` document, which Go unmarshals into a zeroed
        // struct without error.
        // `OrderedFields`, not a map: Go's decoder walks the object in *document* order
        // and takes the last occurrence of a repeated name, and the fold below relies on
        // that. A `HashMap` loses the order outright; sorting the keys to make it
        // deterministic resolves duplicate case variants (`{"key":"a","KEY":"b"}`)
        // alphabetically where Go resolves them by position. serde_json cannot read an
        // object into `Vec<(String, T)>` -- "invalid type: map, expected a sequence" --
        // so the ordering is recovered in the visitor, which keeps `RawValue` rather than
        // parsing values and so keeps `Scope`'s source bytes.
        let doc: Option<OrderedFields> = serde_json::from_slice(bytes)
            .map_err(|e| Error::new(format!("memory: decode meta: {e}")))?;
        let Some(doc) = doc else {
            return Ok(Self::default());
        };
        let mut m = Self::default();
        for (name, raw) in &doc.0 {
            let name = name.as_str();
            // Case-folded like the decoder in crab-protocoltypes; unknown names
            // are ignored, which is what lets a newer file load here. A repeated
            // key is resolved last-wins, as Go's decoder does.
            match name.to_ascii_lowercase().as_str() {
                "key" => m.key = go_string(raw.get(), "SessionMeta.key")?,
                "summary" => m.summary = go_string(raw.get(), "SessionMeta.summary")?,
                "skip" => m.skip = go_int(raw.get(), "SessionMeta.skip")?,
                "count" => m.count = go_int(raw.get(), "SessionMeta.count")?,
                "created_at" => m.created_at = go_time(raw.get())?,
                "updated_at" => m.updated_at = go_time(raw.get())?,
                "scope" => m.scope = Some(raw.get().as_bytes().to_vec()),
                "aliases" => m.aliases = go_string_slice(raw.get())?,
                _ => {}
            }
        }
        Ok(m)
    }

    /// `json.MarshalIndent(meta, "", "  ")`.
    fn marshal_indent(&self) -> Result<Vec<u8>> {
        let mut compact = Vec::new();
        self.marshal_go(&mut compact).map_err(Error::from_inner)?;
        indent(&compact, "", "  ").map_err(Error::from_inner)
    }
}

impl Error {
    fn from_inner(e: crab_gojson::MarshalError) -> Self {
        Error(format!("memory: encode meta: {e}"))
    }
}

/// Reports the value as Go would name it when it refuses a type.
fn describe_value(raw: &str) -> &'static str {
    match raw.trim_start().chars().next() {
        Some('"') => "string",
        Some('[') => "array",
        Some('{') => "object",
        Some('t') | Some('f') => "bool",
        Some('n') => "null",
        Some(_) => "number",
        None => "value",
    }
}

fn type_error(raw: &str, field: &str, go_type: &str) -> Error {
    Error::new(format!(
        "json: cannot unmarshal {} into Go struct field {field} of type {go_type}",
        describe_value(raw)
    ))
}

fn go_string(raw: &str, field: &str) -> Result<String> {
    match serde_json::from_str::<Option<String>>(raw) {
        // `null` into a string field is a no-op in Go, not an error.
        Ok(None) => Ok(String::new()),
        Ok(Some(s)) => Ok(s),
        Err(_) => Err(type_error(raw, field, "string")),
    }
}

fn go_int(raw: &str, field: &str) -> Result<i64> {
    match serde_json::from_str::<Option<i64>>(raw) {
        Ok(None) => Ok(0),
        Ok(Some(v)) => Ok(v),
        // A `1.0` reaching an int is refused here and by Go's decoder, which makes
        // the whole meta unreadable rather than truncating it.
        Err(_) => Err(type_error(raw, field, "int")),
    }
}

fn go_time(raw: &str) -> Result<Option<GoTime>> {
    match serde_json::from_str::<Option<String>>(raw) {
        Ok(None) => Ok(None),
        // A string that is not a timestamp is a decode failure, not a zero. Go's
        // decoder returns the parse error and `readMeta` propagates it, so a
        // corrupt stamp stops the session from loading; defaulting to the zero
        // time here would silently rewrite `created_at` to year 1 the next time
        // anything wrote the file.
        Ok(Some(s)) => unmarshal::parse_rfc3339_nano(&s).map(Some).ok_or_else(|| {
            Error::new(format!(
                "parsing time {s:?} as \"2006-01-02T15:04:05Z07:00\": cannot parse"
            ))
        }),
        Err(_) => Err(type_error(raw, "SessionMeta", "time.Time")),
    }
}

fn go_string_slice(raw: &str) -> Result<Option<Vec<String>>> {
    match serde_json::from_str::<Option<Vec<String>>>(raw) {
        Ok(v) => Ok(v),
        Err(_) => Err(type_error(raw, "SessionMeta.aliases", "[]string")),
    }
}

/// The JSONL session store: one `.jsonl` and one `.meta.json` per session key,
/// all in one directory.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// `memory.NewJSONLStore(dir)`, which creates the directory with
    /// `os.MkdirAll(dir, 0o755)` before handing the store back. A store pointed at
    /// a path that does not exist yet therefore produces the same directory, with
    /// the same mode, as the Go binary -- and the constructor can fail for the
    /// same reasons Go's does.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        create_dir_all(&dir)?;
        Ok(Store { dir })
    }

    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The two paths a key maps to: `(history, meta)`.
    ///
    /// `stemFor` in the generator asks the store this rather than duplicating
    /// [`sanitize_key`], so a raw write in the corpus addresses the file the store
    /// actually uses and the oracle cannot agree with itself about the name.
    #[must_use]
    pub fn paths_for(&self, key: &str) -> (PathBuf, PathBuf) {
        let stem = sanitize_key(key);
        (
            self.dir.join(format!("{stem}.jsonl")),
            self.dir.join(format!("{stem}.meta.json")),
        )
    }

    /// `AddMessage`.
    pub fn add_message(&self, key: &str, role: &str, content: &str) -> Result<()> {
        let mut msg = Message {
            role: role.to_string(),
            content: content.to_string(),
            ..Message::default()
        };
        self.add_full_message(key, &mut msg)
    }

    /// `AddFullMessage`. Takes the message by mutable reference because Go stamps
    /// `created_at` on the caller's value before encoding it.
    pub fn add_full_message(&self, key: &str, msg: &mut Message) -> Result<()> {
        // Go takes one `now := time.Now()` at the top of `addMsg` and stamps the
        // message's `created_at`, the meta's `created_at` and its `updated_at` with that
        // same instant. Three calls to `now()` produce three different nanoseconds, which
        // the corpus clock mask hides -- so the divergence is invisible until a fixture
        // compares two of the three, and then it is a file-byte difference.
        let now = now();
        if is_transient_thought(msg) {
            // A thought-only assistant message is not persisted at all: no
            // history file, no meta file. `transient_thought_creates_no_files`
            // pins that the directory stays empty rather than empty-but-present.
            return Ok(());
        }
        if msg.created_at.is_none() {
            msg.created_at = Some(now);
        }

        let (history_path, meta_path) = self.paths_for(key);
        // Marshal first: a message that cannot be encoded must not leave a
        // half-written line, and must not create the file either.
        let mut line = Vec::new();
        msg.marshal_go(&mut line)
            .map_err(|e| Error::new(format!("memory: marshal message: {e}")))?;
        line.push(b'\n');

        append_bytes(&history_path, &line)?;

        let mut meta = self.read_meta(key)?;
        // Go's guard is `meta.Count == 0 && meta.CreatedAt.IsZero()`. The count test is
        // not redundant with the zero test: a meta written by an older file can carry
        // `count > 0` with no `created_at` at all, and Go leaves that at year 1 forever
        // rather than stamping it now. `set_summary_keeps_a_hand_written_created_at`
        // pins the sibling that genuinely has no count test.
        if meta.count == 0 && SessionMeta::is_zero(&meta.created_at) {
            meta.created_at = Some(now);
        }
        meta.count += 1;
        meta.updated_at = Some(now);
        self.write_meta(&meta_path, &mut meta, key)
    }

    /// `GetHistory`.
    pub fn get_history(&self, key: &str) -> Result<Vec<Message>> {
        let (_, meta_path) = self.paths_for(key);
        let meta = self.read_meta_file(&meta_path, key)?;
        let (history_path, _) = self.paths_for(key);
        self.read_messages(&history_path, meta.skip)
    }

    /// `SetHistory`.
    pub fn set_history(&self, key: &str, messages: &[Message]) -> Result<()> {
        // One instant for the meta pair and every message, as Go's `now := time.Now()`
        // at the top of `SetHistory` does.
        let now = now();
        let history = filter_invalid_history(messages);
        let (history_path, meta_path) = self.paths_for(key);
        let mut meta = self.read_meta_file(&meta_path, key)?;
        if SessionMeta::is_zero(&meta.created_at) {
            meta.created_at = Some(now);
        }
        meta.skip = 0;
        meta.count = history.len() as i64;
        meta.updated_at = Some(now);
        self.write_meta(&meta_path, &mut meta, key)?;

        let mut stamped = history;
        for msg in &mut stamped {
            if msg.created_at.is_none() {
                msg.created_at = Some(now);
            }
        }
        self.rewrite_jsonl(&history_path, &stamped)
    }

    /// `TruncateHistory`.
    ///
    /// `keep_last` counts *retained* messages, while `skip` is stored as a raw
    /// line offset, and the two only coincide on a file where every line reads
    /// back. A negative or zero `keep_last` clears the session rather than being
    /// clamped, which is why the argument is signed.
    pub fn truncate_history(&self, key: &str, keep_last: i64) -> Result<()> {
        let (history_path, meta_path) = self.paths_for(key);
        let mut meta = self.read_meta_file(&meta_path, key)?;
        let (raw_count, retained) = self.scan_retained_message_lines(&history_path)?;

        // Count is the RAW non-empty line count, so a torn final line is counted
        // even though no reader will ever return it.
        meta.count = raw_count;
        if meta.skip > meta.count {
            meta.skip = meta.count;
        }

        // `retained` holds 1-based raw line numbers, so "greater than skip" is
        // exactly the set of lines a read would still return.
        let active_start = retained
            .iter()
            .position(|n| *n > meta.skip)
            .unwrap_or(retained.len());
        let active = &retained[active_start..];

        if keep_last <= 0 || active.is_empty() {
            meta.skip = meta.count;
        } else if keep_last < active.len() as i64 {
            // Land the offset on the raw line just before the ones being kept, so
            // the reader's "skip this many raw lines" lands on the right message
            // even when corrupt lines in between are not counted as retained.
            meta.skip = active[active.len() - keep_last as usize - 1];
        }
        meta.updated_at = Some(now());
        self.write_meta(&meta_path, &mut meta, key)
    }

    /// `Compact`: drop the skipped prefix from the file and reset the offset.
    pub fn compact(&self, key: &str) -> Result<()> {
        let (history_path, meta_path) = self.paths_for(key);
        let mut meta = self.read_meta_file(&meta_path, key)?;
        if meta.skip == 0 {
            // A no-op that writes nothing at all -- not even a refreshed
            // updated_at. `compact_without_truncate_is_a_noop` pins the bytes.
            return Ok(());
        }
        let active = self.read_messages(&history_path, meta.skip)?;
        meta.skip = 0;
        meta.count = active.len() as i64;
        meta.updated_at = Some(now());
        self.write_meta(&meta_path, &mut meta, key)?;
        self.rewrite_jsonl(&history_path, &active)
    }

    /// `SetSummary`.
    pub fn set_summary(&self, key: &str, summary: &str) -> Result<()> {
        let now = now();
        let (_, meta_path) = self.paths_for(key);
        let mut meta = self.read_meta_file(&meta_path, key)?;
        if SessionMeta::is_zero(&meta.created_at) {
            meta.created_at = Some(now);
        }
        meta.summary = summary.to_string();
        meta.updated_at = Some(now);
        self.write_meta(&meta_path, &mut meta, key)
    }

    /// `UpsertSessionMeta`. `scope` is stored raw; `None` is an absent field.
    pub fn upsert_session_meta(
        &self,
        key: &str,
        scope: Option<Vec<u8>>,
        aliases: Option<Vec<String>>,
    ) -> Result<()> {
        let now = now();
        let (_, meta_path) = self.paths_for(key);
        let mut meta = self.read_meta_file(&meta_path, key)?;
        meta.scope = scope;
        meta.aliases = normalize_aliases(key, aliases);
        if SessionMeta::is_zero(&meta.created_at) {
            meta.created_at = Some(now);
        }
        meta.updated_at = Some(now);
        self.write_meta(&meta_path, &mut meta, key)
    }

    /// `PromoteAliasHistory`.
    ///
    /// The only op that moves a history from one session key to another: an empty
    /// canonical session adopts the history of the first of its aliases that has
    /// any. The `bool` is the answer to "did it promote", and `false` with no error
    /// is a normal outcome -- the corpus records it as a query value because
    /// "refused" and "errored" are different expectations that the directory alone
    /// cannot always separate.
    ///
    /// Go guards the pair with `lockSessionPair`. This crate takes no lock at all
    /// (module comment), so the pair-lock is as unimplemented as every other lock
    /// here rather than being the one place a mutex appears.
    pub fn promote_alias_history(
        &self,
        session_key: &str,
        scope: Option<Vec<u8>>,
        aliases: Option<Vec<String>>,
    ) -> Result<bool> {
        let session_key = session_key.trim();
        if session_key.is_empty() {
            return Ok(false);
        }

        // Normalized before the loop, which is what makes two things in the helper
        // redundant rather than load-bearing: the second `normalize_aliases` on the
        // stored list (idempotent), and the unconditional summary assignment (a
        // canonical with a summary is refused before the assignment is reached).
        // Both were injected as faults and both regenerate byte-identical.
        let Some(aliases) = normalize_aliases(session_key, aliases) else {
            return Ok(false);
        };
        for alias in &aliases {
            if is_main_session_alias(alias) {
                continue;
            }
            match self.promote_alias_history_locked(session_key, alias, scope.as_deref(), &aliases)
            {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    /// `promoteAliasHistoryLocked`. The order of the two writes is Go's: the
    /// history is rewritten first, then the meta, and a meta failure rolls the
    /// history back to its exact previous bytes.
    fn promote_alias_history_locked(
        &self,
        session_key: &str,
        alias: &str,
        scope: Option<&[u8]>,
        aliases: &[String],
    ) -> Result<bool> {
        let mut canonical_meta = self.read_meta(session_key)?;
        if self.session_has_visible_content(session_key, &canonical_meta)? {
            return Ok(false);
        }

        let alias_meta = self.read_meta(alias)?;
        // From the alias's own `skip`: promotion moves the *retained tail* of a
        // truncated alias, and resurrecting already-summarised messages into the
        // canonical history is the divergence this line prevents.
        let (alias_history_path, _) = self.paths_for(alias);
        let alias_history = self.read_messages(&alias_history_path, alias_meta.skip)?;
        let alias_summary = alias_meta.summary.trim().to_string();
        if alias_history.is_empty() && alias_summary.is_empty() {
            return Ok(false);
        }

        let (previous_jsonl, had_previous_jsonl) = self.read_raw_jsonl(session_key)?;

        // One instant for both stamps, as Go's single `now := time.Now()` does.
        // `created_at` is guarded by the zero test alone -- no count test, so this
        // is the `set_summary` family, not `add_message`'s.
        let now = now();
        if SessionMeta::is_zero(&canonical_meta.created_at) {
            canonical_meta.created_at = Some(now);
        }
        canonical_meta.scope = scope.map(<[u8]>::to_vec);
        canonical_meta.aliases = normalize_aliases(session_key, Some(aliases.to_vec()));
        canonical_meta.skip = 0;
        canonical_meta.count = alias_history.len() as i64;
        canonical_meta.updated_at = Some(now);
        if !alias_summary.is_empty() {
            canonical_meta.summary = alias_summary;
        }

        let (history_path, meta_path) = self.paths_for(session_key);
        self.rewrite_jsonl(&history_path, &alias_history)?;
        if let Err(e) = self.write_meta(&meta_path, &mut canonical_meta, session_key) {
            // Fidelity, not coverage: this rollback cannot be reached through the
            // public API, because every way of making `write_meta` refuse makes the
            // `read_meta` at the top of this function refuse first. The corpus says
            // so on the `promote_alias` cases rather than leaving the gap silent.
            if let Err(rollback) =
                self.restore_raw_jsonl(session_key, &previous_jsonl, had_previous_jsonl)
            {
                return Err(Error::new(format!(
                    "memory: write promoted meta: {e} (rollback jsonl: {rollback})"
                )));
            }
            return Err(e);
        }
        Ok(true)
    }

    /// `sessionHasVisibleContentLocked`. A summary counts as content even with zero
    /// messages, which is why `promote_alias_refused_when_canonical_has_only_a_summary`
    /// exists.
    fn session_has_visible_content(&self, key: &str, meta: &SessionMeta) -> Result<bool> {
        if !meta.summary.trim().is_empty() {
            return Ok(true);
        }
        let (history_path, _) = self.paths_for(key);
        Ok(!self.read_messages(&history_path, meta.skip)?.is_empty())
    }

    /// `readRawJSONL`: the file's exact bytes, plus whether it was there at all.
    /// The second half matters -- rolling back a session that had no history file
    /// means removing it, not writing an empty one.
    fn read_raw_jsonl(&self, key: &str) -> Result<(Vec<u8>, bool)> {
        let (history_path, _) = self.paths_for(key);
        match fs::read(&history_path) {
            Ok(data) => Ok((data, true)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((Vec::new(), false)),
            Err(e) => Err(Error::new(format!("memory: read jsonl: {e}"))),
        }
    }

    /// `restoreRawJSONL`. The exact previous bytes, not a re-encode.
    fn restore_raw_jsonl(&self, key: &str, data: &[u8], existed: bool) -> Result<()> {
        let (history_path, _) = self.paths_for(key);
        if !existed {
            return match fs::remove_file(&history_path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(Error::new(format!("memory: remove jsonl rollback: {e}"))),
            };
        }
        write_atomic(&history_path, data, 0o644)
            .map_err(|e| Error::new(format!("memory: restore jsonl rollback: {e}")))
    }

    /// `GetSessionMeta`.
    pub fn get_session_meta(&self, key: &str) -> Result<SessionMeta> {
        let (_, meta_path) = self.paths_for(key);
        self.read_meta_file(&meta_path, key)
    }

    /// `ListSessions`. Returns `None` for an empty store, because Go returns a nil
    /// slice and the corpus distinguishes that from `[]`.
    pub fn list_sessions(&self) -> Option<Vec<String>> {
        // Go takes a directory-wide mutex here; see the module comment.
        let mut keys: Vec<String> = Vec::new();
        // os.ReadDir hands back entries sorted by name; fs::read_dir does not,
        // and the order is observable in the result.
        let mut names: Vec<String> = match fs::read_dir(&self.dir) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .filter(|e| !e.path().is_dir())
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .collect(),
            Err(_) => return None,
        };
        names.sort();

        for name in names {
            if !name.ends_with(".meta.json") {
                continue;
            }
            let Ok(data) = fs::read(self.dir.join(&name)) else {
                continue;
            };
            // An unreadable meta is skipped, not an error: that is how
            // `list_skips_unreadable_meta` keeps `good` in the listing.
            let Ok(meta) = SessionMeta::decode(&data) else {
                continue;
            };
            if !meta.key.is_empty() {
                keys.push(meta.key);
            }
        }
        if keys.is_empty() {
            None
        } else {
            Some(keys)
        }
    }

    /// `Close`. Go's `Close()` is `return nil` -- there is no handle to close here
    /// either. The directory sync people expect from a `Close` actually happens in
    /// `WriteFileAtomic`, after each rename, so it is already done by the time this
    /// returns.
    pub fn close(&self) -> Result<()> {
        Ok(())
    }

    /// `readMeta`: a missing file is a fresh meta, not an error.
    fn read_meta(&self, key: &str) -> Result<SessionMeta> {
        let (_, meta_path) = self.paths_for(key);
        self.read_meta_file(&meta_path, key)
    }

    fn read_meta_file(&self, path: &Path, key: &str) -> Result<SessionMeta> {
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(SessionMeta {
                    key: key.to_string(),
                    ..SessionMeta::default()
                })
            }
            Err(e) => return Err(Error::new(format!("memory: read meta: {e}"))),
        };
        let mut meta = SessionMeta::decode(&data)?;
        if meta.key.is_empty() {
            meta.key = key.to_string();
        }
        Ok(meta)
    }

    /// `writeMeta`. The key is filled in when the meta carries none.
    ///
    /// Aliases are *not* normalized here, whatever the reader expects: Go's
    /// `writeMeta` marshals the struct as it was handed it, and only
    /// [`Store::upsert_session_meta`] runs `normalizeAliases`. A meta written by
    /// `write_raw_meta` and then touched by `set_summary` therefore keeps the
    /// blank and duplicate entries it was given.
    fn write_meta(&self, path: &Path, meta: &mut SessionMeta, key: &str) -> Result<()> {
        if meta.key.trim().is_empty() {
            meta.key = key.to_string();
        }
        let bytes = meta.marshal_indent()?;
        write_atomic(path, &bytes, 0o644)
    }

    /// `readMessages`: the history file minus its first `skip` non-blank lines.
    fn read_messages(&self, path: &Path, skip: i64) -> Result<Vec<Message>> {
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::new(format!("memory: open jsonl: {e}"))),
        };
        let mut out = Vec::new();
        let mut line_num: i64 = 0;
        for raw in scan_lines(&data) {
            if raw.len() > MAX_LINE_SIZE {
                return Err(Error::new("memory: scan jsonl: token too long"));
            }
            if raw.is_empty() {
                continue;
            }
            line_num += 1;
            if line_num <= skip {
                continue;
            }
            // A line that will not decode is logged and skipped, so one bad write
            // does not lose the session. `corrupt_line_is_skipped_not_fatal`.
            let Ok(msg) = unmarshal::message(raw) else {
                continue;
            };
            // Transient thoughts are filtered on read as well as on write, which
            // is what makes `transient_thought_on_disk_is_filtered_on_read` agree
            // with a store that never wrote the line.
            if is_transient_thought(&msg) {
                continue;
            }
            out.push(msg);
        }
        Ok(out)
    }

    /// `scanRetainedMessageLines`: the raw non-empty line count, plus the 1-based
    /// raw line number of every line a reader would still hand back.
    ///
    /// The list, not just its length, is what `truncate` needs: with a corrupt
    /// line in the middle, counting retained lines and then indexing into raw
    /// lines puts the offset on the wrong message.
    fn scan_retained_message_lines(&self, path: &Path) -> Result<(i64, Vec<i64>)> {
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((0, Vec::new())),
            Err(e) => return Err(Error::new(format!("memory: open jsonl: {e}"))),
        };
        let mut raw_count: i64 = 0;
        let mut retained = Vec::new();
        for raw in scan_lines(&data) {
            if raw.len() > MAX_LINE_SIZE {
                return Err(Error::new("memory: scan jsonl: token too long"));
            }
            if raw.is_empty() {
                continue;
            }
            raw_count += 1;
            let Ok(msg) = unmarshal::message(raw) else {
                continue;
            };
            if is_transient_thought(&msg) {
                continue;
            }
            retained.push(raw_count);
        }
        Ok((raw_count, retained))
    }

    /// `rewriteJSONL`: replace the file with exactly these messages.
    fn rewrite_jsonl(&self, path: &Path, messages: &[Message]) -> Result<()> {
        let history = filter_invalid_history(messages);
        let mut buf = Vec::new();
        // Go numbers the failing message: `memory: marshal message %d`.
        for (i, msg) in history.iter().enumerate() {
            msg.marshal_go(&mut buf)
                .map_err(|e| Error::new(format!("memory: marshal message {i}: {e}")))?;
            buf.push(b'\n');
        }
        write_atomic(path, &buf, 0o644)
    }
}

/// A JSON object kept as a sequence of name/value pairs, in document order.
///
/// `serde_json`'s own map types cannot give this: `HashMap` discards order, and the
/// `preserve_order` feature would silently reorder every map in every crate that links
/// `serde_json` -- including `crab-gojson`, whose whole job is Go's map encoding. So the
/// order is recovered from the `MapAccess`, which serde_json drives in source order, and
/// values stay `RawValue` so nothing re-serialises them on the way through.
#[derive(Debug)]
struct OrderedFields(Vec<(String, Box<serde_json::value::RawValue>)>);

impl<'de> serde::Deserialize<'de> for OrderedFields {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Vec<(String, Box<serde_json::value::RawValue>)>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut fields = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some(entry) =
                    map.next_entry::<String, Box<serde_json::value::RawValue>>()?
                {
                    fields.push(entry);
                }
                Ok(fields)
            }
        }

        deserializer.deserialize_map(Visitor).map(Self)
    }
}

/// `bufio.Scanner` over `data` with `ScanLines`: split on `\n`, dropping one
/// trailing `\r` from each line. A final segment with no newline is still a line;
/// a trailing newline does not add one.
fn scan_lines(data: &[u8]) -> Vec<&[u8]> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for chunk in data.split(|b| *b == b'\n') {
        out.push(match chunk.strip_suffix(b"\r") {
            Some(stripped) => stripped,
            None => chunk,
        });
    }
    // The split after a trailing newline yields an empty final segment, which is
    // not a line Go's scanner reports.
    if data.last() == Some(&b'\n') {
        out.pop();
    }
    out
}

/// `messageutil.IsTransientAssistantThoughtMessage`.
#[must_use]
pub fn is_transient_thought(msg: &Message) -> bool {
    msg.role == "assistant"
        && msg.content.trim().is_empty()
        && !msg.reasoning_content.trim().is_empty()
        && msg.tool_calls.as_ref().is_none_or(|v| v.is_empty())
        && msg.media.as_ref().is_none_or(|v| v.is_empty())
        && msg.attachments.as_ref().is_none_or(|v| v.is_empty())
        && msg.tool_call_id.trim().is_empty()
}

/// `messageutil.FilterInvalidHistoryMessages`. Always returns a `Vec`, so an empty
/// input yields an empty history rather than an absent one.
#[must_use]
pub fn filter_invalid_history(messages: &[Message]) -> Vec<Message> {
    messages
        .iter()
        .filter(|m| !is_transient_thought(m))
        .cloned()
        .collect()
}

/// `normalizeAliases`: trim each alias, drop the blanks and the duplicates, and
/// collapse an empty result to nil so `omitempty` hides the field.
/// `isMainSessionAlias`. Two shapes name the shared fallback session: the legacy
/// `agent:<agent>:main`, and the opaque `sk_v1_<sha256>` of exactly that string for
/// three capitalisations of `main`.
///
/// The part count is the load-bearing half. `agent:sales:main` *is* a fallback and
/// must never be swallowed into a per-channel session; `agent:sales:direct:main`
/// only looks like one and must still promote. Go expresses this as
/// `len(strings.SplitN(alias, ":", 4)) == 3`, which is exactly two colons in the
/// whole key -- so `agent::main` matches too, odd as that reads. Both directions
/// are pinned by the corpus, because a one-sided case cannot tell "filter missing"
/// from "filter too broad".
fn is_main_session_alias(alias: &str) -> bool {
    if alias.is_empty() {
        return false;
    }
    if alias.starts_with("agent:") && alias.ends_with(":main") && alias.matches(':').count() == 2 {
        return true;
    }
    // Matched by digest, not by shape: a port that hashes the wrong string fails
    // in only one direction, so `promote_alias_skips_the_opaque_main_alias` and
    // `promote_alias_does_not_skip_an_unrelated_opaque_key` pin it from both sides.
    if alias.starts_with("sk_v1_") {
        for agent_id in ["main", "Main", "MAIN"] {
            if opaque_main_alias(agent_id) == alias {
                return true;
            }
        }
    }
    false
}

/// `"sk_v1_"` plus the lowercase hex SHA-256 of `agent:<agent_id>:main`, the form
/// picoclaw writes when it stopped putting the agent id in the key in the clear.
fn opaque_main_alias(agent_id: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(format!("agent:{agent_id}:main").as_bytes());
    let mut hex = String::with_capacity(6 + 64);
    hex.push_str("sk_v1_");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn normalize_aliases(canonical: &str, aliases: Option<Vec<String>>) -> Option<Vec<String>> {
    let list = aliases?;
    if list.is_empty() {
        return None;
    }
    let canonical = canonical.trim();
    let mut seen = Vec::new();
    for alias in list {
        let trimmed = alias.trim();
        // The canonical key is what the file is *about*; listing it as one of its
        // own aliases is noise the caller passes by accident, and dropping it is
        // also what makes `meta_aliases_drop_canonical_and_duplicates` show the
        // dedup working rather than hiding behind the key.
        if trimmed.is_empty() || trimmed == canonical {
            continue;
        }
        if !seen.iter().any(|existing: &String| existing == trimmed) {
            seen.push(trimmed.to_string());
        }
    }
    // Empty comes back as nil, not an empty slice: `omitempty` then hides the
    // field entirely, which is the difference `meta_aliases_all_blank_is_omitted`
    // pins in the file bytes.
    if seen.is_empty() {
        None
    } else {
        Some(seen)
    }
}

/// The mode Go gives every directory it creates: `os.MkdirAll(dir, 0o755)`.
const DIR_MODE: u32 = 0o755;

/// `os.MkdirAll(dir, 0o755)` -- create the directory and every missing parent at
/// `0o755` masked by the process umask, leaving an existing directory alone.
///
/// `fs::create_dir_all` cannot express this: it creates at `0o777` masked, so
/// under `umask 002` -- the default on many distros -- the session directory
/// lands `0o775`, group-writable, where the Go store writes `0o755`. At the
/// ambient `umask 022` the two agree, which is why this needs the child test
/// rather than a plain assertion. `DirBuilder` applies `mode` to every component
/// it creates, which is what `MkdirAll` does.
fn create_dir_all(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(DIR_MODE);
    }
    builder.create(path)?;
    Ok(())
}

/// `fileutil.WriteFileAtomic`: write a hidden temp file in the same directory,
/// then rename it over the target.
///
/// The temp name carries the pid and a nanosecond clock, exactly as Go's does, so
/// a crashed writer leaves the same shape of debris -- and, like Go, the debris is
/// removed on every path that gets that far. A reader never sees a partial file,
/// which is the point.
fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::new("memory: meta path has no directory"))?;
    create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        nanos_since_epoch()
    ));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    use std::io::Write;
    let result = (|| -> Result<()> {
        let mut file = opts.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        // Go calls `tmpFile.Chmod(perm)` after the sync. The create mode above is masked
        // by the process umask -- `umask 007` would leave 0640 where Go writes 0644 -- so
        // the mode is forced here rather than requested at create.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        }
        drop(file);
        fs::rename(&tmp, path)?;
        // Go reopens the directory and syncs it *after* the rename, ignoring any failure
        // (`if dirFile, err := os.Open(dir); err == nil`). Syncing the file does not make
        // the rename durable; this does.
        #[cfg(unix)]
        if let Ok(dir_file) = fs::File::open(dir) {
            let _ = dir_file.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// `os.OpenFile(..., O_APPEND|O_CREATE|O_WRONLY)` then a write.
fn append_bytes(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        create_dir_all(dir)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        // Go passes 0o644 to `os.OpenFile`. Without it the file is created 0o666 masked
        // by the umask, so under `umask 002` the session history lands group-writable
        // where Go's is not. Like Go, this is the create mode and so is umask-masked --
        // only `write_atomic` forces the mode afterwards.
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644);
    }
    let mut file = opts.open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn nanos_since_epoch() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// `time.Now()`, as the store stamps it.
///
/// Go stamps in the process's local zone and the corpus masks any timestamp at
/// or after the generator's own start, so the offset never reaches an expectation
/// -- which is why UTC is fine here and why a port must not read this as a claim
/// that picoclaw writes `Z`.
#[must_use]
pub fn now() -> GoTime {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    GoTime {
        unix_seconds: d.as_secs() as i64,
        nanos: d.subsec_nanos(),
        offset_seconds: 0,
    }
}

/// Builds the `{files, results}` shape the corpus expects, for a directory.
///
/// Lives in the crate rather than the harness because the masking rule belongs
/// with the store: it is the store's own clock that is being hidden.
#[must_use]
pub fn snapshot_dir(dir: &Path) -> Map<String, Value> {
    let mut files = Map::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let Ok(data) = fs::read(&path) else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        files.insert(name, Value::String(mask_store_clock(&data)));
    }
    files
}

/// The corpus's clock rule: a timestamp at or after `threshold` was written by the
/// store during this run and is replaced by `<time>`; an earlier one was scripted
/// by the case and is recorded byte-exact.
///
/// Applied to file bytes, so a port that writes a non-timestamp where a timestamp
/// belongs still fails -- the mask only hides values, never shapes.
#[must_use]
pub fn mask_store_clock(bytes: &[u8]) -> String {
    mask_timestamps(&String::from_utf8_lossy(bytes), clock_threshold())
}

/// The threshold both maskings share: one second before this process started, so
/// a store stamp made a microsecond after the harness began is still masked.
#[must_use]
pub fn clock_threshold() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Computed once, at first use, so every case in a run is judged against the
    // same instant.
    use std::sync::OnceLock;
    static THRESHOLD: OnceLock<i64> = OnceLock::new();
    *THRESHOLD.get_or_init(|| now - 1)
}

/// Replaces every RFC3339-shaped timestamp in `text` whose instant is at or after
/// `threshold` with `<time>`.
#[must_use]
pub fn mask_timestamps(text: &str, threshold: i64) -> String {
    const MASKED: &str = "<time>";
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some(end) = rfc3339_at(text, i) {
            let token = &text[i..end];
            // A match that does not parse is masked anyway: determinism outranks
            // pinning, and the shape test already guarantees it looked like a time.
            let stamped = match unmarshal::parse_rfc3339_nano(token) {
                None => true,
                Some(t) => t.unix_seconds >= threshold,
            };
            out.push_str(if stamped { MASKED } else { token });
            i = end;
            continue;
        }
        // Copy one character, not one byte: the scan index must stay on a boundary.
        let ch_len = 1 + utf8_len(bytes[i]);
        out.push_str(&text[i..i + ch_len]);
        i += ch_len;
    }
    out
}

/// Bytes beyond the leading byte of a UTF-8 sequence, for the copy path above.
fn utf8_len(lead: u8) -> usize {
    if lead >= 0xF0 {
        3
    } else if lead >= 0xE0 {
        2
    } else if lead >= 0xC0 {
        1
    } else {
        0
    }
}

/// If a timestamp starts at `at`, the byte offset where it ends.
///
/// Deliberately permissive, like the generator's regex: the point is to hide the
/// value, and a shape that is not a timestamp must not be hidden.
fn rfc3339_at(text: &str, at: usize) -> Option<usize> {
    let b = text.as_bytes();
    let n = b.len();
    let digit = |i: usize| i < n && b[i].is_ascii_digit();
    // yyyy-mm-ddThh:mm:ss
    if !(digit(at)
        && digit(at + 1)
        && digit(at + 2)
        && digit(at + 3)
        && b.get(at + 4) == Some(&b'-')
        && digit(at + 5)
        && digit(at + 6)
        && b.get(at + 7) == Some(&b'-')
        && digit(at + 8)
        && digit(at + 9)
        && b.get(at + 10) == Some(&b'T')
        && digit(at + 11)
        && digit(at + 12)
        && b.get(at + 13) == Some(&b':')
        && digit(at + 14)
        && digit(at + 15)
        && b.get(at + 16) == Some(&b':')
        && digit(at + 17)
        && digit(at + 18))
    {
        return None;
    }
    let mut i = at + 19;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        let mut j = start;
        while j < n && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == start {
            return None;
        }
        i = j;
    }
    // Z, or a signed hh:mm. Lowercase `z` is not in Go's pattern, and a mask that
    // matches more than the generator's would hide a byte difference.
    if b.get(i) == Some(&b'Z') {
        return Some(i + 1);
    }
    if (b.get(i) == Some(&b'+') || b.get(i) == Some(&b'-'))
        && digit(i + 1)
        && digit(i + 2)
        && b.get(i + 3) == Some(&b':')
        && digit(i + 4)
        && digit(i + 5)
    {
        return Some(i + 6);
    }
    None
}

/// The described form of a [`Message`], matching `describeMessage` in the
/// generator: every wire field, plus the `json:"-"` ones, so a port that leaks an
/// internal field is visible in the comparison.
#[must_use]
pub fn describe_message(msg: &Message) -> Value {
    let mut map = Map::new();
    map.insert("role".into(), Value::String(msg.role.clone()));
    map.insert("content".into(), Value::String(msg.content.clone()));
    map.insert("model_name".into(), Value::String(msg.model_name.clone()));
    map.insert("created_at".into(), describe_time(&msg.created_at));
    map.insert("media".into(), describe_strings(&msg.media));
    map.insert(
        "attachments".into(),
        describe_slice(&msg.attachments, |a| {
            let mut m = Map::new();
            m.insert("type".into(), Value::String(a.attachment_type.clone()));
            m.insert("ref".into(), Value::String(a.ref_.clone()));
            m.insert("url".into(), Value::String(a.url.clone()));
            m.insert("filename".into(), Value::String(a.filename.clone()));
            m.insert("content_type".into(), Value::String(a.content_type.clone()));
            Value::Object(m)
        }),
    );
    map.insert(
        "reasoning_content".into(),
        Value::String(msg.reasoning_content.clone()),
    );
    map.insert(
        "system_parts".into(),
        describe_slice(&msg.system_parts, |b| {
            let mut m = Map::new();
            m.insert("type".into(), Value::String(b.block_type.clone()));
            m.insert("text".into(), Value::String(b.text.clone()));
            m.insert(
                "cache_control".into(),
                match &b.cache_control {
                    None => Value::Null,
                    Some(c) => {
                        let mut inner = Map::new();
                        inner.insert("type".into(), Value::String(c.control_type.clone()));
                        Value::Object(inner)
                    }
                },
            );
            m.insert("prompt_layer".into(), Value::String(b.prompt_layer.clone()));
            m.insert("prompt_slot".into(), Value::String(b.prompt_slot.clone()));
            m.insert(
                "prompt_source".into(),
                Value::String(b.prompt_source.clone()),
            );
            Value::Object(m)
        }),
    );
    map.insert(
        "tool_calls".into(),
        describe_slice(&msg.tool_calls, |tc| {
            let mut m = Map::new();
            m.insert("id".into(), Value::String(tc.id.clone()));
            m.insert("type".into(), Value::String(tc.call_type.clone()));
            // json:"-" fields: read from disk they are always the zero value, and
            // a port that maps the provider wire's near-identical fields by name
            // fills them in and fails here.
            m.insert("arguments".into(), Value::Null);
            m.insert("name".into(), Value::String(tc.name.clone()));
            m.insert(
                "thought_signature".into(),
                Value::String(tc.thought_signature.clone()),
            );
            m.insert(
                "function".into(),
                match &tc.function {
                    None => Value::Null,
                    Some(f) => {
                        let mut inner = Map::new();
                        inner.insert("name".into(), Value::String(f.name.clone()));
                        inner.insert("arguments".into(), Value::String(f.arguments.clone()));
                        inner.insert(
                            "thought_signature".into(),
                            Value::String(f.thought_signature.clone()),
                        );
                        Value::Object(inner)
                    }
                },
            );
            m.insert(
                "extra_content".into(),
                match &tc.extra_content {
                    None => Value::Null,
                    Some(e) => {
                        let mut inner = Map::new();
                        inner.insert(
                            "google".into(),
                            match &e.google {
                                None => Value::Null,
                                Some(g) => {
                                    let mut gmap = Map::new();
                                    gmap.insert(
                                        "thought_signature".into(),
                                        Value::String(g.thought_signature.clone()),
                                    );
                                    Value::Object(gmap)
                                }
                            },
                        );
                        inner.insert(
                            "tool_feedback_explanation".into(),
                            Value::String(e.tool_feedback_explanation.clone()),
                        );
                        Value::Object(inner)
                    }
                },
            );
            Value::Object(m)
        }),
    );
    map.insert(
        "tool_call_id".into(),
        Value::String(msg.tool_call_id.clone()),
    );
    map.insert(
        "prompt_layer".into(),
        Value::String(msg.prompt_layer.clone()),
    );
    map.insert("prompt_slot".into(), Value::String(msg.prompt_slot.clone()));
    map.insert(
        "prompt_source".into(),
        Value::String(msg.prompt_source.clone()),
    );
    Value::Object(map)
}

/// The described form of a [`SessionMeta`].
#[must_use]
pub fn describe_meta(meta: &SessionMeta) -> Value {
    let mut map = Map::new();
    map.insert("key".into(), Value::String(meta.key.clone()));
    map.insert("summary".into(), Value::String(meta.summary.clone()));
    map.insert("skip".into(), Value::from(meta.skip));
    map.insert("count".into(), Value::from(meta.count));
    map.insert(
        "created_at".into(),
        if SessionMeta::is_zero(&meta.created_at) {
            Value::Null
        } else {
            describe_time(&meta.created_at)
        },
    );
    map.insert(
        "updated_at".into(),
        if SessionMeta::is_zero(&meta.updated_at) {
            Value::Null
        } else {
            describe_time(&meta.updated_at)
        },
    );
    map.insert(
        "scope".into(),
        match &meta.scope {
            // len(scope) == 0 is nil for the description, so an empty RawMessage
            // and an absent one are the same answer.
            Some(b) if b.is_empty() => Value::Null,
            Some(b) => Value::String(String::from_utf8_lossy(b).into_owned()),
            None => Value::Null,
        },
    );
    map.insert("aliases".into(), describe_strings(&meta.aliases));
    Value::Object(map)
}

/// `describeTime`: seconds, nanoseconds and zone offset separately, so a port has
/// to get the instant right rather than copy a formatted string.
#[must_use]
pub fn describe_time(t: &Option<GoTime>) -> Value {
    match t {
        None => Value::Null,
        Some(t) => {
            let mut m = Map::new();
            m.insert("unix_seconds".into(), Value::from(t.unix_seconds));
            m.insert("nanos".into(), Value::from(t.nanos));
            m.insert("offset_seconds".into(), Value::from(t.offset_seconds));
            Value::Object(m)
        }
    }
}

/// `describeStrings`: nil stays nil, which is not the same as an empty array.
#[must_use]
pub fn describe_strings(v: &Option<Vec<String>>) -> Value {
    match v {
        None => Value::Null,
        Some(items) => Value::Array(items.iter().map(|s| Value::String(s.clone())).collect()),
    }
}

fn describe_slice<T>(v: &Option<Vec<T>>, each: impl Fn(&T) -> Value) -> Value {
    match v {
        None => Value::Null,
        Some(items) => Value::Array(items.iter().map(each).collect()),
    }
}

/// Applies the clock rule to a described value: a `{unix_seconds, nanos,
/// offset_seconds}` object at or after the threshold becomes `"<time>"`, and
/// strings are scanned for timestamps.
#[must_use]
pub fn mask_times(value: &Value) -> Value {
    mask_times_with(value, clock_threshold())
}

fn mask_times_with(value: &Value, threshold: i64) -> Value {
    match value {
        Value::Object(map) => {
            if is_described_time(map) {
                let unix = map
                    .get("unix_seconds")
                    .and_then(Value::as_i64)
                    .unwrap_or(i64::MIN);
                if unix >= threshold {
                    return Value::String("<time>".into());
                }
            }
            Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), mask_times_with(v, threshold)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| mask_times_with(v, threshold))
                .collect(),
        ),
        // A string is masked wherever it matches, with no threshold: the
        // generator's `maskTimes` replaces every timestamp in a query result,
        // because a value that reached a *result* was never written to disk and
        // the file-byte rule about who stamped it does not apply here.
        Value::String(s) => Value::String(mask_timestamps(s, i64::MIN)),
        other => other.clone(),
    }
}

fn is_described_time(map: &Map<String, Value>) -> bool {
    map.len() == 3
        && map.contains_key("unix_seconds")
        && map.contains_key("nanos")
        && map.contains_key("offset_seconds")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "crab-memory-{tag}-{}-{}",
            std::process::id(),
            nanos_since_epoch()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read(dir: &Path, name: &str) -> String {
        fs::read_to_string(dir.join(name)).unwrap_or_else(|_| panic!("no {name}"))
    }

    #[test]
    fn a_key_becomes_two_files_with_the_exact_bytes() {
        let dir = temp_dir("plain");
        let store = Store::new(&dir).unwrap();
        store
            .add_message("agent:main:signal:+4477", "user", "hi")
            .unwrap();

        let jsonl = read(&dir, "agent_main_signal_+4477.jsonl");
        // The stamp is the store's own, so only the shape is asserted here; the
        // corpus asserts the masked bytes.
        assert!(
            jsonl.starts_with("{\"role\":\"user\",\"content\":\"hi\",\"created_at\":\""),
            "{jsonl}"
        );
        assert!(jsonl.ends_with("\"}\n"), "{jsonl}");

        let meta = read(&dir, "agent_main_signal_+4477.meta.json");
        assert!(meta.starts_with("{\n  \"key\": \"agent:main:signal:+4477\",\n  \"summary\": \"\",\n  \"skip\": 0,\n  \"count\": 1,\n"),
            "{meta}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_thought_only_message_writes_nothing() {
        let dir = temp_dir("transient");
        let store = Store::new(&dir).unwrap();
        let msg = Message {
            role: "assistant".into(),
            reasoning_content: "thinking".into(),
            ..Message::default()
        };
        store.add_full_message("s1", &mut msg.clone()).unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(store.list_sessions(), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scope_is_reindented_and_reescaped() {
        let dir = temp_dir("scope");
        let store = Store::new(&dir).unwrap();
        store
            .upsert_session_meta("s1", Some(b"{\n  \"q\": \"<b> &\" }".to_vec()), None)
            .unwrap();
        let meta = read(&dir, "s1.meta.json");
        // Four-space members under the two-space meta, and the HTML trio escaped.
        assert!(
            meta.contains("\"scope\": {\n    \"q\": \"\\u003cb\\u003e \\u0026\"\n  }"),
            "{meta}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_invalid_scope_is_refused_before_anything_is_written() {
        let dir = temp_dir("bad-scope");
        let store = Store::new(&dir).unwrap();
        let err = store
            .upsert_session_meta("s1", Some(b"{\"a\": <1>}".to_vec()), None)
            .unwrap_err();
        assert!(err.to_string().contains("encode meta"), "{err}");
        // The refusal leaves no trace: not even the session's own file.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_null_scope_is_kept_and_an_absent_one_is_not() {
        let dir = temp_dir("null-scope");
        let store = Store::new(&dir).unwrap();
        store
            .upsert_session_meta("null", Some(b"null".to_vec()), None)
            .unwrap();
        store.upsert_session_meta("absent", None, None).unwrap();
        assert!(read(&dir, "null.meta.json").contains("\"scope\": null"));
        assert!(!read(&dir, "absent.meta.json").contains("scope"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn count_counts_raw_lines_and_history_counts_messages() {
        let dir = temp_dir("torn");
        let store = Store::new(&dir).unwrap();
        store.add_message("s1", "user", "one").unwrap();
        // Simulate a crash: a final line cut off mid-write.
        fs::OpenOptions::new()
            .append(true)
            .open(dir.join("s1.jsonl"))
            .unwrap()
            .write_all(b"{\"role\":\"user\",\"cont")
            .unwrap();

        let history = store.get_history("s1").unwrap();
        assert_eq!(history.len(), 1, "the torn line must not read back");
        // Reading does not recompute anything: Count is still the running total
        // the writer incremented, which is neither the raw nor the retained count.
        let meta = store.get_session_meta("s1").unwrap();
        assert_eq!(meta.count, 1, "{meta:?}");

        // Truncating to keep 1 keeps the raw offset at 0, because skip counts raw
        // lines and only one raw line precedes the retained message.
        store.truncate_history("s1", 1).unwrap();
        let meta = store.get_session_meta("s1").unwrap();
        assert_eq!((meta.count, meta.skip), (2, 0), "{meta:?}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn compact_is_a_no_op_without_a_skip_offset() {
        let dir = temp_dir("compact-noop");
        let store = Store::new(&dir).unwrap();
        store.add_message("s1", "user", "one").unwrap();
        let before = read(&dir, "s1.meta.json");
        store.compact("s1").unwrap();
        assert_eq!(before, read(&dir, "s1.meta.json"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_sorts_and_skips_unreadable_meta() {
        let dir = temp_dir("list");
        let store = Store::new(&dir).unwrap();
        store.add_message("b", "user", "hi").unwrap();
        store.add_message("a", "user", "hi").unwrap();
        fs::write(dir.join("c.meta.json"), b"not json at all\n").unwrap();
        fs::write(dir.join("orphan.jsonl"), b"").unwrap();
        assert_eq!(store.list_sessions(), Some(vec!["a".into(), "b".into()]));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_session_reads_as_empty_not_as_an_error() {
        let dir = temp_dir("missing");
        let store = Store::new(&dir).unwrap();
        assert_eq!(store.get_history("nope").unwrap(), Vec::new());
        assert_eq!(store.get_session_meta("nope").unwrap().key, "nope");
        store.truncate_history("nope", 3).unwrap();
        // Truncating a session that does not exist does create its meta file,
        // because Go writes the meta it just built.
        assert!(dir.join("nope.meta.json").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn aliases_are_trimmed_deduplicated_and_nil_when_empty() {
        let dir = temp_dir("aliases");
        let store = Store::new(&dir).unwrap();
        store
            .upsert_session_meta(
                "s1",
                None,
                Some(vec![" a ".into(), "a".into(), "".into(), "b".into()]),
            )
            .unwrap();
        let meta = store.get_session_meta("s1").unwrap();
        assert_eq!(
            meta.aliases.as_ref().unwrap(),
            &vec!["a".to_string(), "b".to_string()]
        );

        store
            .upsert_session_meta("s2", None, Some(vec!["  ".into()]))
            .unwrap();
        assert_eq!(store.get_session_meta("s2").unwrap().aliases, None);
        assert!(!read(&dir, "s2.meta.json").contains("aliases"));
        fs::remove_dir_all(&dir).ok();
    }

    /// The meta-failure rollback is unreachable through the public API -- every way
    /// of making `write_meta` refuse makes the `read_meta` at the top of
    /// `promote_alias_history_locked` refuse first -- so the corpus cannot pin it and
    /// says so on the `promote_alias` cases. These assertions are the reason the code
    /// is tested rather than dead: "there was no history file" and "there was an
    /// empty one" are the distinction a naive port collapses, and collapsing it
    /// deletes a session's history instead of restoring it.
    #[test]
    fn the_rollback_distinguishes_absent_from_empty() {
        let dir = temp_dir("rollback");
        let store = Store::new(&dir).unwrap();

        let (bytes, existed) = store.read_raw_jsonl("s1").unwrap();
        assert!(!existed, "a fresh session has no history file");
        assert!(bytes.is_empty());
        store.restore_raw_jsonl("s1", &bytes, existed).unwrap();
        assert!(
            !dir.join("s1.jsonl").exists(),
            "rolling back an absent file must not create one"
        );

        // A session that had one gets its exact bytes back, torn line included: the
        // rollback restores what was on disk, not a re-encode of what parsed.
        let torn = "{\"role\":\"user\"}\nnot json\n";
        fs::write(dir.join("s1.jsonl"), torn).unwrap();
        let (bytes, existed) = store.read_raw_jsonl("s1").unwrap();
        assert!(existed);
        fs::write(dir.join("s1.jsonl"), "overwritten").unwrap();
        store.restore_raw_jsonl("s1", &bytes, existed).unwrap();
        assert_eq!(read(&dir, "s1.jsonl"), torn, "byte for byte");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_lines_matches_bufio() {
        assert_eq!(scan_lines(b"a\nb\n"), vec![&b"a"[..], &b"b"[..]]);
        assert_eq!(scan_lines(b"a\nb"), vec![&b"a"[..], &b"b"[..]]);
        assert_eq!(scan_lines(b"a\r\nb\r\n"), vec![&b"a"[..], &b"b"[..]]);
        assert_eq!(
            scan_lines(b"a\n\nb\n"),
            vec![&b"a"[..], &b""[..], &b"b"[..]]
        );
        assert_eq!(scan_lines(b""), Vec::<&[u8]>::new());
        assert_eq!(scan_lines(b"\n"), vec![&b""[..]]);
    }

    #[test]
    fn the_clock_mask_hides_only_the_store() {
        let threshold = 1_700_000_001;
        assert_eq!(
            mask_timestamps("2026-01-01T00:00:00Z", threshold),
            "<time>".to_string()
        );
        assert_eq!(
            mask_timestamps("2023-11-14T22:13:20.25Z", threshold),
            "2023-11-14T22:13:20.25Z".to_string(),
            "a scripted instant predates the run and must survive"
        );
        // A shape that is not a timestamp is left alone, so a port that writes a
        // number where a timestamp belongs still fails.
        assert_eq!(mask_timestamps("1700000000", threshold), "1700000000");
        assert_eq!(
            mask_timestamps("x 2026-01-01T00:00:00+01:00 y", threshold),
            "x <time> y".to_string()
        );
        // Non-ASCII around a timestamp must not break the scan.
        assert_eq!(
            mask_timestamps("héllo 2026-01-01T00:00:00Z ✓", threshold),
            "héllo <time> ✓".to_string()
        );
    }

    #[test]
    fn described_times_are_masked_by_the_same_rule() {
        let threshold = 1_700_000_000;
        let fresh = describe_time(&Some(GoTime {
            unix_seconds: 1_800_000_000,
            nanos: 5,
            offset_seconds: 3600,
        }));
        assert_eq!(
            mask_times_with(&fresh, threshold),
            Value::String("<time>".into())
        );
        let scripted = describe_time(&Some(GoTime {
            unix_seconds: 1_700_000_000,
            nanos: 250_000_000,
            offset_seconds: 0,
        }));
        // Exactly at the threshold is still the store's, which is the rule the
        // generator states.
        assert_eq!(
            mask_times_with(&scripted, threshold),
            Value::String("<time>".into())
        );
        let old = describe_time(&Some(GoTime {
            unix_seconds: 1_000_000_000,
            nanos: 0,
            offset_seconds: 0,
        }));
        assert_eq!(
            mask_times_with(&old, threshold),
            old,
            "a scripted instant must survive"
        );
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_new_history_file_is_not_group_writable() {
        // Go hands `os.OpenFile` 0o644. With no mode at all the file is created
        // 0o666 & ~umask, so under `umask 002` -- the default on many distros -- the
        // whole session history lands group-writable where Go's is not. Asserted as
        // "no write bit outside the owner, and no bit Go would not set" rather than as
        // a literal 0644, because the create mode is umask-masked in Go too; the
        // umask-independent half is the meta, and that is the child test below.
        let dir = temp_dir("mode-jsonl");
        let store = Store::new(&dir).unwrap();
        store.add_message("agent:main:mode", "user", "hi").unwrap();
        let (jsonl, meta) = store.paths_for("agent:main:mode");

        let jsonl_mode = mode_of(&jsonl);
        assert_eq!(
            jsonl_mode & 0o022,
            0,
            "group- or other-writable history: {jsonl_mode:o}"
        );
        assert_eq!(
            jsonl_mode | 0o644,
            0o644,
            "bits Go never sets: {jsonl_mode:o}"
        );
        assert_eq!(
            mode_of(&meta),
            0o644,
            "the meta is chmodded, not merely created"
        );
    }

    #[test]
    #[ignore = "run through the two `modes_under_umask_*` tests; needs its own process"]
    fn umask_child() {
        // The discriminating half, and it needs a umask the parent cannot set for one
        // thread. The parent says which umask it applied by handing over the two modes Go
        // would produce under it:
        //
        //   * the meta is chmodded *after* the write by `WriteFileAtomic`, so it is 0644
        //     whatever the umask;
        //   * the history file only *requests* a create mode, exactly as Go's
        //     `os.OpenFile` does, so it follows the umask: 0644 & ~umask;
        //   * the directory comes from `os.MkdirAll(dir, 0o755)`, so it follows the
        //     umask too but from 0755, not 0777: 0755 & ~umask.
        //
        // Under `umask 077` the two must disagree (0600 beside 0644) -- a port that chmods
        // both, or neither, fails here. Under `umask 002` the history file must still be
        // 0644, which is what a missing `.mode(0o644)` breaks: 0o666 & ~002 is 0664, a
        // group-writable session log. That second one is invisible at the ambient umask,
        // which is why the umask is set rather than read. The directory is discriminated
        // the same way: `fs::create_dir_all` gives 0775 at 002 where Go gives 0755, and
        // the two agree at the ambient 022.
        let expect = |var: &str| -> u32 {
            u32::from_str_radix(&std::env::var(var).unwrap(), 8)
                .unwrap_or_else(|e| panic!("{var}: {e}"))
        };
        // The store has to create this one itself -- `temp_dir` would make it at
        // `0o777 & ~umask` and the assertion would measure the harness.
        let dir = temp_dir(&format!("mode-{}", expect("CRAB_EXPECT_JSONL"))).join("store");
        let store = Store::new(&dir).unwrap();
        store.add_message("agent:main:umask", "user", "hi").unwrap();
        let (jsonl, meta) = store.paths_for("agent:main:umask");
        assert_eq!(
            mode_of(&meta),
            expect("CRAB_EXPECT_META"),
            "the meta is chmodded, not merely created"
        );
        assert_eq!(
            mode_of(&jsonl),
            expect("CRAB_EXPECT_JSONL"),
            "Go's OpenFile mode is umask-masked"
        );
        assert_eq!(
            mode_of(&dir),
            expect("CRAB_EXPECT_DIR"),
            "Go's MkdirAll passes 0o755, not 0o777"
        );
    }

    fn modes_under_umask(umask: &str, jsonl: &str, meta: &str, dir: &str) {
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "umask {umask} && CRAB_EXPECT_JSONL={jsonl} CRAB_EXPECT_META={meta} \
                 CRAB_EXPECT_DIR={dir} exec \
                 '{}' --ignored --exact --nocapture tests::umask_child",
                exe.display()
            ))
            .output()
            .expect("sh");
        let stdout = String::from_utf8_lossy(&out.stdout);
        // An ignored test is *filtered out* rather than run, and a filtered-out run exits
        // 0. Without this the child would prove nothing and the parent would pass -- which
        // is exactly how the first version of this test passed while running zero tests.
        assert!(
            stdout.contains("1 passed"),
            "umask {umask}: the child did not report a passing run. A filtered-out test \
             exits 0 and prints nothing, and a failing one prints its panic instead of \
             \"1 passed\", so both land here:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "umask {umask}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn modes_under_umask_077() {
        modes_under_umask("077", "600", "644", "700");
    }

    #[test]
    fn modes_under_umask_002() {
        // The case the review reproduced: without a create mode the history file lands
        // 0664 here, and the ambient umask on most machines is 022, where it would not.
        modes_under_umask("002", "644", "644", "755");
    }

    #[test]
    fn one_instant_stamps_the_message_and_the_meta_together() {
        // Go takes one `now` in `addMsg` and uses it for all three stamps. Three calls
        // differ in the nanoseconds; the corpus mask hides that today, so nothing but a
        // unit test says the port kept the single instant.
        let dir = temp_dir("one-now");
        let store = Store::new(&dir).unwrap();
        store.add_message("agent:main:now", "user", "hi").unwrap();
        let (jsonl, meta) = store.paths_for("agent:main:now");

        let msg: serde_json::Value = serde_json::from_str(&read(&dir, &file_name(&jsonl))).unwrap();
        let meta_v: serde_json::Value =
            serde_json::from_str(&read(&dir, &file_name(&meta))).unwrap();
        let stamped = msg["created_at"].as_str().unwrap().to_string();
        assert_eq!(
            stamped,
            meta_v["updated_at"].as_str().unwrap(),
            "one instant"
        );
    }

    #[test]
    fn a_populated_meta_never_gets_a_created_at() {
        // Go's guard is `meta.Count == 0 && meta.CreatedAt.IsZero()`. A meta with
        // `count > 0` and no `created_at` therefore stays at year 1 forever; stamping it
        // here is a file-byte difference the corpus cannot see until a write follows a
        // raw meta, which no scripted case does yet.
        let dir = temp_dir("count-guard");
        let store = Store::new(&dir).unwrap();
        let (jsonl, meta_path) = store.paths_for("s1");
        fs::write(
            &meta_path,
            r#"{"key":"s1","count":5,"skip":0,"created_at":"0001-01-01T00:00:00Z","updated_at":"0001-01-01T00:00:00Z"}"#,
        )
        .unwrap();

        store.add_message("s1", "user", "hi").unwrap();
        let meta_text = fs::read_to_string(&meta_path).unwrap();
        assert!(
            meta_text.contains(r#""created_at": "0001-01-01T00:00:00Z""#),
            "Go leaves the year-1 stamp alone: {meta_text}"
        );
        assert!(
            meta_text.contains(r#""count": 6"#),
            "the count still moves: {meta_text}"
        );
        let _: &Path = jsonl.as_path();
    }

    #[test]
    fn duplicate_case_variants_resolve_in_document_order() {
        // Go's decoder walks the object in source order and takes the last occurrence.
        // Sorting the field names to make a HashMap deterministic instead resolves
        // `{"key":...,"KEY":...}` alphabetically, which is a different field.
        let meta = SessionMeta::decode(br#"{"key":"first","KEY":"second"}"#).unwrap();
        assert_eq!(meta.key, "second", "document order, not alphabetical");

        let flipped = SessionMeta::decode(br#"{"KEY":"second","key":"first"}"#).unwrap();
        assert_eq!(
            flipped.key, "first",
            "the same two names, reversed, flip the answer"
        );
    }

    fn file_name(path: &Path) -> String {
        path.file_name().unwrap().to_string_lossy().into_owned()
    }

    use std::io::Write;
}
