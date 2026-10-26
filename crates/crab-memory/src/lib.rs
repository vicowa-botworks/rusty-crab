//! `pkg/memory`'s JSONL session store, byte for byte.
//!
//! This is the on-disk half of the port that users notice: a session file written
//! by picoclaw's Go build has to be readable by this one, and a file written here
//! has to be readable by Go. `conformance/fixtures/memory_jsonl_store.json` pins
//! that -- 78 scripts of store calls whose expectation is the *directory* left
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
//!
//! Concurrency is the one deliberate simplification. Go guards each session with
//! one of 64 read-write locks and the directory listing with a mutex; this module
//! is single-threaded and takes no lock, because the conformance harness runs one
//! script at a time. A runtime that shares a [`Store`] across threads needs the
//! locks added back -- the file-level atomicity (`write` then `rename`) is
//! implemented, the in-process exclusion is not.

use crab_gojson::{compact_html, indent, omit, GoMarshal, ObjectWriter};
use crab_protocoltypes::unmarshal::{self, DecodeError};
use crab_protocoltypes::{GoTime, Message};
use serde_json::{Map, Value};
use std::collections::HashMap;
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
    /// Go's `time.Time.IsZero`, which is the year-1 instant in UTC and nothing
    /// else. A file that spells out `0001-01-01T00:00:00Z` reads back as zero, so
    /// the check is on the instant, not on whether the field was present.
    #[must_use]
    fn is_zero(t: &Option<GoTime>) -> bool {
        match t {
            None => true,
            Some(t) => t.unix_seconds == -62_135_596_800 && t.nanos == 0 && t.offset_seconds == 0,
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
        let doc: Option<HashMap<String, Box<serde_json::value::RawValue>>> =
            serde_json::from_slice(bytes)
                .map_err(|e| Error::new(format!("memory: decode meta: {e}")))?;
        let Some(doc) = doc else {
            return Ok(Self::default());
        };
        // Sorted so a repeated key resolves the same way on every run; Go's decoder
        // takes the last occurrence, which HashMap's insert already did.
        let mut names: Vec<&String> = doc.keys().collect();
        names.sort();
        let mut m = Self::default();
        for name in names {
            let raw = &doc[name];
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
    /// `memory.NewJSONLStore(dir)`. Go also creates the directory; the harness
    /// hands it a temp dir that already exists, so this does not touch the disk.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Store { dir: dir.into() }
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
        if is_transient_thought(msg) {
            // A thought-only assistant message is not persisted at all: no
            // history file, no meta file. `transient_thought_creates_no_files`
            // pins that the directory stays empty rather than empty-but-present.
            return Ok(());
        }
        if msg.created_at.is_none() {
            msg.created_at = Some(now());
        }

        let (history_path, meta_path) = self.paths_for(key);
        // Marshal first: a message that cannot be encoded must not leave a
        // half-written line, and must not create the file either.
        let mut line = Vec::new();
        msg.marshal_go(&mut line)
            .map_err(|e| Error::new(format!("memory: encode message: {e}")))?;
        line.push(b'\n');

        append_bytes(&history_path, &line)?;

        let mut meta = self.read_meta(key)?;
        if SessionMeta::is_zero(&meta.created_at) {
            meta.created_at = Some(now());
        }
        meta.count += 1;
        meta.updated_at = Some(now());
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
        let history = filter_invalid_history(messages);
        let (history_path, meta_path) = self.paths_for(key);
        let mut meta = self.read_meta_file(&meta_path, key)?;
        if SessionMeta::is_zero(&meta.created_at) {
            meta.created_at = Some(now());
        }
        meta.skip = 0;
        meta.count = history.len() as i64;
        meta.updated_at = Some(now());
        self.write_meta(&meta_path, &mut meta, key)?;

        let mut stamped = history;
        for msg in &mut stamped {
            if msg.created_at.is_none() {
                msg.created_at = Some(now());
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
        let (_, meta_path) = self.paths_for(key);
        let mut meta = self.read_meta_file(&meta_path, key)?;
        if SessionMeta::is_zero(&meta.created_at) {
            meta.created_at = Some(now());
        }
        meta.summary = summary.to_string();
        meta.updated_at = Some(now());
        self.write_meta(&meta_path, &mut meta, key)
    }

    /// `UpsertSessionMeta`. `scope` is stored raw; `None` is an absent field.
    pub fn upsert_session_meta(
        &self,
        key: &str,
        scope: Option<Vec<u8>>,
        aliases: Option<Vec<String>>,
    ) -> Result<()> {
        let (_, meta_path) = self.paths_for(key);
        let mut meta = self.read_meta_file(&meta_path, key)?;
        meta.scope = scope;
        meta.aliases = normalize_aliases(key, aliases);
        if SessionMeta::is_zero(&meta.created_at) {
            meta.created_at = Some(now());
        }
        meta.updated_at = Some(now());
        self.write_meta(&meta_path, &mut meta, key)
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

    /// `Close`. Go syncs the directory; there is no handle to close here.
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
        for msg in &history {
            msg.marshal_go(&mut buf)
                .map_err(|e| Error::new(format!("memory: encode message: {e}")))?;
            buf.push(b'\n');
        }
        write_atomic(path, &buf, 0o644)
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
    fs::create_dir_all(dir)?;
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
        drop(file);
        fs::rename(&tmp, path)?;
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
        fs::create_dir_all(dir)?;
    }
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;
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
        let store = Store::new(&dir);
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
        let store = Store::new(&dir);
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
        let store = Store::new(&dir);
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
        let store = Store::new(&dir);
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
        let store = Store::new(&dir);
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
        let store = Store::new(&dir);
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
        let store = Store::new(&dir);
        store.add_message("s1", "user", "one").unwrap();
        let before = read(&dir, "s1.meta.json");
        store.compact("s1").unwrap();
        assert_eq!(before, read(&dir, "s1.meta.json"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_sorts_and_skips_unreadable_meta() {
        let dir = temp_dir("list");
        let store = Store::new(&dir);
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
        let store = Store::new(&dir);
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
        let store = Store::new(&dir);
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

    use std::io::Write;
}
