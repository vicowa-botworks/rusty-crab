//! Replays the memory-store fixtures against this crate.
//!
//! This seam is different from the other three: a case is not one call but a
//! *script* of store calls, and the expectation is the directory the script left
//! behind plus every query it issued. So the unit of comparison is a whole run,
//! and a failure says "the files diverged" or "a query answered differently",
//! never "a function returned the wrong number".
//!
//! Two things are deliberately not done here.
//!
//! * The harness never computes a file name. `write_raw` and `write_raw_meta`
//!   find the stem by reading the `.meta.json` files back, exactly as the
//!   generator's `stemFor` does, because the filename cases exist to make the
//!   port discover the key→name mapping from the store's behaviour. A harness
//!   that called [`crab_memory::sanitize_key`] itself could agree with a wrong
//!   implementation and never notice.
//! * An error is recorded as the *name of the op that refused*, not its message.
//!   Go's error text wraps `os.PathError` sentences that are not portable, and
//!   pinning them would force this crate to reproduce a sentence rather than the
//!   behaviour that matters: that the call is refused, at that step, leaving the
//!   directory in the state the fixture shows.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use conformance::{Fixture, Report};
use crab_memory::{
    describe_message, describe_meta, describe_strings, mask_times, snapshot_dir, Store,
};
use crab_protocoltypes::{format_rfc3339_nano, unmarshal, Message};
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[test]
fn store_scripts_leave_what_go_left() {
    let fixture = Fixture::load("memory_jsonl_store.json");
    let mut report = Report::new(&fixture);

    for case in &fixture.cases {
        let input: FixtureScript = case.parse();
        report.record(case, run_script(&case.name, &input.ops));
    }

    report.finish(8);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureScript {
    ops: Vec<Op>,
}

/// One scripted call. Every field any op can emit is present so
/// `deny_unknown_fields` catches a generator that starts describing something
/// new; an op that ignores a field it was never given is caught by the
/// `unknown op` arm below instead.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Op {
    op: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    message: Option<Value>,
    #[serde(default)]
    messages: Option<Vec<Value>>,
    #[serde(default)]
    keep_last: Option<i64>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    aliases: Option<Vec<String>>,
}

impl Op {
    fn key(&self) -> &str {
        self.key
            .as_deref()
            .unwrap_or_else(|| panic!("op {} needs a key", self.op))
    }
}

/// Runs one script and returns the `{files, results}` shape the fixture holds, or
/// `{files, results, error}` when a step refuses.
fn run_script(name: &str, ops: &[Op]) -> Value {
    let dir = temp_dir(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{name}: temp dir: {e}"));

    let store = Store::new(&dir);
    // Key -> stem, learned from disk. Cached across the script because a case may
    // corrupt the .meta.json and still need to address the session afterwards.
    let mut stems: HashMap<String, String> = HashMap::new();
    let mut results: Vec<Value> = Vec::new();
    let mut outcome: Option<Value> = None;

    for (index, op) in ops.iter().enumerate() {
        let step = run_op(&store, &dir, op, &mut stems);
        // A query's value is appended only once the step has succeeded: Go's
        // runner does the same, so a refused query records the refusal and not
        // the zero value Go happened to return beside it.
        let query = match &step {
            Ok(Some(value)) => Some(value.clone()),
            Ok(None) => None,
            Err(_) => None,
        };
        if let Err(why) = step {
            // The fixture pins the op, not the sentence; the message goes to
            // stderr so a failure can still be traced without changing what is
            // compared.
            eprintln!("{} step {} refused: {why}", name, op.op);
            outcome = Some(json!(op.op));
            break;
        }
        if let Some(value) = query {
            results.push(json!({"op_index": index, "op": op.op, "value": value}));
        }
    }

    let files = snapshot_dir(&dir);
    let masked: Vec<Value> = results
        .iter()
        .map(|entry| {
            let mut entry = entry.clone();
            let value = entry
                .get_mut("value")
                .expect("a recorded query has a value");
            *value = mask_times(value);
            entry
        })
        .collect();

    let mut expected = Map::new();
    expected.insert("files".into(), Value::Object(files));
    expected.insert("results".into(), Value::Array(masked));
    if let Some(op_name) = outcome {
        expected.insert("error".into(), op_name);
    }

    let _ = fs::remove_dir_all(&dir);
    Value::Object(expected)
}

/// Performs one step. `Ok(Some(_))` is a query, `Ok(None)` a mutation, and
/// `Err(op)` is the store refusing -- the op name, never the message.
fn run_op(
    store: &Store,
    dir: &Path,
    op: &Op,
    stems: &mut HashMap<String, String>,
) -> Result<Option<Value>, String> {
    match op.op.as_str() {
        "add" => {
            let mut msg = message_from_described(described(op, "message")?)
                .map_err(|e| format!("add: {e}"))?;
            store
                .add_full_message(op.key(), &mut msg)
                .map(|()| None)
                .map_err(|e| e.to_string())
        }
        "add_simple" => store
            .add_message(
                op.key(),
                op.role.as_deref().unwrap_or_default(),
                op.content.as_deref().unwrap_or_default(),
            )
            .map(|()| None)
            .map_err(|e| e.to_string()),
        "truncate" => store
            .truncate_history(op.key(), op.keep_last.unwrap_or(0))
            .map(|()| None)
            .map_err(|e| e.to_string()),
        "set_history" => {
            let described = op.messages.clone().unwrap_or_default();
            let mut history = Vec::with_capacity(described.len());
            for m in &described {
                history.push(message_from_described(m).map_err(|e| format!("set_history: {e}"))?);
            }
            store
                .set_history(op.key(), &history)
                .map(|()| None)
                .map_err(|e| e.to_string())
        }
        "compact" => store
            .compact(op.key())
            .map(|()| None)
            .map_err(|e| e.to_string()),
        "set_summary" => store
            .set_summary(op.key(), op.summary.as_deref().unwrap_or_default())
            .map(|()| None)
            .map_err(|e| e.to_string()),
        "upsert_meta" => {
            // An empty scope in the script means Go's nil RawMessage, which the
            // generator describes as null; the two are the same instruction.
            let scope = op.scope.clone().filter(|s| !s.is_empty());
            store
                .upsert_session_meta(op.key(), scope.map(String::into_bytes), op.aliases.clone())
                .map(|()| None)
                .map_err(|e| e.to_string())
        }
        "promote_alias" => {
            let scope = op.scope.clone().filter(|s| !s.is_empty());
            store
                .promote_alias_history(op.key(), scope.map(String::into_bytes), op.aliases.clone())
                .map(|promoted| Some(json!(promoted)))
                .map_err(|e| e.to_string())
        }
        "write_file" => {
            let name = op.name.clone().unwrap_or_default();
            fs::write(dir.join(&name), op.content.as_deref().unwrap_or_default())
                .map(|()| None)
                .map_err(|e| e.to_string())
        }
        "write_raw" | "write_raw_meta" => {
            let stem = stem_for(store, dir, op.key(), stems)
                .ok_or_else(|| format!("no session on disk for key {:?}", op.key()))?;
            let suffix = if op.op == "write_raw" {
                ".jsonl"
            } else {
                ".meta.json"
            };
            fs::write(
                dir.join(stem + suffix),
                op.content.as_deref().unwrap_or_default(),
            )
            .map(|()| None)
            .map_err(|e| e.to_string())
        }
        "get_history" => store
            .get_history(op.key())
            .map(|msgs| Some(Value::Array(msgs.iter().map(describe_message).collect())))
            .map_err(|e| e.to_string()),
        "get_meta" => store
            .get_session_meta(op.key())
            .map(|meta| Some(describe_meta(&meta)))
            .map_err(|e| e.to_string()),
        "list_all" => Ok(Some(describe_strings(&store.list_sessions()))),
        other => panic!("unknown op {other:?}"),
    }
}

fn described<'a>(op: &'a Op, field: &str) -> Result<&'a Value, String> {
    match (field, &op.message) {
        ("message", Some(v)) => Ok(v),
        _ => Err(format!("{}: missing {field}", op.op)),
    }
}

/// `stemFor`: asks the store, through the files on disk, which stem a key maps
/// to. Never creates anything.
fn stem_for(
    store: &Store,
    dir: &Path,
    key: &str,
    stems: &mut HashMap<String, String>,
) -> Option<String> {
    if let Some(stem) = stems.get(key) {
        return Some(stem.clone());
    }
    // SessionMeta.Key holds the canonical key, so after `add a:b` a raw write
    // addressed as the alias `a/b` still finds the one session both names.
    let mut canonical = key.to_string();
    if let Ok(meta) = store.get_session_meta(key) {
        if !meta.key.is_empty() {
            canonical = meta.key.clone();
        }
    }
    let stem = find_stem_by_key(dir, &canonical)?;
    stems.insert(key.to_string(), stem.clone());
    stems.insert(canonical, stem.clone());
    Some(stem)
}

fn find_stem_by_key(dir: &Path, key: &str) -> Option<String> {
    // os.ReadDir hands back names sorted; fs::read_dir does not, and the first
    // match wins, so the order has to be pinned here or two alias files could
    // resolve differently on two runs.
    let mut names: Vec<String> = fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            (!e.path().is_dir() && name.ends_with(".meta.json")).then_some(name)
        })
        .collect();
    names.sort();
    for name in names {
        let Ok(data) = fs::read(dir.join(&name)) else {
            continue;
        };
        let Ok(meta) = crab_memory::SessionMeta::decode(&data) else {
            continue;
        };
        if meta.key == key {
            return Some(name.trim_end_matches(".meta.json").to_string());
        }
    }
    None
}

/// Turns a described message back into the wire JSON the store reads.
///
/// The description carries the three `json:"-"` fields, which the generator sets
/// to sentinels precisely so a leak would show. They are dropped here the way
/// Go's decoder drops them, and that is what makes the round trip prove
/// something: a port that wrote `prompt_layer` to disk would read back "PL"
/// where the fixture says `""`.
///
/// `created_at` is the one field whose described form is not its wire form: the
/// fixture holds `{unix_seconds, nanos, offset_seconds}` so a nanosecond cannot
/// be lost through a string, and the store reads an RFC3339 stamp.
fn message_from_described(value: &Value) -> Result<Message, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "a described message is an object".to_string())?
        .clone();
    let mut wire = Map::new();
    for (name, field) in object {
        match name.as_str() {
            "prompt_layer" | "prompt_slot" | "prompt_source" => {}
            "created_at" => {
                if field.is_null() {
                    continue;
                }
                let t = field
                    .as_object()
                    .ok_or_else(|| "created_at is neither null nor a described time".to_string())?;
                let text = format_rfc3339_nano(
                    t["unix_seconds"].as_i64().unwrap_or_default(),
                    u32::try_from(t["nanos"].as_u64().unwrap_or_default()).unwrap_or_default(),
                    i32::try_from(t["offset_seconds"].as_i64().unwrap_or_default())
                        .unwrap_or_default(),
                )
                .map_err(|e| e.to_string())?;
                wire.insert(name, Value::String(text));
            }
            _ => {
                wire.insert(name, field);
            }
        }
    }
    let bytes = serde_json::to_vec(&Value::Object(wire)).map_err(|e| e.to_string())?;
    unmarshal::message(&bytes).map_err(|e| e.to_string())
}

/// A directory per case, named after it so a failure on disk is traceable to the
/// case without rerunning the suite under a debugger.
fn temp_dir(case: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "crab-memory-oracle-{case}-{n}-{}",
        std::process::id()
    ))
}
