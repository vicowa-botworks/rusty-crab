//! Replays the config fixture's load-only cases against this crate.
//!
//! The seam is scripted like the memory store: a case is a list of `ops` and the
//! expectation is the directory they leave behind plus the value each `load` returned.
//! The value is compared as the *bytes Go recorded*, not as a parsed document, because
//! the whole point of this seam is that a user's existing config file loads and
//! re-serialises identically — key order, `omitzero` behaviour and the `session` shadow
//! included.
//!
//! ## Why only some cases run
//!
//! Ten of the twenty-five call `save`, and [`crab_config::save`] is a stub: the loader
//! stages it has not ported (`env.Parse`, `InitChannelList`, `expandMultiKeyModels`, the
//! two `Validate*` passes) all change what a save writes, so a replay that skipped them
//! would compare a partial pipeline against Go's full one and pass for the wrong reason.
//! Those cases are counted and named in the failure output rather than dropped silently,
//! and the `.security.yml` half of `save` is pinned directly by `security_golden.rs`,
//! which needs no loader.
//!
//! ## What a failure here means
//!
//! The comparison is byte-exact, so a failure is a real divergence, not a formatting
//! difference. When a case fails because of a stage listed above, say which stage in the
//! commit message — the fixture cannot tell "wrong" from "not implemented yet", and a
//! green run must not be read as "the loader is done".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use conformance::{Fixture, Report};
use crab_config::{config_schema, default_config, load, loaded_value};
use serde::Deserialize;
use serde_json::{json, Value};

/// One step of a case's script.
#[derive(Debug, Deserialize)]
struct Op {
    op: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Script {
    ops: Vec<Op>,
}

/// The directory a case runs in. Every case gets its own so that `migrate_backs_up_both_files`
/// cannot see another case's backups.
fn scratch_dir(case: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "crab-config-conf-{}-{n}",
        case.replace(['/', ' '], "_")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Every file in the directory, keyed by name. Read back from disk rather than from what
/// the script wrote: the expectation is what is *on disk*, and a harness that reported its
/// own writes could agree with an implementation that never touched the file.
fn snapshot(dir: &Path) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    for entry in std::fs::read_dir(dir).expect("read scratch dir") {
        let entry = entry.expect("directory entry");
        if !entry.path().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        files.insert(
            name,
            std::fs::read_to_string(entry.path()).unwrap_or_else(|_| "<binary>".to_string()),
        );
    }
    files
}

/// Runs one script and returns the value the harness compares.
///
/// A failing op stops the script and is recorded by index only, with no message: Go's
/// error sentences quote absolute paths, so pinning them would compare paths, not
/// behaviour.
fn run_script(case: &str, ops: &[Op]) -> Value {
    run_ops(case, ops, false)
}

/// The same script, stopped at its first `save`.
///
/// A case that saves is deferred whole because its `expected` holds files this crate
/// cannot write yet -- and deferring it whole used to defer its `load` values with it.
/// That is backwards: the loads are replayable today, and they are the only recorded
/// witness of what the loader does with a `.security.yml`, which is what most of those
/// cases were written to show.
fn run_prefix(case: &str, ops: &[Op]) -> Value {
    run_ops(case, ops, true)
}

fn run_ops(case: &str, ops: &[Op], stop_at_save: bool) -> Value {
    let dir = scratch_dir(case);
    let home = "/home/oracle";
    let schema = config_schema();
    let mut results = Vec::new();
    let mut error_op_index: Option<usize> = None;

    for (index, op) in ops.iter().enumerate() {
        if stop_at_save && op.op == "save" {
            break;
        }
        match op.op.as_str() {
            "defaults" => {
                results.push(json!({"op": op.op, "op_index": index, "value": loaded_value(&default_config(home), &schema)}));
            }
            "write_file" => {
                let name = op.name.clone().expect("write_file names a file");
                std::fs::write(
                    dir.join(&name),
                    op.content.clone().expect("write_file carries content"),
                )
                .expect("seed the scratch dir");
            }
            "load" => {
                let name = op.name.clone().expect("load names a file");
                match load(&dir.join(&name), home) {
                    Ok(cfg) => results.push(json!({
                        "op": op.op,
                        "op_index": index,
                        "value": loaded_value(&cfg.document, &schema),
                    })),
                    Err(_) => {
                        error_op_index = Some(index);
                        break;
                    }
                }
            }
            other => panic!("case {case} uses an op this harness does not know: {other}"),
        }
    }

    let files = serde_json::to_value(snapshot(&dir)).expect("files are serialisable");
    let mut got = json!({"files": files, "results": results});
    if let Some(index) = error_op_index {
        got["error_op_index"] = json!(index);
    }
    let _ = std::fs::remove_dir_all(&dir);
    got
}

/// Cases that replay today and disagree with Go for one known reason.
///
/// This is not a skip list. Every entry here is still executed and still compared; what
/// it asserts is that the case fails *and* that nothing else does. A case that starts
/// matching Go fails the test with its name in the message, so the list cannot quietly
/// outlive the gap, and a new divergence fails it too.
///
/// All four have the same cause, so one stage closes all four: `InitChannelList`
/// (`config_channel.go:728`) decodes each channel's `settings` into the typed struct for
/// that channel's `type` and the loaded value then marshals the struct, not the stored
/// JSON. So Go emits every field of `TelegramSettings` -- `{"base_url":"","proxy":"",
/// "use_markdown_v2":false,"media_group_delay_ms":500}` -- where this crate echoes the
/// two keys the default table happens to carry, and writes no `settings` key at all for a
/// channel like `dingtalk` whose entry is empty. The per-type field lists are in the
/// schema dump as `settings_schemas` (22 types), which is why the gap is portable and not
/// merely unknown.
const KNOWN_UNPORTED: &[&str] = &[
    "load_current_version_minimal",
    "migrate_v0_api_key_becomes_api_keys",
    "migrate_v1_channels_renamed",
    "migrate_v2_channels_to_channel_list",
];

#[test]
fn loading_matches_what_go_returned() {
    let fixture = Fixture::load("config_load_save.json");
    let mut report = Report::new(&fixture);
    let mut deferred: Vec<&str> = Vec::new();
    let mut gaps: Vec<&str> = Vec::new();
    let mut prefix_checked = 0usize;
    let mut prefix_failed: Vec<String> = Vec::new();

    for case in &fixture.cases {
        let input: Script = case.parse();
        if let Some(first_save) = input.ops.iter().position(|op| op.op == "save") {
            // The whole script is out of reach until `save` is ported, but every recorded
            // load before that save is not. Compare those, so a deferred case still
            // witnesses the loader.
            let got = run_prefix(&case.name, &input.ops);
            let produced = got["results"].as_array().expect("results are an array");
            let gaps = KNOWN_LOAD_GAPS
                .iter()
                .find(|(name, _)| *name == case.name.as_str())
                .map(|(_, gaps)| *gaps)
                .unwrap_or_else(|| {
                    panic!(
                        "{} is deferred for a `save` but is not in KNOWN_LOAD_GAPS, so its \
                         load-side values are unaccounted for. Add it, naming the stages \
                         that explain any difference (an empty list if none does).",
                        case.name
                    )
                });
            let want = case.expected["results"]
                .as_array()
                .expect("a scripted case records its results");
            for entry in want.iter().filter(|r| {
                r["op_index"]
                    .as_u64()
                    .is_some_and(|i| i < first_save as u64)
            }) {
                let index = entry["op_index"].as_u64().expect("op_index is a number");
                prefix_checked += 1;
                let recorded = entry["value"].as_str().unwrap_or_default();
                let Some(produced) = produced
                    .iter()
                    .find(|r| r["op_index"].as_u64() == Some(index))
                    .and_then(|r| r["value"].as_str())
                else {
                    prefix_failed.push(format!(
                        "{} op {index}: this crate produced no value",
                        case.name
                    ));
                    continue;
                };
                let (want_doc, got_doc) = (document(recorded), document(produced));
                if want_doc == got_doc {
                    if !gaps.is_empty() {
                        panic!(
                            "{} op {index} now matches Go exactly. Drop a label from \
                             KNOWN_LOAD_GAPS -- a stage listed there that no longer explains \
                             anything is a lie about what is still unported.",
                            case.name
                        );
                    }
                    continue;
                }
                if stripped(&want_doc, gaps) != stripped(&got_doc, gaps) {
                    prefix_failed.push(format!(
                        "{} op {index} differs for a reason outside {}\n    go:   {}\n    rust: {}",
                        case.name,
                        gaps.join(" + "),
                        truncate(recorded),
                        truncate(produced),
                    ));
                    continue;
                }
                // Every named stage has to be load-bearing, or the table is a list of
                // excuses rather than a list of gaps.
                for (position, label) in gaps.iter().enumerate() {
                    let fewer: Vec<&str> = gaps
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != position)
                        .map(|(_, gap)| *gap)
                        .collect();
                    if stripped(&want_doc, &fewer) == stripped(&got_doc, &fewer) {
                        prefix_failed.push(format!(
                            "{} op {index}: `{label}` in KNOWN_LOAD_GAPS explains nothing here",
                            case.name
                        ));
                    }
                }
            }
            deferred.push(case.name.as_str());
            continue;
        }

        let got = run_script(&case.name, &input.ops);
        let known = KNOWN_UNPORTED.contains(&case.name.as_str());
        match (case.expected == got, known) {
            // Recorded, not just counted. A success that never reaches the Report leaves
            // `passed` at zero, and the summary line then reads "0 of 96 cases match" on
            // a run where every case matched -- a number that looks like the seam is
            // broken when it is the counter that is.
            (true, false) => report.record(case, got),
            (true, true) => panic!(
                "{} now matches Go. Remove it from KNOWN_UNPORTED -- a case on that list \
                 that passes is a lie about what is still missing.",
                case.name
            ),
            (false, true) => gaps.push(case.name.as_str()),
            (false, false) => report.record(case, got),
        }
    }

    for name in KNOWN_UNPORTED {
        assert!(
            gaps.contains(name),
            "{name} is on KNOWN_UNPORTED but was not replayed -- it was renamed, or it \
             started needing `save`."
        );
    }

    // Printed before `finish`, which panics on the first disagreement: these two lines are
    // what a reader needs most, and they must not be the part that gets lost.
    eprintln!(
        "{} of {} replayable cases match Go byte for byte",
        report.passed(),
        fixture.cases.len() - deferred.len(),
    );
    eprintln!(
        "known gaps (InitChannelList): {}
deferred until `save` is ported ({}): {}",
        gaps.join(", "),
        deferred.len(),
        deferred.join(", ")
    );
    eprintln!(
        "load values replayed out of the deferred cases: {prefix_checked} compared, {} disagree \
         for a reason outside the stages KNOWN_LOAD_GAPS names",
        prefix_failed.len()
    );
    for failure in &prefix_failed {
        eprintln!("  {failure}");
    }
    report.finish(8);
    assert!(
        prefix_failed.is_empty(),
        "{} of the {} load values recorded before a deferred `save` disagree with Go for a \
         reason outside the stages KNOWN_LOAD_GAPS names",
        prefix_failed.len(),
        prefix_checked
    );
}

/// A recorded loaded value as a document. Something that is not JSON compares as its text.
fn document(value: &str) -> Value {
    serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.into()))
}

/// The unported stages a deferred case's recorded `load` is allowed to differ by.
///
/// A case that saves is deferred whole, which used to defer its `load` values with it --
/// so the ten save cases witnessed nothing at all about the loader, even though every load
/// in them is replayable today. They are replayed now, and this table is what keeps that
/// honest: each case names the stages that explain any difference, and the harness checks
/// that every named stage is *load-bearing*. A stage that stops mattering fails the run,
/// exactly like a case that leaves `KNOWN_UNPORTED` stale.
const KNOWN_LOAD_GAPS: &[(&str, &[&str])] = &[
    ("save_writes_the_document", &["channel_settings"]),
    ("save_bumps_an_old_version", &["channel_settings"]),
    ("session_omitted_when_empty", &["channel_settings"]),
    ("migrate_backs_up_both_files", &["channel_settings"]),
    (
        "unparseable_security_file_is_refused",
        &["channel_settings"],
    ),
    (
        "security_entry_replaces_the_json_model",
        &["channel_settings"],
    ),
    ("security_seq_form_is_refused", &["channel_settings"]),
    ("save_writes_both_halves", &["channel_settings"]),
    (
        "virtual_key_models_are_written_back_once",
        &["channel_settings", "model_list"],
    ),
    (
        "save_then_load_then_save_is_stable",
        &["channel_settings", "model_list"],
    ),
];

/// Removes what one unported stage is responsible for.
///
/// Every label is a *laxness*: stripping can only make a comparison easier to pass. So a
/// match here is proof that nothing beyond the named stages is wrong, never proof that the
/// loader is right -- which is the same bargain `KNOWN_UNPORTED` strikes, per case rather
/// than per whole script.
fn strip_gap(label: &str, value: &mut Value) {
    match label {
        // `InitChannelList` is not ported. Go marshals each channel's *settings struct*,
        // so untagged and zero-valued fields appear and a `SecureString` inside them does
        // not; the three telegram values this crate's `defaults.rs` adds land in the same
        // three keys.
        "channel_settings" => {
            if let Some(channels) = value.get_mut("channel_list").and_then(Value::as_object_mut) {
                for channel in channels.values_mut() {
                    if let Some(fields) = channel.as_object_mut() {
                        for key in ["settings", "typing", "placeholder"] {
                            fields.remove(key);
                        }
                    }
                }
            }
        }
        // `expandMultiKeyModels` is not ported: Go turns one model holding two keys into
        // `m1__key_1` and `m1__key_2`, so the list itself is a different length and a
        // per-field strip cannot express it.
        "model_list" => {
            if let Some(fields) = value.as_object_mut() {
                fields.remove("model_list");
            }
        }
        other => panic!("{other} is not a gap this harness knows how to strip"),
    }
}

/// Both sides with `gaps` removed, ready to compare.
fn stripped(value: &Value, gaps: &[&str]) -> Value {
    let mut copy = value.clone();
    for gap in gaps {
        strip_gap(gap, &mut copy);
    }
    copy
}

/// Enough of a loaded value to tell one from another in a failure line.
fn truncate(value: &str) -> String {
    const MAX: usize = 240;
    let mut end = MAX.min(value.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    if end == value.len() {
        return value.to_string();
    }
    format!("{}…", &value[..end])
}
