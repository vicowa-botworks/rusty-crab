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
    let dir = scratch_dir(case);
    let home = "/home/oracle";
    let schema = config_schema();
    let mut results = Vec::new();
    let mut error_op_index: Option<usize> = None;

    for (index, op) in ops.iter().enumerate() {
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
/// The three that remain are not loader work. `InitChannelList` is ported (see
/// [`crab_config`]'s `channels` module) and closed `load_current_version_minimal` on its
/// own, which is the proof that the typed-settings decode was the only gap on the
/// load-only side. What these three need is what `LoadConfig` *writes* when it migrates:
/// `SaveConfig` defers to the last `case 0..=2` arm, so a migration leaves three files
/// behind -- the migrated `config.json`, a `.security.yml` carrying each channel type's
/// `settings: {}`, and `config.json.<date>.bak` with the original bytes -- and this crate
/// does not implement `save` yet. `saveSecurityConfig` is reached from `SaveConfig`
/// (`config.go:1691`), so the same work also unblocks the ten cases the harness defers
/// outright for using `save`.
const KNOWN_UNPORTED: &[&str] = &[
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
    let mut matched = 0;

    for case in &fixture.cases {
        let input: Script = case.parse();
        if input.ops.iter().any(|op| op.op == "save") {
            deferred.push(case.name.as_str());
            continue;
        }

        let got = run_script(&case.name, &input.ops);
        let known = KNOWN_UNPORTED.contains(&case.name.as_str());
        match (case.expected == got, known) {
            (true, false) => matched += 1,
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
        "{matched} of {} replayable cases match Go byte for byte",
        fixture.cases.len() - deferred.len(),
    );
    eprintln!(
        "known gaps (migration persistence): {}
deferred until `save` is ported ({}): {}",
        gaps.join(", "),
        deferred.len(),
        deferred.join(", ")
    );
    report.finish(8);
}
