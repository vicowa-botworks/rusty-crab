//! Replays the config fixture's load-only cases against this crate.
//!
//! The seam is scripted like the memory store: a case is a list of `ops` and the
//! expectation is the directory they leave behind plus the value each `load` returned.
//! The value is compared as the *bytes Go recorded*, not as a parsed document, because
//! the whole point of this seam is that a user's existing config file loads and
//! re-serialises identically — key order, `omitzero` behaviour and the `session` shadow
//! included.
//!
//! ## Every case runs
//!
//! `KNOWN_UNPORTED` is empty and nothing is deferred: the ten `save` cases and the three
//! `migrate_*` cases that used to sit here went green when [`crab_config::save`] and the
//! migration's own persistence landed. The list is kept rather than deleted because it is
//! the crate's own statement of what is missing, and the assertion below is what keeps it
//! honest — a name that outlives its gap hides the next one.
//!
//! ## What a failure here means
//!
//! The comparison is byte-exact, so a failure is a real divergence, not a formatting
//! difference.
//!
//! ## Faults the corpus cannot see
//!
//! A green replay is only evidence that the recorded bytes match. The save, backup and
//! migration path was therefore mutated fault by fault, and six faults walked through
//! 53/53. They are recorded here rather than left as a green run, because "the corpus does
//! not catch it" and "the behaviour does not matter" are different claims:
//!
//! * `SaveConfig`'s own `version` bump. Unreachable through `load`, because every version
//!   below the current one either migrates (which sets it) or errors. Defence in depth,
//!   like the `registries` name skip in the legacy skills pass.
//! * The deferred restore of the unfiltered model list. Visible only to a caller that
//!   keeps using the same `*Config` after a save; the corpus re-reads from disk.
//! * `MakeBackup`'s missing-file short-circuit. The file always exists after a successful
//!   load, so no case can reach it.
//! * A virtual entry's `api_keys`. The entry itself is filtered out of both files, so what
//!   it carries is invisible from outside the process.
//! * `enabled` on a generated entry. Go's copy does not name the field, but keeping it
//!   changes no bytes either, because `omitempty` drops `false`.
//! * The ladder's `clawhub` to `registries` rewrite. Redundant with the security pass that
//!   runs after it on the same file.
//!
//! Six *other* survivors were real corpus gaps and are not equivalents: a security
//! `model_list` entry that exists without `api_keys` (Go clears the model's keys); one
//! carrying a real model field such as `provider`; a `channel_list` settings node that
//! differs from the defaults; a `channel_list` naming a channel the config does not have;
//! a legacy `skills.github.token` reaching the migration pre-merge, where the plaintext
//! duplicate is unpinned; and a security file holding both `tools:` and `web:`, the only
//! shape where Go's `m2["tools"] = m3` assignment differs from a merge. Each needs a
//! Go-side case before the Rust side may be said to hold.

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
        let name = mask_backup_date(&entry.file_name().to_string_lossy());
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
    // Bytes each `save` wrote, per file name, so a case that saves twice can say whether
    // the second save produced the same document. Go's harness records the same map, and
    // `save_stable` is derived from it in the fixture rather than asserted here: a config
    // that drifts a little on every save is the failure mode this seam exists to catch,
    // and the port is graded on reproducing the verdict either way.
    let mut saves: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut loaded: Option<crab_config::Config> = None;

    for (index, op) in ops.iter().enumerate() {
        match op.op.as_str() {
            "defaults" => {
                let document = default_config(home);
                results.push(json!({"op": op.op, "op_index": index, "value": loaded_value(&document, &schema)}));
                loaded = Some(crab_config::Config {
                    document,
                    needs_version_bump: false,
                    virtual_models: Vec::new(),
                });
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
                    Ok(cfg) => {
                        results.push(json!({
                            "op": op.op,
                            "op_index": index,
                            "value": loaded_value(&cfg.document, &schema),
                        }));
                        loaded = Some(cfg);
                    }
                    Err(_) => {
                        error_op_index = Some(index);
                        break;
                    }
                }
            }
            "save" => {
                // Go's harness refuses a save with nothing loaded, because a harness that
                // manufactures the thing a case is named for cannot pin its absence. Same
                // rule here: panic rather than write a default config.
                let cfg = loaded.as_mut().unwrap_or_else(|| {
                    panic!("case {case} saves at op {index} without loading one")
                });
                let name = op.name.clone().expect("save names a file");
                match crab_config::save(&dir.join(&name), cfg, home) {
                    Ok(_) => {
                        if let Ok(text) = std::fs::read_to_string(dir.join(&name)) {
                            saves.entry(name).or_default().push(text);
                        }
                    }
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
    if let Some(verdict) = save_stable(&saves) {
        got["save_stable"] = json!(verdict);
    }
    let _ = std::fs::remove_dir_all(&dir);
    got
}

/// Go's `saveIsStable`: the question is asked only when one file was saved twice, and
/// `stable` is vacuously true when it was not -- so `None` here means "not asked", which
/// is the fixture's absence of the key rather than `false`.
fn save_stable(saves: &BTreeMap<String, Vec<String>>) -> Option<bool> {
    let mut asked = false;
    for writes in saves.values() {
        if writes.len() < 2 {
            continue;
        }
        asked = true;
        if writes[1..].iter().any(|w| *w != writes[0]) {
            return Some(false);
        }
    }
    asked.then_some(true)
}

/// The generator masks the eight date digits of a `MakeBackup` suffix, because a case
/// that recorded the real date would disagree with itself after midnight. Same mask here,
/// or a correct backup name would read as a divergence.
fn mask_backup_date(name: &str) -> String {
    const SUFFIX: &str = ".bak";
    let Some(stem) = name.strip_suffix(SUFFIX) else {
        return name.to_string();
    };
    let digits = stem.rsplit('.').next().unwrap_or_default();
    if digits.len() == 8 && digits.bytes().all(|b| b.is_ascii_digit()) {
        let head = &stem[..stem.len() - 9];
        return format!("{head}.<date>{SUFFIX}");
    }
    name.to_string()
}

/// Cases that replay today and disagree with Go for one known reason.
///
/// This is not a skip list. Every entry here is still executed and still compared; what
/// it asserts is that the case fails *and* that nothing else does. A case that starts
/// matching Go fails the test with its name in the message, so the list cannot quietly
/// outlive the gap, and a new divergence fails it too.
///
/// It is empty, and it earned that. The last three entries were the migration cases, and
/// they closed together when `load` learned to persist a migration (`MakeBackup` plus the
/// deferred `SaveConfig`) -- they were never loader work on their own, which is why one
/// stage cleared all three. Keeping a name here after it passes is not a harmless
/// bookkeeping slip: the list is the crate's own statement of what is missing, so a stale
/// entry makes a complete port look incomplete and hides the next real gap behind it.
///
/// The next thing that belongs here is a `save`-side gap, if one appears. The whole
/// fixture replays now, so anything that lands here from now on is a divergence someone
/// has to explain, not a stage that has not been written yet.
const KNOWN_UNPORTED: &[&str] = &[];

#[test]
fn loading_matches_what_go_returned() {
    let fixture = Fixture::load("config_load_save.json");
    let mut report = Report::new(&fixture);
    let mut gaps: Vec<&str> = Vec::new();
    let mut matched = 0;

    for case in &fixture.cases {
        let input: Script = case.parse();

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
        "{matched} of {} cases match Go byte for byte",
        fixture.cases.len(),
    );
    if gaps.is_empty() {
        eprintln!("no case is listed as unported");
    } else {
        eprintln!("known gaps: {}", gaps.join(", "));
    }
    report.finish(8);
}
