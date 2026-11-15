//! The file a user's next start reads, at the one position Go collapses to a bare string.
//!
//! rusty-crab#33. `config.AgentModelConfig.MarshalJSON` (`pkg/config/config.go:303-312`)
//! answers for itself: with a `Primary` and nothing in `Fallbacks` it returns
//! `json.Marshal(m.Primary)`, so a document that spells an agent's model as
//! `{"primary":"gpt-4"}` goes back out as `"model": "gpt-4"`. The port echoed the object,
//! which byte-diverges from Go on **every** save path — measured one process per shape at
//! picoclaw `99ea66d6` against this crate's own load/save in a throwaway tree:
//!
//! ```text
//! shape                                            Go's config.json        port before
//! v3, model {"primary":"gpt-4"}                    "model": "gpt-4"       "model": {"primary":"gpt-4"}
//! v2 (migrated), same model                        "model": "gpt-4"       "model": {"primary":"gpt-4"}
//! ```
//!
//! It is not a lockout: the string form is what Go's own `UnmarshalJSON` reads back, and the
//! port reads it too once rusty-crab#30 lands (that branch adds the string exemption at this
//! type). What this file pins is the write side, so the two binaries agree on bytes rather
//! than merely agreeing that either spelling loads.
//!
//! These are integration tests rather than `src/marshal.rs` unit tests for two reasons. They
//! drive the public `load`/`save` pair, which is the seam the issue is about — a unit test on
//! the marshal pass cannot show that the walk reaches the position through migration and
//! stamping. And a new file here cannot collide with the `src/lib.rs` tests module, which is
//! the shared append anchor of every stacked `crab-config` branch.

use std::fs;

/// Loads `body` the way the corpus does (`HOME` pinned so no `$HOME` expansion leaks in),
/// saves it back over the same path, and hands back the bytes that landed on disk.
fn saved(body: &str) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");
    fs::write(&config_path, body).expect("write config.json");

    let mut cfg = crab_config::load(&config_path, "/home/oracle")
        .unwrap_or_else(|e| panic!("this document must load, got {e:?}"));
    crab_config::save(&config_path, &mut cfg, "/home/oracle").expect("save must succeed");
    fs::read_to_string(&config_path).expect("read config.json back")
}

#[test]
fn a_primary_only_agent_model_saves_as_a_bare_string() {
    let text = saved(r#"{"version":3,"agents":{"list":[{"id":"a","model":{"primary":"gpt-4"}}]}}"#);
    assert!(
        text.contains(r#""model": "gpt-4""#),
        "Go writes the collapsed string; got {text}"
    );
    assert!(
        !text.contains(r#""primary": "gpt-4""#),
        "the object spelling must not survive the marshal; got {text}"
    );
}

#[test]
fn a_model_with_fallbacks_saves_as_the_object() {
    // The other half of Go's condition. A port that always collapses to `primary` passes the
    // test above and corrupts every real fallback list, so this one is load-bearing.
    let text = saved(
        r#"{"version":3,"agents":{"list":[{"id":"a","model":{"primary":"gpt-4","fallbacks":["gpt-3"]}}]}}"#,
    );
    assert!(
        text.contains(r#""primary": "gpt-4""#) && text.contains(r#""fallbacks": ["#),
        "fallbacks keep the object; got {text}"
    );
    assert!(
        !regex_free_model_is_string(&text),
        "a model with fallbacks must never be written as a bare string; got {text}"
    );
}

#[test]
fn the_migration_path_collapses_too_because_the_collapse_is_at_the_marshal() {
    // Version 3 is stamped on the way out, and the model was already collapsed before that:
    // the collapse belongs to `json.Marshal` of the typed value, not to the migration arm.
    let text = saved(r#"{"version":2,"agents":{"list":[{"id":"a","model":{"primary":"gpt-4"}}]}}"#);
    assert!(
        text.contains(r#""model": "gpt-4""#),
        "the migrated save collapses the same way; got {text}"
    );
    assert!(
        text.contains(r#""version": 3"#),
        "and still stamps the current version; got {text}"
    );
}

#[test]
fn the_recorded_loaded_value_says_the_same_thing_as_the_file() {
    // The corpus records `load` as the typed config re-marshalled by encoding/json
    // (`cmd/oracle/config.go:237-243`), so the recorded value and the written file are the
    // same marshal. A port that collapses only the file is right on disk and wrong in every
    // recorded query -- and the conformance replay compares the recorded query, so it would
    // be the replay that noticed, not the user.
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");
    fs::write(
        &config_path,
        r#"{"version":3,"agents":{"list":[{"id":"a","model":{"primary":"gpt-4"}}]}}"#,
    )
    .expect("write config.json");

    let cfg = crab_config::load(&config_path, "/home/oracle").expect("loads");
    let value = crab_config::loaded_value(&cfg.document, &crab_config::config_schema());
    assert!(
        value.contains(r#""model":"gpt-4""#),
        "the loaded value collapses too; got {value}"
    );
}

/// True when some `"model"` key in the file holds a string rather than an object. Written by
/// hand because the crate has no regex dependency, and the check only needs the first
/// non-whitespace character after the colon.
fn regex_free_model_is_string(text: &str) -> bool {
    let mut rest = text;
    while let Some(index) = rest.find("\"model\":") {
        let after = rest[index + "\"model:".len()..].trim_start();
        if let Some(first) = after.chars().next() {
            if first == '"' {
                return true;
            }
        }
        rest = &rest[index + "\"model:".len()..];
    }
    false
}
