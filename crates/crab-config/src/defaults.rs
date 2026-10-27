//! The default config table: what `pkg/config.DefaultConfig()` answers.
//!
//! This is data, not behaviour, and it is worth being blunt about where it came
//! from. The table is the Go function's output, transcribed. It is embedded as
//! JSON rather than rebuilt as forty Rust structs with field-by-field defaults for
//! two reasons: the answer has to be *byte*-comparable with what Go marshals, and a
//! transcription bug in a Rust literal is invisible in a way that a diff against
//! the Go output is not.
//!
//! Three things make that transcription safe rather than a snapshot of whoever ran
//! the generator:
//!
//! * `$HOME` is a placeholder in the table and is expanded by [`default_config`],
//!   so the workspace path is the loader's decision and not the machine's. The
//!   corpus pins the expansion byte for byte (`/home/oracle/...`), so a port that
//!   expands it differently fails the case instead of passing for the wrong reason.
//! * Key order is preserved by [`crate::doc::Doc`], not by the JSON parser's map
//!   type. The table's order is Go's *struct field order*, and a sorted copy of it
//!   is the same data and a different file.
//! * `conformance/fixtures/config_load_save.json` case `defaults_canonical` *is*
//!   this table. When `DefaultConfig()` moves in Go and the fixture is regenerated,
//!   the replay fails on the first case with the diverging key named. That is the
//!   mechanism; nothing here asks anyone to remember to re-copy it.
//!
//! To refresh: `go run -tags goolm,stdjson ./cmd/oracle --out DIR` in picoclaw,
//! re-copy `config_load_save.json` into `conformance/fixtures/`, then re-derive this
//! file from the `defaults_canonical` result with the workspace path turned back
//! into the placeholder.

use crate::doc::{from_json, Doc};

/// The table, with `$HOME` left as the placeholder.
const DEFAULTS_JSON: &str = include_str!("defaults.json");

/// The placeholder the workspace path is stored under.
///
/// Go builds the path with `filepath.Join(home, ".picoclaw", "workspace")`, so the
/// only machine-dependent part is the home itself.
const HOME_PLACEHOLDER: &str = "$HOME";

/// The top-level keys, in the order Go emits them.
///
/// This is the table's contract, stated separately from the data so a re-derivation
/// that loses the order fails loudly instead of producing a document that differs
/// from Go's only in bytes.
pub const TOP_LEVEL_KEYS: [&str; 15] = [
    "session",
    "version",
    "isolation",
    "agents",
    "evolution",
    "channel_list",
    "model_list",
    "gateway",
    "events",
    "hooks",
    "tools",
    "heartbeat",
    "devices",
    "voice",
    "build_info",
];

/// The number of built-in model entries `DefaultConfig()` ships.
pub const BUILTIN_MODEL_COUNT: usize = 30;

/// `DefaultConfig()`, with `$HOME` replaced by `home`.
///
/// `home` is a parameter, not an environment read: the generator pins `HOME` at
/// `/home/oracle` for every case precisely so the corpus does not record the machine
/// that made it, and a replay that consulted the real environment would disagree
/// with the fixture on any machine but that one.
///
/// # Panics
///
/// If the embedded table is not the shape [`assert_table_shape`] documents. That is
/// a build-time fact, so a panic here means the file was edited without re-running
/// the tests -- not a condition a caller can handle.
#[must_use]
pub fn default_config(home: &str) -> Doc {
    let mut value = expect_table();
    expand_home(&mut value, home);
    value
}

/// The embedded table, parsed once per call, with the parse failure made fatal.
///
/// A `Parsed` rather than a `Result` because the loader needs the position in Go's
/// diagnostic; here there is no diagnostic to propagate -- an unparseable embedded
/// table is a broken build, and the sentence says so.
fn expect_table() -> Doc {
    let parsed = from_json(DEFAULTS_JSON);
    if let Some(diagnostic) = &parsed.error {
        panic!("the embedded default table is not valid JSON: {diagnostic}");
    }
    parsed.doc
}

/// Replaces every `$HOME` in a string value with `home`.
///
/// Walked rather than replaced over the serialized document on purpose: the
/// placeholder is a path component, and a whole-text replace would also rewrite a
/// user's literal `$HOME` inside a header value or a model name, which Go hands back
/// unchanged.
fn expand_home(value: &mut Doc, home: &str) {
    match value {
        Doc::String(s) => {
            if s.contains(HOME_PLACEHOLDER) {
                *s = s.replace(HOME_PLACEHOLDER, home);
            }
        }
        Doc::Array(items) => {
            for item in items {
                expand_home(item, home);
            }
        }
        Doc::Object(entries) => {
            for (_k, v) in entries.iter_mut() {
                expand_home(v, home);
            }
        }
        _ => {}
    }
}

/// Checks the embedded table against the two facts this module claims about it.
///
/// Runs in tests. A table that lost its placeholder, or whose key order moved, is a
/// silent divergence from Go -- the placeholder because it would pin whoever
/// generated it, the order because the file is compared byte for byte.
///
/// # Panics
///
/// If the table does not match its documented shape.
#[must_use]
pub fn assert_table_shape() -> usize {
    let value = expect_table();

    let entries = value.as_object().expect("the default table is an object");
    let keys: Vec<&str> = entries.iter().map(|(k, _v)| k.as_str()).collect();
    assert_eq!(
        keys, TOP_LEVEL_KEYS,
        "the table's top-level key order moved; it must be Go's struct field order"
    );

    let workspace = value
        .path(&["agents", "defaults", "workspace"])
        .and_then(Doc::as_str)
        .expect("agents.defaults.workspace is a string");
    assert!(
        workspace.starts_with(HOME_PLACEHOLDER),
        "the workspace path must carry the {HOME_PLACEHOLDER} placeholder, not a real home: a \
         transcribed /home/<someone> would pin the machine that generated the table"
    );

    value
        .get("model_list")
        .and_then(Doc::as_array)
        .expect("model_list is an array")
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_the_shape_the_module_claims() {
        // 30 built-in models is a fact about pkg/config, and the count is the
        // cheapest way to notice the list moved.
        assert_eq!(assert_table_shape(), BUILTIN_MODEL_COUNT);
    }

    #[test]
    fn home_is_expanded_where_go_expands_it() {
        let cfg = default_config("/home/oracle");
        assert_eq!(
            cfg.path(&["agents", "defaults", "workspace"])
                .and_then(Doc::as_str),
            Some("/home/oracle/.picoclaw/workspace")
        );
    }

    #[test]
    fn a_literal_home_in_a_value_is_not_special() {
        // The reason expand_home walks instead of replacing over the serialized
        // document: a user's string that happens to contain the placeholder is data.
        // Go hands it back as written, and so does this.
        let mut value = Doc::Object(vec![(
            "header".into(),
            Doc::String("send to $HOME at $HOME/x".into()),
        )]);
        expand_home(&mut value, "/h");
        assert_eq!(
            value.get("header").and_then(Doc::as_str),
            Some("send to /h at /h/x")
        );
    }

    #[test]
    fn key_order_survives_the_round_trip() {
        let cfg = default_config("/home/oracle");
        let keys: Vec<&str> = cfg
            .as_object()
            .expect("object")
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(
            keys, TOP_LEVEL_KEYS,
            "the document must keep Go's declaration order"
        );
    }

    #[test]
    fn the_table_is_the_fixture_s_first_case() {
        // The claim in the module docs, checked here rather than only in the replay:
        // defaults_canonical's recorded value must equal this table byte for byte.
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/fixtures/config_load_save.json"
        ))
        .expect("the config fixture is in the repository");
        let fixture: serde_json::Value = serde_json::from_str(&text).expect("fixture parses");
        let cases = fixture["cases"].as_array().expect("cases");
        let case = cases
            .iter()
            .find(|c| c["name"] == "defaults_canonical")
            .expect("defaults_canonical is in the fixture");
        // The recorded value is a JSON document stored as a string, which is how the
        // generator keeps the loader's answer byte-exact rather than re-encoded.
        let want: String =
            serde_json::from_str(&case["expected"]["results"][0]["value"].to_string())
                .expect("the recorded value is a JSON string");
        let got = default_config("/home/oracle").to_compact_json();
        assert_eq!(
            got, want,
            "the embedded table is not what Go's DefaultConfig answers"
        );
    }
}
