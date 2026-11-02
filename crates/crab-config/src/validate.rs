//! The last two refusals in `LoadConfig`: `ValidateTurnProfile` and `ValidateModelList`.
//!
//! Both run inside the load, both refuse a config rather than repair one, and both are
//! reached on every current-version document, so a port that omits them returns a
//! plausible `*Config` for files the shipped binary rejects. The Go side is
//! `turn_profile.go:74` (`ValidateTurnProfile` → `validateTurnProfile` →
//! `validateTurnProfileBlock`) and `config.go:1752` (`ValidateModelList` →
//! `ModelConfig.Validate` at `config.go:839`).
//!
//! ## Where they sit, and why the position is not cosmetic
//!
//! `LoadConfig` runs them as `InitChannelList` → **turn profile** → gateway host →
//! `expandMultiKeyModels` → **model list** → the workspace default → the session scope.
//! The model-list half is therefore graded over the *expanded* list, so the index in its
//! message counts entries the file never contained: a two-key `m1` validates as
//! `[m1__key_1, m1]` (see [`crate::multikey`]), and a fault in the original is reported
//! at index 1. Validating before the expansion reports a different index for the same
//! file, and nothing about the refusal looks wrong.
//!
//! The Go function's own comment says it validates "uniqueness and required fields".
//! There is no uniqueness check in it — duplicate `model_name`s load. Stated because the
//! comment is the kind a porter implements from.
//!
//! ## What each rule actually keys on
//!
//! Turn profile: the blocks are checked in Go's order — `history`, `system_prompt`,
//! `skills`, `tools` — so the first refusal wins, and `custom` is legal on exactly the
//! last two (`validateTurnProfileBlock`'s `allowCustom`). Nothing is checked at all once
//! `enabled` is false, including an unrecognised mode, and the corpus pins both halves of
//! that pair (`a_disabled_turn_profile_does_not_validate_its_blocks` loads a profile whose
//! `history.mode` is `custom`). A port that validates the mode uniformly across blocks, or
//! regardless of `enabled`, is wrong on one side of it.
//!
//! The mode is *matched* on a lowercased, trimmed value — `" OFF "` loads — and
//! `Effective()` maps the empty string to `default`. But the refusal prints the **raw**
//! string, because Go formats `block.Mode` and not the effective mode, so
//! `has unsupported mode "Sometimes"` quotes what the user typed.
//!
//! Model list: four rules on the entry, in order — `model_name` required, `model`
//! required, the `tool_schema_transform` set, then three identifier refusals
//! (whitespace, leading `/`, `//`). The transform check comes *before* the identifier
//! checks, so an entry with a bad transform and a bad identifier reports the transform.
//! Its accepted set is the normaliser's aliases, not the two names in its message:
//! `""`, `off`, `none`, `native` all mean off and `simple`, `basic`, `strict`, `flat` all
//! mean simple, matched case-insensitively and trimmed ([`normalize_tool_schema_transform`]),
//! while the message says only `(supported: off, simple)`. A port that lists the aliases
//! in the message diverges textually; one that accepts only the two canonical names
//! rejects files Go loads.
//!
//! ## What this stage deliberately does not decide
//!
//! A `mode` that is not a string, or an `enabled` that is not a bool, is refused by Go
//! during the typed decode and so never reaches Go's validator. This crate's decoder does
//! not check types at that depth — the same gap as the security-file scalar rules — so
//! here a value of the wrong kind reads as absent, exactly as an omitted key does. That is
//! a stated position, not a decided behaviour: the decoder-side refusal belongs with the
//! type-refusal work, not with these two rules, and inventing a message here would put an
//! unpinned string in front of a user.

//! ## What a refusal leaves behind
//!
//! A migrated document is saved by a `defer` that runs at `LoadConfig`'s *return*, so it
//! persists whatever the loader did after the migration switch — these two validators
//! included. A `version: 2` file that one of them refuses therefore ends up rewritten,
//! version-raised and backed up on disk while the caller receives only the error. That is
//! why [`crate::load`] captures both verdicts and raises them after the write: refusing
//! where they run would leave the same result, refusing before it would not.
//! (`MakeBackup`'s own failure still wins, because Go returns from inside the migration arm
//! before either validator runs.)
//!
//! ## `PICOCLAW_*`: why no environment-substituted value is checked here
//!
//! `ValidateModelList` calls `ApplyEnvVarOverrides(entry)` per entry, *after* the identifier
//! checks, substituting `$VAR` and `${VAR}` in `model_name`, `model` and `api_keys`. The
//! ordering is the point: Go grades the token as written, so a `model` holding a reference
//! whose value contains whitespace loads, where a port that substituted first would refuse
//! it. This stage has no environment access at all, which is how it matches that ordering
//! without reproducing it. Recorded as a stated position rather than assumed away:
//! `os.LookupEnv` in a Go test needs a subprocess, and the corpus clears `PICOCLAW_*` for
//! every case.

use crate::doc::Doc;
use crate::Error;

/// `TurnProfileMode.Effective` (`turn_profile.go:39`): lowercase and trim, then the empty
/// string and `default` are the same mode. Anything else is returned normalised, and the
/// caller decides whether it is one of the three known values.
fn effective_mode(raw: &str) -> String {
    let trimmed = raw.trim().to_lowercase();
    if trimmed.is_empty() {
        return "default".to_string();
    }
    trimmed
}

/// `validateTurnProfileBlock` (`turn_profile.go:97`) for one block.
///
/// `raw` is what the document says; the match is on the normalised form while the refusal
/// quotes the raw one, which is Go's asymmetry and not a typo.
fn validate_block(field: &str, raw: &str, allow_custom: bool) -> Result<(), String> {
    match effective_mode(raw).as_str() {
        "default" | "off" => Ok(()),
        "custom" if allow_custom => Ok(()),
        "custom" => Err(format!(
            "turn_profile.{field}.mode custom is not supported in this version"
        )),
        _ => Err(format!(
            "turn_profile.{field}.mode has unsupported mode {raw:?}"
        )),
    }
}

/// The mode a block carries. A block that is absent, or whose `mode` is not a string,
/// reads as the empty string — which is `default` (see the module doc for why that is a
/// position and not a fix).
fn block_mode(profile: &Doc, block: &str) -> String {
    profile
        .get(block)
        .and_then(|b| b.get("mode"))
        .and_then(Doc::as_str)
        .unwrap_or_default()
        .to_string()
}

/// `Config.ValidateTurnProfile` (`turn_profile.go:74`) over a loaded document.
pub(crate) fn turn_profile(document: &Doc) -> Result<(), Error> {
    let Some(profile) = document.path(&["agents", "defaults", "turn_profile"]) else {
        return Ok(());
    };
    // `Enabled` is a plain bool in the struct, so a profile nobody switched on is not
    // examined at all. This is the whole reason the corpus's disabled case is an
    // acceptance of a value the same file would otherwise refuse.
    if !matches!(profile.get("enabled"), Some(Doc::Bool(true))) {
        return Ok(());
    }
    // Go's order, because the first refusal is the one a user reads.
    for (field, allow_custom) in [
        ("history", false),
        ("system_prompt", false),
        ("skills", true),
        ("tools", true),
    ] {
        validate_block(field, &block_mode(profile, field), allow_custom)
            .map_err(Error::TurnProfile)?;
    }
    Ok(())
}

/// `providercommon.NormalizeToolSchemaTransform` (`tool_schema_transform.go:16`).
///
/// Only the verdict is needed here; the canonical name is what the provider layer wants.
/// The message names two values even though eight spellings are accepted, and quotes the
/// raw input.
fn normalize_tool_schema_transform(raw: &str) -> Result<(), String> {
    match raw.trim().to_lowercase().as_str() {
        "" | "off" | "none" | "native" | "simple" | "basic" | "strict" | "flat" => Ok(()),
        _ => Err(format!(
            "unsupported tool_schema_transform {raw:?} (supported: off, simple)"
        )),
    }
}

/// `ModelConfig.Validate` (`config.go:839`) for one entry.
///
/// The order is Go's: both required fields, then the transform, then the three identifier
/// rules. Each refusal is returned verbatim because Go wraps it with the position at the
/// call site rather than inside the method.
fn validate_entry(entry: &Doc) -> Result<(), String> {
    let field = |key: &str| -> String {
        entry
            .get(key)
            .and_then(Doc::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let model_name = field("model_name");
    let model = field("model");

    if model_name.is_empty() {
        return Err("model_name is required".to_string());
    }
    if model.is_empty() {
        return Err("model is required".to_string());
    }
    normalize_tool_schema_transform(&field("tool_schema_transform"))?;

    // Three refusals on the shape of an identifier that is a perfectly good JSON string in
    // each case. Go checks whitespace first, so an identifier that is both blank-padded
    // and slash-prefixed reports the whitespace.
    if model.contains([' ', '\t', '\n', '\r']) {
        return Err("model identifier contains whitespace".to_string());
    }
    if model.starts_with('/') {
        return Err("model identifier must not start with /".to_string());
    }
    if model.contains("//") {
        return Err("model identifier must not contain //".to_string());
    }
    Ok(())
}

/// `Config.ValidateModelList` (`config.go:1752`) over a loaded document.
///
/// Run it *after* [`crate::multikey::expand`]: the index Go reports is the position in the
/// expanded list, and an absent `model_list` is an empty slice rather than an error.
pub(crate) fn model_list(document: &Doc) -> Result<(), Error> {
    let Some(entries) = document.get("model_list").and_then(Doc::as_array) else {
        return Ok(());
    };
    for (index, entry) in entries.iter().enumerate() {
        validate_entry(entry).map_err(|m| Error::ModelList(format!("model_list[{index}]: {m}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::from_json;

    fn doc(text: &str) -> Doc {
        from_json(text).doc
    }

    /// The entry every model-list test varies, so each one changes exactly one rule.
    const OK: &str = "{\"model_name\":\"m1\",\"provider\":\"p\",\"model\":\"m\"}";

    fn model_list_error(entry: &str) -> String {
        let document = doc(&format!("{{\"model_list\":[{entry}]}}"));
        match model_list(&document) {
            Ok(()) => panic!("expected a refusal"),
            Err(e) => e.to_string(),
        }
    }

    fn accepted(entry: &str) -> bool {
        model_list(&doc(&format!("{{\"model_list\":[{entry}]}}"))).is_ok()
    }

    #[test]
    fn a_complete_entry_loads() {
        assert!(accepted(OK));
    }

    #[test]
    fn the_two_required_fields_have_their_own_messages() {
        // Separate requirements, and the port must not merge them: Go's own migration
        // section reports `model is required` for a document that only named `model_name`.
        assert_eq!(
            model_list_error("{\"provider\":\"p\",\"model\":\"m\"}"),
            "model_list[0]: model_name is required"
        );
        assert_eq!(
            model_list_error("{\"model_name\":\"m1\",\"provider\":\"p\"}"),
            "model_list[0]: model is required"
        );
        // An empty string is absent to Go (`== ""`), not a value.
        assert_eq!(
            model_list_error("{\"model_name\":\"\",\"model\":\"m\"}"),
            "model_list[0]: model_name is required"
        );
    }

    #[test]
    fn the_index_is_the_position_in_the_list() {
        let document = doc(&format!(
            "{{\"model_list\":[{OK},{{\"model_name\":\"m2\"}}]}}"
        ));
        let err = model_list(&document).expect_err("second entry must be refused");
        assert_eq!(err.to_string(), "model_list[1]: model is required");
    }

    #[test]
    fn three_identifier_shapes_are_refused_for_different_reasons() {
        // All three are valid JSON strings, so only this stage can refuse them.
        assert_eq!(
            model_list_error("{\"model_name\":\"m1\",\"model\":\"claude 3\"}"),
            "model_list[0]: model identifier contains whitespace"
        );
        assert_eq!(
            model_list_error("{\"model_name\":\"m1\",\"model\":\"/anthropic.claude\"}"),
            "model_list[0]: model identifier must not start with /"
        );
        assert_eq!(
            model_list_error("{\"model_name\":\"m1\",\"model\":\"anthropic//claude\"}"),
            "model_list[0]: model identifier must not contain //"
        );
        // A tab is whitespace too, and whitespace outranks the slash rules.
        assert_eq!(
            model_list_error("{\"model_name\":\"m1\",\"model\":\"\\t/x\"}"),
            "model_list[0]: model identifier contains whitespace"
        );
        // A single slash is ordinary: providers name models like `org/model`.
        assert!(accepted(
            "{\"model_name\":\"m1\",\"model\":\"anthropic/claude\"}"
        ));
    }

    #[test]
    fn the_transform_accepts_eight_spellings_and_names_two() {
        for spelling in [
            "", "off", "none", "native", "simple", "basic", "strict", "flat",
        ] {
            assert!(
                accepted(&format!(
                    "{{\"model_name\":\"m1\",\"model\":\"m\",\"tool_schema_transform\":\
                     \"{spelling}\"}}"
                )),
                "{spelling} must load"
            );
        }
        // Matched on the normalised value...
        assert!(accepted(
            "{\"model_name\":\"m1\",\"model\":\"m\",\"tool_schema_transform\":\" SIMPLE \"}"
        ));
        // ...but quoted as typed, with only the canonical pair named.
        assert_eq!(
            model_list_error(
                "{\"model_name\":\"m1\",\"model\":\"m\",\"tool_schema_transform\":\"Sideways\"}"
            ),
            "model_list[0]: unsupported tool_schema_transform \"Sideways\" (supported: off, simple)"
        );
    }

    #[test]
    fn the_transform_is_checked_before_the_identifier() {
        // Both halves of this entry are faults, and Go's order decides which one a user
        // is told about.
        assert_eq!(
            model_list_error(
                "{\"model_name\":\"m1\",\"model\":\"bad id\",\"tool_schema_transform\":\"nope\"}"
            ),
            "model_list[0]: unsupported tool_schema_transform \"nope\" (supported: off, simple)"
        );
    }

    #[test]
    fn an_absent_model_list_is_not_an_error() {
        assert!(model_list(&doc("{\"version\":3}")).is_ok());
    }

    /// `{"agents":{"defaults":{"turn_profile":{...}}}}` carrying `enabled` and then one
    /// block per entry of `blocks`.
    ///
    /// Built through the document API rather than a `format!` template: the doubled braces
    /// that quoting JSON inside a format string needs hid a mismatch until the compiler
    /// said so, and the shape of a profile is three levels deep.
    fn profile(enabled: bool, blocks: &[(&str, Doc)]) -> Doc {
        let mut profile = Doc::Object(vec![("enabled".to_string(), Doc::Bool(enabled))]);
        for (field, mode) in blocks {
            profile.set(field, Doc::Object(vec![("mode".to_string(), mode.clone())]));
        }
        let mut defaults = Doc::Object(Vec::new());
        defaults.set("turn_profile", profile);
        let mut agents = Doc::Object(Vec::new());
        agents.set("defaults", defaults);
        let mut root = Doc::Object(Vec::new());
        root.set("agents", agents);
        root
    }

    fn mode(raw: &str) -> Doc {
        Doc::String(raw.to_string())
    }

    #[test]
    fn a_profile_nobody_enabled_is_not_examined() {
        // The acceptance half of the pair the corpus pins: every block goes unchecked, so
        // a `custom` history mode loads and the loaded value keeps it.
        assert!(turn_profile(&profile(
            false,
            &[("history", mode("custom")), ("tools", mode("nope"))]
        ))
        .is_ok());
    }

    #[test]
    fn custom_is_legal_on_two_blocks_and_not_on_the_other_two() {
        for (block, allowed) in [
            ("history", false),
            ("system_prompt", false),
            ("skills", true),
            ("tools", true),
        ] {
            let outcome = turn_profile(&profile(true, &[(block, mode("custom"))]));
            if allowed {
                assert!(outcome.is_ok(), "{block} must accept custom");
            } else {
                assert_eq!(
                    outcome.expect_err("must refuse").to_string(),
                    format!("turn_profile.{block}.mode custom is not supported in this version")
                );
            }
        }
    }

    #[test]
    fn go_checks_the_blocks_in_this_order() {
        // Both blocks refuse, so only the order decides the message.
        let document = profile(
            true,
            &[
                ("system_prompt", mode("custom")),
                ("history", mode("custom")),
            ],
        );
        assert_eq!(
            turn_profile(&document)
                .expect_err("must refuse")
                .to_string(),
            "turn_profile.history.mode custom is not supported in this version"
        );
    }

    #[test]
    fn a_mode_is_matched_normalised_and_quoted_as_typed() {
        assert!(turn_profile(&profile(
            true,
            &[("history", mode(" OFF ")), ("skills", mode(""))]
        ))
        .is_ok());
        let err = turn_profile(&profile(true, &[("history", mode("Sometimes"))]));
        assert_eq!(
            err.expect_err("must refuse").to_string(),
            "turn_profile.history.mode has unsupported mode \"Sometimes\""
        );
    }

    #[test]
    fn a_non_string_mode_reads_as_absent() {
        // Stated position, see the module doc: Go never reaches its validator with a
        // mis-typed mode, so this pins what the stage does rather than claiming Go's
        // answer to a file it refuses earlier.
        assert!(turn_profile(&profile(true, &[("history", Doc::Int(42))])).is_ok());
    }

    #[test]
    fn a_profile_that_is_absent_or_switched_off_loads() {
        assert!(turn_profile(&doc("{\"version\":3}")).is_ok());
        assert!(turn_profile(&profile(false, &[])).is_ok());
    }
}
