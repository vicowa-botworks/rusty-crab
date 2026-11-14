//! The legacy top-level `bindings` array, measured against the binary that still reads it.
//!
//! rusty-crab#32. `bindings` is a key that exists on one side of a version boundary: the
//! migration arms validate a legacy document against `legacyDiagnosticConfig`
//! (`pkg/config/migration.go:30-46`), which declares it at `:44`, while the current-version
//! path validates against `Config`, which has no such field. `pkg/config/legacy_bindings.go`
//! then rewrites the array into `agents.dispatch.rules` from **config.json's own bytes** at
//! `config.go:1514` -- after the ladder, the decode and the security file, and inside the
//! migration arm's `defer SaveConfig`, so the rewrite reaches the disk.
//!
//! Measured one process per shape against the shipped binary (picoclaw `main`, 2026-11-12),
//! and against this crate before the module landed:
//!
//! ```text
//! shape                                     Go                            port before
//! v2 + bindings                             dispatch.rules, no bindings   no dispatch, no bindings
//! v2 + bindings + dispatch.rules            its own rules kept            its own rules kept
//! v2 + one bad agent_id                     rules lost whole array        no dispatch, no bindings
//! v2 + bindings only in .security.yml       not migrated                  not migrated
//! v3 + bindings                             unknown field(s): bindings    unknown field(s): bindings
//! ```
//!
//! The second column of the first row is the bug worth fixing: the port deleted the key in
//! `migrate_v2_to_v3` and put the rules nowhere, so a v2 config with bindings loaded clean,
//! wrote a file both binaries accept, and **silently lost every routing rule**. Nothing
//! downstream notices, because the config still loads.
//!
//! No corpus case mentions `bindings` (0 of 168), so nothing on the fixture grades either
//! direction; these in-crate tests are the only pins until the config-fixture bump carries a
//! scripted legacy document with bindings in it. That deferral is stated on the PR rather
//! than left to be discovered: the bump is its own commit, and one corpus change at a time.

use std::fs;

use crab_config::{config_schema, loaded_value, Doc};

/// Loads `body` the way the corpus does (`HOME` pinned so no `$HOME` expansion leaks in),
/// lets the loader do whatever the version decides -- a migration saves -- and hands back the
/// refusal, if there was one, plus the bytes that are on disk afterwards.
fn round_trip(body: &str) -> (Option<String>, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");
    fs::write(&config_path, body).expect("write config.json");

    let loaded = crab_config::load(&config_path, "/home/oracle");
    let error = loaded.as_ref().err().map(ToString::to_string);
    (
        error,
        fs::read_to_string(&config_path).expect("read config.json back"),
    )
}

/// The same, for a document with a `.security.yml` beside it.
fn round_trip_pair(config: &str, security: &str) -> (Option<String>, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");
    fs::write(&config_path, config).expect("write config.json");
    fs::write(dir.path().join(".security.yml"), security).expect("write .security.yml");

    let loaded = crab_config::load(&config_path, "/home/oracle");
    let error = loaded.as_ref().err().map(ToString::to_string);
    (
        error,
        fs::read_to_string(&config_path).expect("read config.json back"),
    )
}

/// The file parsed back, so a test asserts on structure and key order rather than on
/// substrings of an indented document.
fn parse(text: &str) -> Doc {
    let parsed = crab_config::from_json(text);
    assert!(
        parsed.error.is_none(),
        "the saved file must parse: {:?}",
        parsed.error
    );
    parsed.doc
}

/// The object names under `path`, in the order the file holds them.
fn keys(document: &Doc, path: &[&str]) -> Vec<String> {
    document
        .path(path)
        .and_then(Doc::as_object)
        .map(|entries| {
            entries
                .iter()
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

/// Each `agents.dispatch.rules` entry as compact JSON: the rule's field order and its
/// selector's key order are both part of what Go pins, and compact rendering is the cheapest
/// way to assert on both at once.
fn rules(document: &Doc) -> Vec<String> {
    document
        .path(&["agents", "dispatch", "rules"])
        .map(|node| {
            node.as_array()
                .map(|items| items.iter().map(Doc::to_compact_json).collect::<Vec<_>>())
                .unwrap_or_else(|| panic!("rules is not an array: {node:?}"))
        })
        .unwrap_or_default()
}

/// The rule names, in the order the file holds them.
fn rule_names(document: &Doc) -> Vec<String> {
    document
        .path(&["agents", "dispatch", "rules"])
        .and_then(Doc::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|rule| rule.get("name").and_then(Doc::as_str))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[test]
fn a_legacy_bindings_array_is_rewritten_into_dispatch_rules_on_disk() {
    let (error, text) = round_trip(
        r#"{"version":2,"bindings":[{"agent_id":"agent-plain","match":{"channel":"telegram"}}]}"#,
    );
    assert_eq!(error, None, "a v2 document with bindings loads: {error:?}");
    let file = parse(&text);
    assert!(
        file.get("bindings").is_none(),
        "the legacy key is gone from the file: {text}"
    );
    assert_eq!(
        rules(&file),
        vec![
            r#"{"name":"legacy-binding-1","agent":"agent-plain","when":{"channel":"telegram","account":"default"}}"#
        ],
        "the rule is what Go writes"
    );
    // `AgentsConfig` declares dispatch last (`config.go:269`) and the document is held in
    // declaration order, so this is a byte-level fact about the file, not a detail.
    assert_eq!(keys(&file, &["agents"]), ["defaults", "dispatch"], "{text}");
    assert_eq!(keys(&file, &["agents", "dispatch"]), ["rules"], "{text}");
}

#[test]
fn the_migrated_file_is_one_the_current_version_accepts() {
    // The asymmetry this issue is about, run through both halves: the file the legacy path
    // writes must load at the current version. Before the module the port wrote a file that
    // merely *parsed* -- the rules were missing rather than invalid -- which is why this
    // assertion is about the rules and not about the refusal.
    let (error, text) = round_trip(
        r#"{"version":2,"bindings":[{"agent_id":"agent-plain","match":{"channel":"telegram"}}]}"#,
    );
    assert_eq!(error, None, "{error:?}");
    assert!(
        text.contains(r#""version": 3"#),
        "the file is stamped: {text}"
    );
    let (again, _) = round_trip(&text);
    assert_eq!(again, None, "and the stamped file loads clean: {again:?}");
}

#[test]
fn rules_are_ordered_by_kind_and_then_by_the_position_they_came_from() {
    // `migrateLegacyBindings` (`legacy_bindings.go:100`) buckets by kind and concatenates,
    // while `name` keeps the binding's own 1-based index. Peers are kind 0, guild space 1,
    // team space 2, account match 3, wildcard account 4. A port that keeps the file's order
    // passes every single-binding test and reorders a real config's precedence -- which is
    // the whole purpose of the array, since the first matching rule wins.
    let (error, text) = round_trip(
        r#"{"version":2,"bindings":[
            {"agent_id":"agent-guild","match":{"channel":"DISCORD","guild_id":"G1"}},
            {"agent_id":"agent-plain","match":{"channel":"telegram"}},
            {"agent_id":"agent-direct","match":{"channel":"telegram","peer":{"kind":"direct","id":"U9"}}},
            {"agent_id":"agent-star","match":{"channel":"slack","account_id":"*"}},
            {"agent_id":"agent-team","match":{"channel":"slack","team_id":"T1"}},
            {"agent_id":"agent-acct-guild","match":{"channel":"discord","account_id":"Work","guild_id":"G2"}},
            {"agent_id":"agent-badpeer","match":{"channel":"telegram","peer":{"kind":"whatever","id":"x"}}},
            {"agent_id":"agent-group","match":{"channel":"discord","peer":{"kind":"GROUP","id":"C5"}}},
            {"agent_id":"agent-topic","match":{"channel":"telegram","peer":{"kind":"topic","id":"T7"}}},
            {"agent_id":"agent-acct-peer","match":{"channel":"telegram","account_id":"WORK","peer":{"kind":"direct","id":"U8"}}},
            {"agent_id":"agent-space-peer","match":{"channel":"discord","guild_id":"G3","peer":{"kind":"channel","id":"C6"}}},
            {"agent_id":"agent-star-guild","match":{"channel":"slack","account_id":"*","guild_id":"G4"}}
        ]}"#,
    );
    assert_eq!(error, None, "{error:?}");
    let file = parse(&text);
    assert_eq!(
        rule_names(&file),
        [
            "legacy-binding-3",
            "legacy-binding-8",
            "legacy-binding-9",
            "legacy-binding-10",
            "legacy-binding-11",
            "legacy-binding-1",
            "legacy-binding-6",
            "legacy-binding-12",
            "legacy-binding-5",
            "legacy-binding-2",
            "legacy-binding-4",
        ],
        "kind buckets first, each bucket in the array's own order, names from the original index"
    );
    assert_eq!(
        rules(&file),
        vec![
            r#"{"name":"legacy-binding-3","agent":"agent-direct","when":{"channel":"telegram","account":"default","sender":"u9"}}"#,
            r#"{"name":"legacy-binding-8","agent":"agent-group","when":{"channel":"discord","account":"default","chat":"group:C5"}}"#,
            r#"{"name":"legacy-binding-9","agent":"agent-topic","when":{"channel":"telegram","account":"default","topic":"topic:T7"}}"#,
            r#"{"name":"legacy-binding-10","agent":"agent-acct-peer","when":{"channel":"telegram","account":"work","sender":"u8"}}"#,
            r#"{"name":"legacy-binding-11","agent":"agent-space-peer","when":{"channel":"discord","account":"default","chat":"channel:C6"}}"#,
            r#"{"name":"legacy-binding-1","agent":"agent-guild","when":{"channel":"discord","account":"default","space":"guild:G1"}}"#,
            r#"{"name":"legacy-binding-6","agent":"agent-acct-guild","when":{"channel":"discord","account":"work","space":"guild:G2"}}"#,
            r#"{"name":"legacy-binding-12","agent":"agent-star-guild","when":{"channel":"slack","space":"guild:G4"}}"#,
            r#"{"name":"legacy-binding-5","agent":"agent-team","when":{"channel":"slack","account":"default","space":"team:T1"}}"#,
            r#"{"name":"legacy-binding-2","agent":"agent-plain","when":{"channel":"telegram","account":"default"}}"#,
            r#"{"name":"legacy-binding-4","agent":"agent-star","when":{"channel":"slack"}}"#,
        ],
        "every selector field, its prefix and its casing, measured against the shipped binary"
    );
}

#[test]
fn a_wildcard_sorts_after_a_plain_account_even_when_it_came_first() {
    // The one document that separates kind 4 from kind 3. Inside a bucket the array's own order
    // decides, so a document whose wildcard comes *before* any plain account is the only shape
    // where bucketing the wildcard with the plain accounts changes the output -- and the
    // precedence matters, because the first matching rule wins. Measured (probe shape `i`):
    //
    //     legacy-binding-4 team-fourth  {channel:matrix, account:default, space:team:T9}
    //     legacy-binding-2 plain-second {channel:matrix, account:default}
    //     legacy-binding-1 star-first   {channel:matrix}
    //     legacy-binding-3 star-third   {channel:irc}
    //
    // A port that returns the wildcard from the kind-3 branch instead of the kind-4 one writes
    // 4, 1, 2, 3 -- and every other bindings test in this file still passes.
    let (_, text) = round_trip(
        r#"{"version":2,"bindings":[
            {"agent_id":"star-first","match":{"channel":"matrix","account_id":"*"}},
            {"agent_id":"plain-second","match":{"channel":"matrix"}},
            {"agent_id":"star-third","match":{"channel":"irc","account_id":"*"}},
            {"agent_id":"team-fourth","match":{"channel":"matrix","team_id":"T9"}}
        ]}"#,
    );
    assert_eq!(
        rule_names(&parse(&text)),
        [
            "legacy-binding-4",
            "legacy-binding-2",
            "legacy-binding-1",
            "legacy-binding-3"
        ],
        "kind 2, then kind 3, then kind 4, whatever the array's own order: {text}"
    );
    assert_eq!(
        rules(&parse(&text)),
        vec![
            r#"{"name":"legacy-binding-4","agent":"team-fourth","when":{"channel":"matrix","account":"default","space":"team:T9"}}"#,
            r#"{"name":"legacy-binding-2","agent":"plain-second","when":{"channel":"matrix","account":"default"}}"#,
            r#"{"name":"legacy-binding-1","agent":"star-first","when":{"channel":"matrix"}}"#,
            r#"{"name":"legacy-binding-3","agent":"star-third","when":{"channel":"irc"}}"#,
        ],
        "{text}"
    );
}

#[test]
fn a_wildcard_account_is_cleared_rather_than_written() {
    // Three positions a wildcard can appear in, because two different statements keep it out
    // of the selector and only the kind-4 branch clears it again: `migrateLegacyBinding`'s
    // `switch` guard omits it for every kind, and the kind-4 branch assigns the empty string.
    // A peer or space binding therefore pins the guard on its own -- a port that writes the
    // `*` into the selector for kinds 0, 1 and 2 still passes a wildcard-only test, and its
    // rules then match no account at all instead of every one.
    let (_, text) = round_trip(
        r#"{"version":2,"bindings":[
            {"agent_id":"a","match":{"channel":"slack","account_id":"*"}},
            {"agent_id":"b","match":{"channel":"discord","account_id":" * "}},
            {"agent_id":"c","match":{"channel":"slack","account_id":"*","guild_id":"G4"}},
            {"agent_id":"d","match":{"channel":"telegram","account_id":"*","peer":{"kind":"direct","id":"U1"}}}
        ]}"#,
    );
    assert_eq!(
        rules(&parse(&text)),
        vec![
            r#"{"name":"legacy-binding-4","agent":"d","when":{"channel":"telegram","sender":"u1"}}"#,
            r#"{"name":"legacy-binding-3","agent":"c","when":{"channel":"slack","space":"guild:G4"}}"#,
            r#"{"name":"legacy-binding-1","agent":"a","when":{"channel":"slack"}}"#,
            r#"{"name":"legacy-binding-2","agent":"b","when":{"channel":"discord"}}"#,
        ],
        "the wildcard never reaches the selector at any kind, and it is trimmed first: {text}"
    );
}

#[test]
fn an_account_is_lower_cased_and_an_absent_one_becomes_default() {
    // The dead `case "":` in `migrateLegacyBinding` is only dead because normalize never
    // returns an empty string, so an unset account means `legacyDefaultAccountID`.
    let (_, text) = round_trip(
        r#"{"version":2,"bindings":[
            {"agent_id":"a","match":{"channel":"telegram","account_id":"Work"}},
            {"agent_id":"b","match":{"channel":"telegram","account_id":"  "}},
            {"agent_id":"c","match":{"channel":"telegram","account_id":null}}
        ]}"#,
    );
    assert_eq!(
        rules(&parse(&text)),
        vec![
            r#"{"name":"legacy-binding-1","agent":"a","when":{"channel":"telegram","account":"work"}}"#,
            r#"{"name":"legacy-binding-2","agent":"b","when":{"channel":"telegram","account":"default"}}"#,
            r#"{"name":"legacy-binding-3","agent":"c","when":{"channel":"telegram","account":"default"}}"#,
        ],
        "{text}"
    );
}

#[test]
fn a_direct_peer_is_canonicalised_through_the_identity_links() {
    // Three spellings of the same lookup (`legacy_bindings.go:228`): the bare id, the
    // channel-qualified id, and the part after the first colon. Only the third entry's own
    // value matches here, so the first and third rules get the canonical id and the second
    // keeps its peer id lower-cased.
    let (_, text) = round_trip(
        r#"{"version":2,"session":{"identity_links":{"canonical-user":["tg:111","discord:222"]}},
            "bindings":[
            {"agent_id":"a1","match":{"channel":"telegram","peer":{"kind":"direct","id":"TG:111"}}},
            {"agent_id":"a2","match":{"channel":"discord","peer":{"kind":"direct","id":"333"}}},
            {"agent_id":"a3","match":{"channel":"discord","peer":{"kind":"direct","id":"discord:222"}}}
        ]}"#,
    );
    assert_eq!(
        rules(&parse(&text)),
        vec![
            r#"{"name":"legacy-binding-1","agent":"a1","when":{"channel":"telegram","account":"default","sender":"canonical-user"}}"#,
            r#"{"name":"legacy-binding-2","agent":"a2","when":{"channel":"discord","account":"default","sender":"333"}}"#,
            r#"{"name":"legacy-binding-3","agent":"a3","when":{"channel":"discord","account":"default","sender":"canonical-user"}}"#,
        ],
        "{text}"
    );

    // The candidate spellings and their edges, measured 2026-11-14 (probe shape `h`, one
    // process, `bindings=7 dispatch_rules=7`): the bare id, the channel-qualified id, and the
    // part after the *first* colon all resolve a link, and each of the last two needs its own
    // witness because the row above is satisfied by the bare id alone.
    //
    // `h3` is Go's `idx > 0 && idx < len - 1`: a peer id that *starts* with a colon gets no
    // third candidate, so `:7` stays `:7` even though a link names `7`. `h5` shows the
    // qualified candidate is built from the lower-cased channel. `h4` shows the *link's own*
    // value is lower-cased for the comparison, not only the peer id. `h7` is the empty
    // canonical key: Go walks past it rather than answering with an empty id, which would
    // have made `sender` disappear from the selector entirely under `omitempty`.
    //
    // No two canonical keys claim the same peer id in this document, so none of these rows turns
    // on which key Go's map hands over first. The shape that does has its own test,
    // `a_peer_id_two_identity_link_keys_claim_answers_in_document_order`, and the reason it is not
    // a corpus case is in `docs/DIVERGENCES.md`.
    let (_, text) = round_trip(
        r#"{"version":2,"session":{"identity_links":{
            "can-qualified":["slack:999"],
            "can-suffix":["777"],
            "can-leading-colon":["7"],
            "can-uppercase":["TG:UP"],
            "can-star":["*"],
            "":["can-empty-key"]
        }},"bindings":[
            {"agent_id":"h1","match":{"channel":"slack","peer":{"kind":"direct","id":"999"}}},
            {"agent_id":"h2","match":{"channel":"telegram","peer":{"kind":"direct","id":"tg:777"}}},
            {"agent_id":"h3","match":{"channel":"telegram","peer":{"kind":"direct","id":":7"}}},
            {"agent_id":"h4","match":{"channel":"telegram","peer":{"kind":"direct","id":"TG:up"}}},
            {"agent_id":"h5","match":{"channel":"SLACK","peer":{"kind":"direct","id":"999"}}},
            {"agent_id":"h6","match":{"channel":"slack","peer":{"kind":"direct","id":"*"}}},
            {"agent_id":"h7","match":{"channel":"slack","peer":{"kind":"direct","id":"CAN-EMPTY-KEY"}}}
        ]}"#,
    );
    assert_eq!(
        rules(&parse(&text)),
        vec![
            r#"{"name":"legacy-binding-1","agent":"h1","when":{"channel":"slack","account":"default","sender":"can-qualified"}}"#,
            r#"{"name":"legacy-binding-2","agent":"h2","when":{"channel":"telegram","account":"default","sender":"can-suffix"}}"#,
            r#"{"name":"legacy-binding-3","agent":"h3","when":{"channel":"telegram","account":"default","sender":":7"}}"#,
            r#"{"name":"legacy-binding-4","agent":"h4","when":{"channel":"telegram","account":"default","sender":"can-uppercase"}}"#,
            r#"{"name":"legacy-binding-5","agent":"h5","when":{"channel":"slack","account":"default","sender":"can-qualified"}}"#,
            r#"{"name":"legacy-binding-6","agent":"h6","when":{"channel":"slack","account":"default","sender":"can-star"}}"#,
            r#"{"name":"legacy-binding-7","agent":"h7","when":{"channel":"slack","account":"default","sender":"can-empty-key"}}"#,
        ],
        "every candidate spelling Go tries, and the two it does not: {text}"
    );
}

#[test]
fn a_peer_id_two_identity_link_keys_claim_answers_in_document_order() {
    // Probe shape `j`, measured 2026-11-14: one input, one binary, five separate processes gave
    //
    //     key-one  key-one  key-three  key-one  key-one
    //
    // for the first rule's `sender`, because `resolveLegacyBindingLinkedID` walks the links `map`
    // and returns the first canonical key holding the id (`legacy_bindings.go:250`). There is no Go
    // answer to reproduce, so the port takes the order the file lists the keys in and stays there;
    // `docs/DIVERGENCES.md` records why this shape stays out of the corpus. The second rule is the
    // control: only one key claims `other`, and its answer never moves.
    let (_, text) = round_trip(
        r#"{"version":2,"session":{"identity_links":{
            "key-one":["dup"],"key-two":["dup"],"key-three":["other","dup"]
        }},"bindings":[
            {"agent_id":"j1","match":{"channel":"telegram","peer":{"kind":"direct","id":"dup"}}},
            {"agent_id":"j2","match":{"channel":"telegram","peer":{"kind":"direct","id":"OTHER"}}}
        ]}"#,
    );
    assert_eq!(
        rules(&parse(&text)),
        vec![
            r#"{"name":"legacy-binding-1","agent":"j1","when":{"channel":"telegram","account":"default","sender":"key-one"}}"#,
            r#"{"name":"legacy-binding-2","agent":"j2","when":{"channel":"telegram","account":"default","sender":"key-three"}}"#,
        ],
        "two keys claim `dup`, so the file's own order decides: {text}"
    );
}

#[test]
fn bindings_that_cannot_be_expressed_are_dropped_and_keep_their_siblings_numbered() {
    // Four shapes Go's `dropped` counter covers: no agent, a blank channel, a peer kind that
    // is none of the four, a peer id that is blank after trimming. The surviving rule is
    // *named for its own position*, which is what distinguishes this from renumbering.
    let (_, text) = round_trip(
        r#"{"version":2,"bindings":[
            {"agent_id":"","match":{"channel":"telegram"}},
            {"agent_id":"nochan","match":{"channel":"  "}},
            {"agent_id":"badpeer","match":{"channel":"telegram","peer":{"kind":"whatever","id":"x"}}},
            {"agent_id":"emptypeer","match":{"channel":"telegram","peer":{"kind":"direct","id":"  "}}},
            {"agent_id":"ok","match":{"channel":"telegram"}}
        ]}"#,
    );
    assert_eq!(
        rules(&parse(&text)),
        vec![
            r#"{"name":"legacy-binding-5","agent":"ok","when":{"channel":"telegram","account":"default"}}"#
        ],
        "{text}"
    );
}

#[test]
fn one_bad_field_loses_every_rule_in_the_array() {
    // The decode is all-or-nothing: `json.Unmarshal` fills the whole `[]legacyAgentBinding`
    // in one pass, so a numeric `agent_id` fails the array, not the entry -- and a failed
    // decode is a warning and a return, not a refusal. A port that skips the bad entry and
    // migrates the rest invents routing the shipped binary drops, which is the loud kind of
    // wrong: the user's messages start going to an agent Go would have left unanswered.
    let (error, text) = round_trip(
        r#"{"version":2,"bindings":[{"agent_id":5,"match":{"channel":"telegram"}},{"agent_id":"ok","match":{"channel":"telegram"}}]}"#,
    );
    assert_eq!(
        error, None,
        "a lost migration is not a failed load: {error:?}"
    );
    let file = parse(&text);
    assert!(
        file.get("bindings").is_none(),
        "the key is still deleted: {text}"
    );
    assert!(rules(&file).is_empty(), "and no rule survives: {text}");
    assert!(
        keys(&file, &["agents"]) == ["defaults"] || keys(&file, &["agents"]).is_empty(),
        "no empty `dispatch` is written either: {text}"
    );
}

#[test]
fn a_null_element_is_dropped_but_still_counts() {
    // A `null` element decodes into the zero value, so it is dropped for having no channel --
    // while the entry after it is still `legacy-binding-2`, because the index is the array's.
    let (_, text) = round_trip(
        r#"{"version":2,"bindings":[null,{"agent_id":"ok","match":{"channel":"telegram"}}]}"#,
    );
    assert_eq!(
        rules(&parse(&text)),
        vec![
            r#"{"name":"legacy-binding-2","agent":"ok","when":{"channel":"telegram","account":"default"}}"#
        ],
        "{text}"
    );
}

#[test]
fn an_array_shaped_value_that_is_not_an_array_migrates_nothing() {
    // `bindings: null` is found and empty; `[]` is empty; an object is a decode error. All
    // three end the same way on disk, and none of them is an error.
    for body in [
        r#"{"version":2,"bindings":null}"#,
        r#"{"version":2,"bindings":[]}"#,
        r#"{"version":2,"bindings":{"agent_id":"a","match":{"channel":"telegram"}}}"#,
    ] {
        let (error, text) = round_trip(body);
        assert_eq!(error, None, "{body} must load, got {error:?}");
        let file = parse(&text);
        assert!(
            rules(&file).is_empty(),
            "{body} must migrate nothing: {text}"
        );
        assert!(file.get("bindings").is_none(), "{body}: {text}");
    }
}

#[test]
fn an_existing_dispatch_rule_is_kept_and_the_legacy_array_ignored() {
    // `legacy_bindings.go:52`: configured rules win outright. Not merged, not appended -- a
    // port that appends would silently re-route traffic the user moved to another agent.
    let (_, text) = round_trip(
        r#"{"version":2,"agents":{"dispatch":{"rules":[{"name":"mine","agent":"explicit","when":{"channel":"telegram"}}]}},"bindings":[{"agent_id":"legacy","match":{"channel":"discord","guild_id":"G1"}}]}"#,
    );
    assert_eq!(
        rules(&parse(&text)),
        vec![r#"{"name":"mine","agent":"explicit","when":{"channel":"telegram"}}"#],
        "the document's own rule stands alone: {text}"
    );
}

#[test]
fn an_empty_rules_array_does_not_guard() {
    // The guard is `Dispatch != nil && len(Rules) > 0`, so `rules: []` is not a configured
    // rule set and the migration fills it.
    let (_, text) = round_trip(
        r#"{"version":2,"agents":{"dispatch":{"rules":[]}},"bindings":[{"agent_id":"legacy","match":{"channel":"telegram"}}]}"#,
    );
    assert_eq!(
        rules(&parse(&text)),
        vec![
            r#"{"name":"legacy-binding-1","agent":"legacy","when":{"channel":"telegram","account":"default"}}"#
        ],
        "{text}"
    );
}

#[test]
fn a_bindings_key_only_the_security_file_mentions_is_not_migrated() {
    // The array is decoded out of `data`, config.json's own bytes (`config.go:1514`) -- not
    // out of the map `loadConfigMap` merged with `.security.yml`. So a legacy security file
    // that carries `bindings` has it dropped by the ladder and never rewritten, and a port
    // that reads the merged document would migrate a rule Go never sees.
    let (error, text) = round_trip_pair(
        r#"{"version":2}"#,
        "bindings:\n  - agent_id: sec-agent\n    match:\n      channel: telegram\n",
    );
    assert_eq!(error, None, "{error:?}");
    let file = parse(&text);
    assert!(
        rules(&file).is_empty(),
        "the security file's bindings are not migrated: {text}"
    );
}

#[test]
fn every_legacy_version_reaches_the_same_migration() {
    // `case 0..=2` shares one arm, and the array is read after the ladder, so a v0 document
    // (which is what an absent `version` means) and a v1 document are migrated the same way.
    for body in [
        r#"{"bindings":[{"agent_id":"a","match":{"channel":"telegram"}}]}"#,
        r#"{"version":1,"bindings":[{"agent_id":"a","match":{"channel":"telegram"}}]}"#,
        r#"{"version":2,"bindings":[{"agent_id":"a","match":{"channel":"telegram"}}]}"#,
    ] {
        let (error, text) = round_trip(body);
        assert_eq!(error, None, "{body} must load, got {error:?}");
        assert_eq!(
            rules(&parse(&text)),
            vec![
                r#"{"name":"legacy-binding-1","agent":"a","when":{"channel":"telegram","account":"default"}}"#
            ],
            "{body}: {text}"
        );
    }
}

#[test]
fn the_current_version_refuses_the_key_and_leaves_the_file_alone() {
    // The other half of the asymmetry, pinned beside the first so the two cannot drift apart:
    // the same bytes are a migration at v2 and an unknown field at v3.
    let body = r#"{"version":3,"bindings":[{"agent_id":"a","match":{"channel":"telegram"}}]}"#;
    let (error, text) = round_trip(body);
    let message = error.expect("v3 must refuse the key");
    assert!(
        message.contains("unknown field(s)") && message.contains("bindings"),
        "Go's own sentence, got {message}"
    );
    assert_eq!(text, body, "a refusal writes nothing: {text}");
}

#[test]
fn the_loaded_value_carries_the_rules_too() {
    // The corpus records a `load` as the typed config re-marshalled by `encoding/json`
    // (`cmd/oracle/config.go:237-243`), and `applyLegacyBindingsMigration` mutates that same
    // struct, so the recorded value and the written file agree. A port that rewrote only the
    // file would be right on disk and wrong in every recorded query.
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");
    fs::write(
        &config_path,
        r#"{"version":2,"bindings":[{"agent_id":"a","match":{"channel":"telegram"}}]}"#,
    )
    .expect("write config.json");

    let cfg = crab_config::load(&config_path, "/home/oracle").expect("a v2 document loads");
    let value = loaded_value(&cfg.document, &config_schema());
    assert!(
        value.contains(r#""dispatch":{"rules":[{"name":"legacy-binding-1""#),
        "the loaded value carries the migrated rules; got {value}"
    );
}
