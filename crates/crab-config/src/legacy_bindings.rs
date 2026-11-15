//! The legacy `bindings` array, and the dispatch rules it becomes when it can be read.
//!
//! Go: `pkg/config/legacy_bindings.go`, called by `LoadConfig` at `config.go:1514` -- after
//! the version ladder, the decode and the security file, and before `env.Parse` and every
//! validator. That position is the whole point of the module. A migration arm registers
//! `defer func(cfg *Config){ _ = SaveConfig(path, cfg) }(cfg)` (`config.go:1379`) over the
//! same `cfg` this stage mutates, so a migrated document reaches the disk **with**
//! `agents.dispatch.rules` and **without** `bindings`: the rewrite is not merely in memory,
//! it is what the user's next start reads.
//!
//! # Why one key is two rules (rusty-crab#32)
//!
//! `bindings` is a known key on the legacy path and an unknown one at the current version.
//! The legacy arms validate against `legacyDiagnosticConfig` (`migration.go:30-46`), which
//! declares `bindings` at `:44`; the current-version path validates against `Config`, which
//! has no such field. Measured one process per shape against the shipped binary, same array
//! at both versions:
//!
//! ```text
//! version 2 + bindings   loads, writes agents.dispatch.rules, bindings gone, "version": 3
//! version 3 + bindings   config.json contains unknown field(s): bindings -- file untouched
//! ```
//!
//! Before this module the port only did half of the first line: `migrate_v2_to_v3` deletes
//! the key (`lib.rs`, "bindings is deleted outright") because nothing could hold it, and
//! nothing put the rules anywhere. A v2 config with bindings therefore loaded clean, wrote a
//! file both binaries accept, and silently lost every routing rule the user had configured --
//! the config keeps loading, so nothing downstream ever notices. That is why the fix is the
//! rewrite and not the delete.
//!
//! # What the shapes pin
//!
//! * The array is decoded out of **config.json's own bytes**, not out of the map
//!   `load_config_map` merged with `.security.yml` (`data`, at `config.go:1514`, is still the
//!   file). A `bindings` only the security file mentions is dropped by the ladder and never
//!   migrated -- measured, and pinned by `a_bindings_key_only_the_security_file_mentions_is_not_migrated`.
//! * The decode is **all-or-nothing**: `json.Unmarshal` fills the whole `[]legacyAgentBinding`
//!   in one pass, so one `agent_id` holding a number loses every rule in the array rather than
//!   that entry alone. Two shapes in `tests/legacy_bindings.rs` hold that line.
//! * Rule order is **(kind, original index)**, not index: `migrateLegacyBindings`
//!   (`legacy_bindings.go:100`) buckets by kind and concatenates, while the name keeps the
//!   binding's own 1-based position (`legacy-binding-7`). Peers are kind 0, a guild space 1,
//!   a team space 2, a plain account match 3, a wildcard account 4. Unlike the ledger's map-order
//!   divergences this is reproducible -- it is a fixed `for kind := 0; kind <= 4` pass over the
//!   array -- and measured that way: five processes on the eleven-binding document returned the
//!   same order each time (`3 11 12 13 14 1 6 15 5 2 4`), and this crate emits the rules in that
//!   order for the same document. `rules_are_ordered_by_kind_and_then_by_the_position_they_came_from`
//!   pins the same bucket order on a document the corpus can carry.
//! * An existing `agents.dispatch.rules` wins outright and the legacy array is ignored
//!   (`legacy_bindings.go:52`) -- not merged, not appended to.

use crate::doc::Doc;

/// `legacyDefaultAccountID` (`legacy_bindings.go:11`): what a binding with no `account_id`
/// matches on, because `normalizeLegacyAccountSelector` never returns an empty string.
const LEGACY_DEFAULT_ACCOUNT_ID: &str = "default";

/// One decoded entry of the array (`legacyAgentBinding` + `legacyBindingMatch` +
/// `legacyPeerMatch`, `legacy_bindings.go:17-33`). Every string is the JSON value as
/// written: Go's trimming and lower-casing all happen in `migrateLegacyBinding`, so
/// decoding must not do any of it or the name and the peer id would be trimmed twice.
#[derive(Default)]
struct Binding {
    agent_id: String,
    channel: String,
    account_id: String,
    peer: Option<Peer>,
    guild_id: String,
    team_id: String,
}

/// `legacyPeerMatch`. `None` for the whole struct is Go's nil pointer, which is what an
/// absent or `null` `peer` decodes to.
struct Peer {
    kind: String,
    id: String,
}

/// The selector under construction, in `DispatchSelector`'s declaration order
/// (`config.go:340`). Go mutates one struct in whatever order the branches fall through, and
/// `json.Marshal` then emits declaration order regardless; holding the fields in a struct and
/// rendering once reproduces that without tracking which branch set what.
#[derive(Default)]
struct Selector {
    channel: String,
    account: String,
    space: String,
    chat: String,
    topic: String,
    sender: String,
}

impl Selector {
    /// The rule's `when` object. Every field of `DispatchSelector` is `omitempty`, so an
    /// unset one is absent from the bytes rather than `""`; `mentioned` is a `*bool` this
    /// migration never fills, so it is absent by construction.
    fn into_doc(self) -> Doc {
        let mut fields = Vec::new();
        for (key, value) in [
            ("channel", self.channel),
            ("account", self.account),
            ("space", self.space),
            ("chat", self.chat),
            ("topic", self.topic),
            ("sender", self.sender),
        ] {
            if !value.is_empty() {
                fields.push((key.to_string(), Doc::String(value)));
            }
        }
        Doc::Object(fields)
    }
}

/// Applies Go's migration to a document that has already been through the ladder.
///
/// `raw_bindings` is the `bindings` value from the **pre-migration** config.json, which the
/// caller has to keep because the ladder deletes the key out of the document it returns.
pub fn apply(document: &mut Doc, raw_bindings: Option<&Doc>) {
    // A missing key is `len(envelope.Bindings) == 0`: not found, and nothing to warn about
    // (`legacy_bindings.go:84`). Anything that fails the decode is Go's `logger.WarnF` and a
    // return: the load succeeds, and `bindings` stays deleted by the ladder.
    let Ok(bindings) = decode(raw_bindings) else {
        return;
    };
    if bindings.is_empty() {
        return;
    }
    if rules_already_configured(document) {
        return;
    }

    let identity_links = document
        .get("session")
        .and_then(|session| session.get("identity_links"));
    let rules = migrate(&bindings, identity_links);
    if rules.is_empty() {
        // "could not be migrated": every entry was dropped, so the document keeps whatever
        // `agents.dispatch` it had rather than gaining an empty `rules` array.
        return;
    }
    install(document, rules);
}

/// Go's decode, including the two ways it produces nothing at all.
fn decode(raw: Option<&Doc>) -> Result<Vec<Binding>, ()> {
    match raw {
        None => Ok(Vec::new()),
        // `"bindings": null` is a non-empty `json.RawMessage`, so it *is* found, and then
        // decodes to a nil slice: no rules, and no error either.
        Some(Doc::Null) => Ok(Vec::new()),
        Some(Doc::Array(items)) => items.iter().map(decode_binding).collect(),
        // An object, a string, a number: `json.Unmarshal` into `[]legacyAgentBinding` fails,
        // and the failure belongs to the array, not to one entry.
        Some(_) => Err(()),
    }
}

fn decode_binding(entry: &Doc) -> Result<Binding, ()> {
    let fields = match entry {
        // A `null` element decodes into the zero value and survives to be dropped for having
        // no channel -- while keeping its index, which is what names its siblings.
        Doc::Null => return Ok(Binding::default()),
        Doc::Object(fields) => fields.as_slice(),
        _ => return Err(()),
    };

    let mut binding = Binding {
        agent_id: string_field(fields, "agent_id")?,
        ..Binding::default()
    };
    if let Some(matched) = object_field(fields, "match")? {
        binding.channel = string_field(matched, "channel")?;
        binding.account_id = string_field(matched, "account_id")?;
        binding.guild_id = string_field(matched, "guild_id")?;
        binding.team_id = string_field(matched, "team_id")?;
        if let Some(peer) = object_field(matched, "peer")? {
            binding.peer = Some(Peer {
                kind: string_field(peer, "kind")?,
                id: string_field(peer, "id")?,
            });
        }
    }
    Ok(binding)
}

/// A `string` field: absent and `null` leave the zero value, any other type is Go's decode
/// error. Unknown keys are simply not read -- `json.Unmarshal` ignores what it has no field
/// for, which is why a legacy array full of extra keys still migrates.
fn string_field(fields: &[(String, Doc)], key: &str) -> Result<String, ()> {
    match fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
    {
        None | Some(Doc::Null) => Ok(String::new()),
        Some(Doc::String(value)) => Ok(value.clone()),
        Some(_) => Err(()),
    }
}

/// A struct field, as `match` and `peer` are: `Some` when it is an object, `None` when it is
/// absent or `null` (Go leaves the value struct or the nil pointer alone), an error when it is
/// anything else.
fn object_field<'a>(
    fields: &'a [(String, Doc)],
    key: &str,
) -> Result<Option<&'a Vec<(String, Doc)>>, ()> {
    match fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
    {
        None | Some(Doc::Null) => Ok(None),
        Some(Doc::Object(entries)) => Ok(Some(entries)),
        Some(_) => Err(()),
    }
}

/// `legacy_bindings.go:52`: dispatch rules that are already configured win, and the legacy
/// array is ignored whole. `rules: []` is empty, so it does *not* guard -- Go allocates and
/// fills `Rules` there.
fn rules_already_configured(document: &Doc) -> bool {
    document
        .path(&["agents", "dispatch", "rules"])
        .and_then(Doc::as_array)
        .is_some_and(|rules| !rules.is_empty())
}

/// `migrateLegacyBindings` (`legacy_bindings.go:100`): drop what cannot be expressed, then
/// concatenate the kind buckets in ascending kind, each bucket in the array's own order.
fn migrate(bindings: &[Binding], identity_links: Option<&Doc>) -> Vec<Doc> {
    let mut prioritized: Vec<(u8, Doc)> = Vec::new();
    for (index, binding) in bindings.iter().enumerate() {
        if let Some((kind, rule)) = migrate_binding(binding, index, identity_links) {
            prioritized.push((kind, rule));
        }
    }

    let mut rules = Vec::new();
    for kind in 0..=4u8 {
        rules.extend(
            prioritized
                .iter()
                .filter(|(bucket, _)| *bucket == kind)
                .map(|(_, rule)| rule.clone()),
        );
    }
    rules
}

/// `migrateLegacyBinding` (`legacy_bindings.go:136`), returning its kind alongside the rule.
/// The `None` cases are Go's `dropped` counter, and each has its own shape: no agent, no
/// channel, a peer id that is blank after trimming, a peer kind that is none of the four.
fn migrate_binding(
    binding: &Binding,
    index: usize,
    identity_links: Option<&Doc>,
) -> Option<(u8, Doc)> {
    let channel = binding.channel.trim().to_lowercase();
    let agent = binding.agent_id.trim();
    if channel.is_empty() || agent.is_empty() {
        return None;
    }

    let account = normalize_account(&binding.account_id);
    let mut when = Selector {
        channel,
        ..Selector::default()
    };
    // Go's guard is `switch normalizeLegacyAccountSelector(...) { case "": case "*": }`, and
    // normalize never returns `""` -- so the only account left out of the selector is the
    // wildcard, and a binding that spells no account gets `"default"`. The dead `case "":`
    // is the reason a bare `{channel}` binding is `account: "default"` rather than `when:
    // {channel}`, and it is visible on every rule of the measured shape.
    if account != "*" {
        when.account = account.clone();
    }

    if let Some(peer) = &binding.peer {
        let kind = peer.kind.trim().to_lowercase();
        let id = peer.id.trim();
        if id.is_empty() {
            return None;
        }
        match kind.as_str() {
            // `direct` is the one selector field the identity links can rewrite.
            "direct" => when.sender = canonical_sender(&when.channel, id, identity_links),
            // `group` and `channel` share a field, and the prefix keeps whichever was written
            // -- so `"kind":"GROUP"` becomes `chat: "group:C5"`, with the id untouched.
            "group" | "channel" => when.chat = format!("{kind}:{id}"),
            "topic" => when.topic = format!("topic:{id}"),
            _ => return None,
        }
        return Some((0, rule(when, index, agent)));
    }

    if !binding.guild_id.trim().is_empty() {
        when.space = format!("guild:{}", binding.guild_id.trim());
        return Some((1, rule(when, index, agent)));
    }
    if !binding.team_id.trim().is_empty() {
        when.space = format!("team:{}", binding.team_id.trim());
        return Some((2, rule(when, index, agent)));
    }
    if account == "*" {
        // The wildcard is a rule with no account selector at all: clearing it is what makes
        // the rule match every account of the channel.
        when.account = String::new();
        return Some((4, rule(when, index, agent)));
    }
    Some((3, rule(when, index, agent)))
}

fn rule(when: Selector, index: usize, agent: &str) -> Doc {
    // `DispatchRule`'s declaration order (`config.go:333`): name, agent, when,
    // session_dimensions. `name` and `agent` are never empty here -- `name` has no omitempty
    // effect to observe, and `agent` has none at all -- and `session_dimensions` is
    // `omitempty` and unfilled, so it is absent.
    Doc::Object(vec![
        (
            "name".to_string(),
            Doc::String(format!("legacy-binding-{}", index + 1)),
        ),
        ("agent".to_string(), Doc::String(agent.to_string())),
        ("when".to_string(), when.into_doc()),
    ])
}

/// `normalizeLegacyAccountSelector` (`legacy_bindings.go:203`).
fn normalize_account(account_id: &str) -> String {
    let account = account_id.trim();
    match account {
        "" => LEGACY_DEFAULT_ACCOUNT_ID.to_string(),
        "*" => "*".to_string(),
        other => other.to_lowercase(),
    }
}

/// `canonicalLegacyBindingSenderID` (`legacy_bindings.go:215`): an identity link's canonical
/// id when one matches, the peer id lower-cased otherwise.
fn canonical_sender(channel: &str, peer_id: &str, identity_links: Option<&Doc>) -> String {
    let peer = peer_id.trim();
    if peer.is_empty() {
        return String::new();
    }
    match resolve_linked_id(identity_links, channel, peer) {
        Some(linked) => linked.to_lowercase(),
        None => peer.to_lowercase(),
    }
}

/// `resolveLegacyBindingLinkedID` (`legacy_bindings.go:228`): the three spellings a link's
/// value list is matched against -- the id itself, the channel-qualified id, and the part
/// after the first colon -- and then the first link that names any of them.
///
/// Which *spelling* matched is deterministic in both binaries: Go builds the three into a
/// `map[string]struct{}` and only tests membership. Which *key* answers is not, because Go walks
/// the links map itself (`legacy_bindings.go:250`) and returns the first canonical key whose list
/// holds a candidate: measured on a document where `key-one` and `key-three` both claim `dup`,
/// five processes gave `key-one key-one key-three key-one key-one`. This walk follows the file's
/// own order instead, so the port answers `key-one` every time. `docs/DIVERGENCES.md` records why
/// that shape stays out of the corpus rather than pinned to either answer here.
fn resolve_linked_id(links: Option<&Doc>, channel: &str, peer_id: &str) -> Option<String> {
    let links = links.and_then(Doc::as_object)?;
    if links.is_empty() {
        return None;
    }

    let raw = peer_id.to_lowercase();
    let mut candidates = vec![raw.clone()];
    if !channel.is_empty() {
        candidates.push(format!("{channel}:{raw}"));
    }
    // Go's condition is `idx > 0 && idx < len-1`: a non-empty prefix and a non-empty suffix,
    // split on the *first* colon and keeping the rest of the string whole.
    if let Some((prefix, suffix)) = raw.split_once(':') {
        if !prefix.is_empty() && !suffix.is_empty() {
            candidates.push(suffix.to_string());
        }
    }

    for (canonical, ids) in links {
        let canonical = canonical.trim();
        if canonical.is_empty() {
            continue;
        }
        let Some(ids) = ids.as_array() else {
            // Go's `map[string][]string` would have refused the document at the decode. The
            // port does not refuse a mistyped slice everywhere (`schema::misplaced_secure_strings`
            // is the one named type it checks), so this is the same tracked gap, not a rule.
            continue;
        };
        for id in ids {
            let Some(value) = id.as_str() else { continue };
            let value = value.trim().to_lowercase();
            if value.is_empty() {
                continue;
            }
            if candidates.iter().any(|candidate| candidate == &value) {
                return Some(canonical.to_string());
            }
        }
    }
    None
}

/// Puts the rules where `AgentsConfig` declares them.
fn install(document: &mut Doc, rules: Vec<Doc>) {
    if document.get("agents").is_none() {
        document.set("agents", Doc::Object(Vec::new()));
    }
    let Some(agents) = document.get_mut_at("agents").and_then(Doc::as_object_mut) else {
        // Not an object: Go's typed decode refused a document like this two stages earlier,
        // so there is no on-disk shape here to agree with.
        return;
    };

    // `dispatch` is `AgentsConfig`'s last field (`config.go:269`) and the document is held in
    // declaration order, so appending it when the file had none is what puts it where Go
    // writes it: `{"defaults": …, "dispatch": …}`.
    if !agents.iter().any(|(name, _)| name == "dispatch") {
        agents.push(("dispatch".to_string(), Doc::Object(Vec::new())));
    }
    let Some((_, dispatch)) = agents.iter_mut().find(|(name, _)| name == "dispatch") else {
        return;
    };
    let Some(fields) = dispatch.as_object_mut() else {
        return;
    };

    // `DispatchConfig` has the one field, so replacing `rules` in place and appending are the
    // same position -- but only because there is nothing else to land after.
    match fields.iter_mut().find(|(name, _)| name == "rules") {
        Some((_, slot)) => *slot = Doc::Array(rules),
        None => fields.push(("rules".to_string(), Doc::Array(rules))),
    }
}
