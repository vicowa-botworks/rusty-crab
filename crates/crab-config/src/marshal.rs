//! Marshalling a config: the omit rules, and the one field that is not a tag.
//!
//! The document a config *file* holds is not the document the struct holds. Go drops
//! fields whose tag says so, and `Config` additionally has a hand-written
//! [`MarshalJSON`](https://github.com/sipeed/picoclaw) that shadows one field with a
//! pointer so it can be omitted at all. Both belong here, because the corpus compares
//! the file.
//!
//! ## `omitempty` on a struct does nothing
//!
//! `isolation`, `evolution`, `events`, `hooks` and `build_info` all carry
//! `json:"…,omitempty"` and all appear in the saved file as `{}`. That is not a
//! contradiction: `omitempty` is defined over the *zero* values — false, 0, an empty
//! string, a nil or empty slice or map — and a struct value is never one of them. Go
//! added `omitzero` in 1.24 precisely because `omitempty` could not be made to do this
//! without breaking every existing tag.
//!
//! So the pass below applies the option only where the schema says the field is not a
//! struct, and the corpus case that saves an empty `isolation` is what keeps that
//! reading honest.
//!
//! ## `omitzero` is not the whole story for a secret
//!
//! `token,omitzero` over a `SecureString` and `api_keys,omitzero` over a `SecureStrings`
//! are dropped from the JSON rendering even when they are full. Neither the option nor
//! emptiness decides that: both types implement `MarshalJSON` and return **nil bytes**,
//! and encoding/json omits a field when its Marshaler does that, without consulting the
//! tag. The dump carries the type name at every one of them, so the pass drops them by
//! name. This is the stage that keeps `sk-1` out of `config.json` while
//! `.security.yml` carries it, and the reason no recorded loaded value contains a secret.
//!
//! ## `session` is omitted by code, not by a tag
//!
//! `Config.MarshalJSON` builds an anonymous struct that declares
//! `Session *SessionConfig json:"session,omitempty"` alongside the embedded real
//! `Config`, and sets it only when
//!
//! ```text
//! len(Dimensions) > 0 || len(IdentityLinks) > 0 || DmScope != ""
//! ```
//!
//! Three consequences, all of them visible in the fixture:
//!
//! * the field is a *pointer*, which is what makes `omitempty` able to fire at all —
//!   the real field is a value and could never be omitted by its own tag;
//! * the shadowed field is declared **before** the embedded alias, so when `session`
//!   is present it is the **first key in the file**, ahead of `version`. The default
//!   table shows exactly that, and `session_omitted_when_empty` shows the file
//!   starting at `version` instead;
//! * the emptiness test is those three fields and no others. A `SessionConfig` with
//!   some other field set is still omitted.
//!
//! A port that reads only the struct tags concludes "omitempty on a value struct never
//! fires, so always write session" — a defensible reading of the source, and wrong on
//! every file the shipped binary writes.

use crate::doc::Doc;
use crate::schema::Schema;

/// The `session` shadow, applied to a merged document.
///
/// Returns the document with `session` either first or absent. Everything else keeps
/// its position: the shadow only moves the one key it owns.
#[must_use]
pub fn apply_session_shadow(mut document: Doc) -> Doc {
    let Some(session) = document.get("session") else {
        return document;
    };
    let present = is_present(session);
    if !present {
        document.remove("session");
        return document;
    }
    // Re-insert at the front. `Doc::set` replaces in place, which would leave the key
    // wherever the defaults table happened to put it; the Go aux struct declares it
    // first, so the file has it first.
    let Some(entries) = document.as_object_mut() else {
        return document;
    };
    let Some(position) = entries.iter().position(|(k, _)| k == "session") else {
        return document;
    };
    let (_, value) = entries.remove(position);
    entries.insert(0, ("session".to_string(), value));
    document
}

/// `len(Dimensions) > 0 || len(IdentityLinks) > 0 || DmScope != ""`.
///
/// `IdentityLinks` is a `map[string][]string`, so its emptiness is "no entries" -- not
/// "no entries with a non-empty list". `{"a": []}` has length 1 in Go and keeps the
/// section, which is why the map arm below counts keys rather than looking through
/// them.
fn is_present(session: &Doc) -> bool {
    let non_empty_array = |key: &str| {
        session
            .get(key)
            .and_then(Doc::as_array)
            .is_some_and(|items| !items.is_empty())
    };
    let non_empty_map = |key: &str| {
        session
            .get(key)
            .and_then(Doc::as_object)
            .is_some_and(|entries| !entries.is_empty())
    };
    non_empty_array("dimensions")
        || non_empty_map("identity_links")
        || session
            .get("dm_scope")
            .and_then(Doc::as_str)
            .is_some_and(|s| !s.is_empty())
}

/// Drops every field whose omit option applies to its value.
///
/// Walked against the schema rather than over the document alone, because "is this
/// empty?" is a question about the *declared type*: an empty object is an empty map
/// (omit it) and a non-empty struct (keep it), and the document cannot tell those
/// apart on its own.
#[must_use]
pub fn apply_omit(document: &Doc, schema: &Schema) -> Doc {
    match (document, schema) {
        (Doc::Object(entries), Schema::Struct { .. }) => {
            let mut out = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let Some(child) = schema.field(key) else {
                    // Not a field at all. The validator refuses such a document, so
                    // this arm only runs on a document that never went through it --
                    // keep the data rather than silently dropping it.
                    out.push((
                        key.clone(),
                        apply_omit(
                            value,
                            &Schema::Scalar {
                                omit: None,
                                name: None,
                                marshaler: false,
                            },
                        ),
                    ));
                    continue;
                };
                if matches!(child.name(), Some("SecureString") | Some("SecureStrings")) {
                    // Go's `SecureString`/`SecureStrings` `MarshalJSON` returns nil bytes,
                    // and encoding/json omits a field outright when its Marshaler does
                    // that -- the tag never gets asked. So a secret never reaches
                    // config.json, and never appears in the marshalled loaded value, which
                    // is why the corpus records no secret anywhere and why a load-side case
                    // cannot witness the security merge. The yaml half is the other story:
                    // `yaml:"token,omitempty"` is an ordinary field to yaml.v3, so
                    // `.security.yml` carries the value. See `docs/ARCHITECTURE.md` on
                    // loader side-state.
                    continue;
                }
                if is_dropped_by_omit(child, value) {
                    continue;
                }
                out.push((key.clone(), apply_omit(value, child)));
            }
            Doc::Object(out)
        }
        (Doc::Array(items), Schema::Slice { elem, .. }) => {
            Doc::Array(items.iter().map(|item| apply_omit(item, elem)).collect())
        }
        (Doc::Object(entries), Schema::Map { elem, .. }) => {
            let mut out: Vec<(String, Doc)> = entries
                .iter()
                .map(|(k, v)| (k.clone(), apply_omit(v, elem)))
                .collect();
            // A Go map has no order, and `encoding/json` gives it one by sorting the
            // keys. So `channel_list` comes out a, b, deltachat, dingtalk -- not the
            // order the file or the defaults table happened to list them in. Equal
            // bytes either way to anything that parses it, and a different document to
            // anything that compares them, which is what this seam compares.
            out.sort_by(|(a, _), (b, _)| a.cmp(b));
            Doc::Object(out)
        }
        (other, _) => other.clone(),
    }
}

/// Go's `isEmpty`, restricted to the types where the option can fire.
///
/// The struct case is the whole point of the function and it returns `false`: a
/// non-pointer struct is never empty, which is why `isolation: {}` survives its own
/// `omitempty`. A map or slice is empty at length zero, including a nil one, and a
/// pointer-to-struct is not modelled here because `Config` has no such field at the
/// top level.
pub(crate) fn is_empty_by_go(value: &Doc, schema: &Schema) -> bool {
    if matches!(schema, Schema::Struct { .. }) {
        return false;
    }
    // A byte-holder is not a string here. `RawNode` and `json.RawMessage` hold encoded
    // JSON, so `null` is the only document form that means nil; an empty *object* is two
    // non-nil bytes, which is why a slack channel keeps `"settings": {}` past
    // `settings,omitzero` once InitChannelList has decoded its settings struct.
    if matches!(
        schema.name(),
        Some("RawNode") | Some("json.RawMessage") | Some("[]byte")
    ) {
        return matches!(value, Doc::Null);
    }
    match value {
        Doc::Null => true,
        Doc::Bool(false) => true,
        Doc::Int(0) => true,
        Doc::Float(f) => *f == 0.0,
        Doc::String(s) => s.is_empty(),
        Doc::Array(items) => items.is_empty(),
        Doc::Object(entries) => entries.is_empty(),
        _ => false,
    }
}

/// Whether the field's own encoding option drops this value -- the one place the crate
/// decides that, for both the marshal path and the channel projection.
///
/// `omitzero` and `omitempty` are *not* the same test, and the difference is exactly
/// where the channel settings live: `streaming` carries `omitzero`, so a zero
/// `StreamingConfig` disappears, while `group_trigger` carries `omitempty`, so an empty
/// `GroupTriggerConfig` is kept -- a struct is never "empty" to `omitempty`, which is
/// the same rule that keeps `isolation: {}` in the config file.
///
/// This used to live in `channels` while `apply_omit` routed *both* spellings through
/// `is_empty_by_go`, so which definition applied to a given value depended on which
/// stage touched it first. One rule, one place.
pub(crate) fn is_dropped_by_omit(schema: &Schema, value: &Doc) -> bool {
    // A `SecureString` is never written by `encoding/json`, whatever it holds. Its
    // `omitzero` option calls its `IsZero`, and that returns true for every caller
    // except the yaml encoder -- on the type's own comment, "to prevent marshal this
    // field". So the rule cannot come out of the omit option alone: `omitzero` on an
    // ordinary struct means "zero when every field is", and a `SecureString` holding a
    // token is not that. It has to come from the type.
    //
    // Answering before the option is read also prices `omitempty` on the same type, and
    // it buys the same silence: `omitempty` asks `isEmpty`, and `isEmpty(SecureString{v})`
    // is `v == ""` only for the yaml encoder, which is not the caller here. Every field
    // of this type in the schema today spells the option `omitzero`, so the two spellings
    // agree only because nothing has tried the other one yet -- a future `omitempty`
    // SecureString is dropped by this arm, not written.
    //
    // The one value that *must* survive is the hand-written `[NOT_HERE]` in
    // `skills::Registry::to_doc`, and it does because `registries` is an object under a
    // slice schema, so `apply_omit` never reaches this function for it. That is a
    // coupling, not a coincidence; both sides say so.
    if matches!(schema.name(), Some("SecureString") | Some("SecureStrings")) {
        return true;
    }
    match schema.omit() {
        None => false,
        Some("omitzero") => is_go_zero(schema, value),
        Some(_) => is_empty_by_go(value, schema),
    }
}

/// Go's `reflect.Value.IsZero`. Unlike `isEmpty`, this one *does* fire on a struct: it
/// is zero when every field is.
fn is_go_zero(schema: &Schema, value: &Doc) -> bool {
    match (value, schema) {
        (Doc::Object(entries), Schema::Struct { .. }) => entries.iter().all(|(key, value)| {
            schema
                .field(key)
                .is_some_and(|child| is_go_zero(child, value))
        }),
        // `IsZero` on a map or slice is *nil-ness*, not length: a non-nil empty slice is
        // not zero, so `omitzero` keeps it as `[]`. The document already carries the
        // distinction -- `Doc::Null` is nil, `Doc::Array(vec![])` is non-nil empty, the
        // same pair `project` preserves -- so reading length here would drop an `[]` that
        // Go writes. `omitempty` does test length, and that is `is_empty_by_go`.
        (Doc::Null, Schema::Map { .. } | Schema::Slice { .. }) => true,
        (Doc::Object(_), Schema::Map { .. }) | (Doc::Array(_), Schema::Slice { .. }) => false,
        _ => is_empty_by_go(value, schema),
    }
}

/// The config file's bytes: `json.MarshalIndent(cfg, "", "  ")` plus the trailing
/// newline `SaveConfig` writes.
///
/// The omit rules are applied here rather than by the caller, because in Go they are
/// not a step anyone can skip — they are the marshaller.
pub fn config_file(document: &Doc, schema: &Schema) -> Result<String, crate::Error> {
    let marshalled = apply_session_shadow(apply_omit(document, schema));
    let mut text = marshalled
        .to_indented_json()
        .map_err(|e| crate::Error::Io(e.to_string()))?;
    text.push('\n');
    Ok(text)
}

/// The loaded value: the same marshal, compact.
///
/// This is what the corpus records for a `load` query — the loaded `*Config`
/// re-marshalled by `encoding/json` — so it goes through the identical rules as the
/// file, minus the indentation.
#[must_use]
pub fn loaded_value(document: &Doc, schema: &Schema) -> String {
    apply_session_shadow(apply_omit(document, schema)).to_compact_json()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::from_json;
    use crate::schema::config_schema;

    fn doc(text: &str) -> Doc {
        from_json(text).into_doc()
    }

    #[test]
    fn an_empty_session_disappears() {
        let document =
            doc(r#"{"session":{"dimensions":[],"identity_links":{},"dm_scope":""},"version":3}"#);
        let out = apply_session_shadow(document);
        assert_eq!(out.to_compact_json(), r#"{"version":3}"#);
    }

    #[test]
    fn each_of_the_three_conditions_alone_keeps_session() {
        for body in [
            r#"{"dimensions":["chat"]}"#,
            r#"{"identity_links":{"a":["b"]}}"#,
            r#"{"identity_links":{"a":[]}}"#,
            r#"{"dm_scope":"per-channel"}"#,
        ] {
            let document = doc(&format!(r#"{{"version":3,"session":{body}}}"#));
            let out = apply_session_shadow(document);
            assert!(out.get("session").is_some(), "{body} must keep session");
        }
    }

    #[test]
    fn a_present_session_is_the_first_key() {
        // The aux struct declares it before the embedded alias, so the file leads with
        // it. A port that leaves it where the defaults table put it writes the same
        // data in the wrong order.
        let document = doc(r#"{"version":3,"session":{"dimensions":["chat"]}}"#);
        let out = apply_session_shadow(document);
        let keys: Vec<&str> = out
            .as_object()
            .expect("object")
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(keys[0], "session");
    }

    #[test]
    fn omitempty_on_a_struct_does_nothing() {
        // isolation is `json:"isolation,omitempty"` over a value struct, and the
        // fixture's saved file carries `"isolation": {}`.
        let schema = config_schema();
        let document = doc(r#"{"version":3,"isolation":{}}"#);
        let out = apply_omit(&document, &schema);
        assert!(out.get("isolation").is_some(), "a struct is never empty");
    }

    #[test]
    fn omitempty_on_a_slice_and_a_string_does_fire() {
        let schema = config_schema();
        let document = doc(r#"{"version":3,"session":{"dimensions":[],"dm_scope":""}}"#);
        let out = apply_omit(&document, &schema);
        let session = out.get("session").expect("session kept by the omit pass");
        assert!(
            session.get("dimensions").is_none(),
            "an empty slice is dropped"
        );
        assert!(
            session.get("dm_scope").is_none(),
            "an empty string is dropped"
        );
    }

    #[test]
    fn a_secure_field_is_dropped_however_full_it_is() {
        // `api_keys` is `json:"api_keys,omitzero"` over a non-empty `SecureStrings`, so
        // `omitempty`'s rule would keep it and Go does not: the Marshaler returns nil
        // bytes and encoding/json omits the field before the tag matters. The fixture's
        // `save_writes_both_halves` records a config.json with no `api_keys` key at all
        // while its `.security.yml` carries `sk-1`, and the same pair is what the loader
        // puts in the document -- so this is the only stage standing between a secret and
        // the file that is not the secrets file.
        let schema = config_schema();
        let document = doc(
            r#"{"version":3,"model_list":[{"model_name":"m1","api_keys":["sk-1"]}],
                "tools":{"skills":{"github":{"token":"ghp_1"}}}}"#,
        );
        let out = apply_omit(&document, &schema);
        let model = out
            .get("model_list")
            .and_then(Doc::as_array)
            .and_then(|items| items.first())
            .expect("the model is kept");
        assert_eq!(
            model.get("model_name").and_then(Doc::as_str),
            Some("m1"),
            "the entry itself is not what is dropped"
        );
        assert!(
            model.get("api_keys").is_none(),
            "SecureStrings never reaches the JSON rendering"
        );
        assert!(
            out.path(&["tools", "skills", "github"])
                .and_then(|g| g.get("token"))
                .is_none(),
            "nor does SecureString"
        );
    }

    #[test]
    fn a_zero_inside_a_map_is_not_dropped() {
        // Map *values* have no tag of their own. `identity_links: {"a": []}` keeps the
        // empty list, because the option belongs to the field, not to whatever a map
        // happens to hold.
        let schema = config_schema();
        let document = doc(r#"{"version":3,"session":{"identity_links":{"a":[]}}}"#);
        let out = apply_omit(&document, &schema);
        let links = out.path(&["session", "identity_links"]).expect("links");
        assert!(links.get("a").is_some());
    }

    #[test]
    fn the_file_is_indented_with_two_spaces_and_a_trailing_newline() {
        let schema = config_schema();
        let document = doc(r#"{"version":3,"isolation":{}}"#);
        let text = config_file(&document, &schema).expect("marshals");
        assert!(text.starts_with("{\n  \"version\": 3,\n"), "got {text:?}");
        assert!(
            text.ends_with("}\n"),
            "SaveConfig writes a trailing newline"
        );
    }

    #[test]
    fn the_loaded_value_is_the_compact_form_of_the_same_marshal() {
        let schema = config_schema();
        let document = doc(r#"{"version":3,"session":{"dimensions":[]}}"#);
        assert_eq!(loaded_value(&document, &schema), r#"{"version":3}"#);
    }
}
