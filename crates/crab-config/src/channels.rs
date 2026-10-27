//! `InitChannelList` (`pkg/config/config_channel.go:728`) -- the stage that turns a
//! stored `settings` block into the typed struct the loaded value then marshals.
//!
//! ## Why the loaded value is not the stored document
//!
//! A config file says `{"settings":{"token":"x"}}` for a telegram channel. Go decodes
//! that into `TelegramSettings`, and `Channel.MarshalJSON` marshals *the struct* -- so
//! the loaded config carries every field the struct declares, in declaration order,
//! whether or not the file mentioned it:
//!
//! ```text
//! {"base_url":"","proxy":"","use_markdown_v2":false,"media_group_delay_ms":0,
//!  "token":"x"}
//! ```
//!
//! Two consequences a port cannot guess from the file:
//!
//! * **A field with no omit option is written even when its value is zero.** Across the
//!   default channel list that is 16 keys a document-driven port never emits at all --
//!   `dingtalk`'s `client_id`, `telegram`'s `base_url` and `proxy`, and so on -- and
//!   `slack` gets an empty `settings` object rather than no `settings` key.
//! * **The order is the Go struct's.** `TelegramSettings` declares `base_url` before
//!   `use_markdown_v2`, so the loaded value says so too; sorted or file order are both
//!   wrong. This is what `json_fields` in the schema dump exists to carry.
//!
//! ## What is not here
//!
//! Two of the stage's four checks are absent, and both are refusals rather than
//! rewrites, so neither changes what a *passing* config looks like:
//!
//! * `validateSingletonChannels` -- more than one enabled channel of a singleton type.
//!   It needs the singleton registry, which the dump does not carry (it is Go-side data
//!   like `base_fields`), and no corpus case reaches it.
//! * `validateChannelStreamingConfig` -- the same, for the streaming knobs.
//!
//! `env.Parse(target)` is genuinely a no-op here: no field in this file carries an
//! `env:` tag. `applyTelegramStreamingEnvCompat` is not -- it reads three
//! `PICOCLAW_CHANNELS_TELEGRAM_STREAMING_*` variables -- but the corpus runs with the
//! environment cleared, so it is inert for every recorded case and unportable against
//! this fixture. That is recorded in `docs/DIVERGENCES.md` rather than left for a green
//! replay to imply otherwise.

use crate::doc::Doc;
use crate::schema::Schema;
use crate::Error;

/// The one field of `Channel` whose value this stage replaces outright.
const SETTINGS_KEY: &str = "settings";

/// Runs `InitChannelList` over a merged document, in place.
///
/// The channel list is rebuilt from the schema rather than edited: Go marshals a
/// struct, so a loaded channel carries exactly the struct's fields in the struct's
/// order, and a document that kept the file's keys and appended the rest would put the
/// new ones last.
pub fn init_channel_list(document: &mut Doc, schema: &Schema) -> Result<(), Error> {
    let Some(elem) = schema.field("channel_list").and_then(Schema::elem) else {
        return Ok(());
    };
    let channels = match document
        .get_mut_at("channel_list")
        .and_then(Doc::as_object_mut)
    {
        Some(entries) => std::mem::take(entries),
        // Go calls InitChannelList on whatever the decode left, and a nil map ranges
        // zero times. A document with no channel_list is that.
        None => return Ok(()),
    };

    let mut rebuilt: Vec<(String, Doc)> = Vec::with_capacity(channels.len());
    for (name, channel) in channels {
        // A `null` entry decodes to a nil *Channel, which the loop deletes rather than
        // refusing. It is not an error and it is not kept.
        if matches!(channel, Doc::Null) {
            continue;
        }
        if !channel.is_object() {
            // Go's decode into `map[string]*Channel` would have refused the document
            // long before this stage, so there is no Go behaviour to match. Keep the
            // bytes rather than inventing a verdict.
            rebuilt.push((name, channel));
            continue;
        }

        // "Infer Type from map key if not explicitly set", then the registry check.
        let declared = channel
            .get("type")
            .and_then(Doc::as_str)
            .unwrap_or_default();
        let channel_type = if declared.is_empty() {
            name.clone()
        } else {
            declared.to_string()
        };
        let Some(settings_schema) = elem.settings_schema(&channel_type) else {
            return Err(Error::Channel(format!(
                "channel {name:?} has unknown type {channel_type:?}"
            )));
        };

        let mut out: Vec<(String, Doc)> = Vec::new();
        for field in elem.json_fields() {
            let Some(child) = elem.field(field.json) else {
                continue;
            };
            if field.json == SETTINGS_KEY {
                let stored = channel.get(SETTINGS_KEY);
                let mut settings = project(settings_schema, stored).ok_or_else(|| {
                    Error::Channel(format!("channel {name:?} failed to decode settings"))
                })?;
                preserve_explicit_disabled_streaming(&mut settings, stored);
                // `settings,omitzero` never fires past this point: with the typed struct
                // decoded, MarshalJSON writes the marshalled bytes, which are at minimum
                // `{}` -- two bytes, not zero. So the key is always present, and `slack`
                // shows that as an empty object.
                out.push((SETTINGS_KEY.to_string(), settings));
                continue;
            }
            // The inference is not just a lookup key: `bc.Type = name` writes into the
            // struct, and `type` carries no omit option, so the loaded value says
            // `"type":"maixcam"` for a channel the file only named by its key. Leaving
            // the field as the document had it writes `"type":""` -- the same channel,
            // described as having no type at all.
            let value = if field.json == "type" {
                Doc::String(channel_type.clone())
            } else {
                project(child, channel.get(field.json)).ok_or_else(|| {
                    Error::Channel(format!(
                        "channel {name:?} failed to decode settings: field {:?}",
                        field.json
                    ))
                })?
            };
            if is_dropped_by_omit(child, &value) {
                continue;
            }
            out.push((field.json.to_string(), value));
        }
        rebuilt.push((name, Doc::Object(out)));
    }

    if let Some(slot) = document.get_mut_at("channel_list") {
        *slot = Doc::Object(rebuilt);
    }
    Ok(())
}

/// The value `encoding/json` would write for `schema` given what the document holds.
///
/// This is the decode and the re-marshal in one walk, because for the values a config
/// can hold they compose to very little: a scalar round-trips, a struct comes back with
/// every declared field, and a nil map or slice comes back as `null`. What it is *not*
/// is permissive -- a value Go's decoder would reject returns `None`, which the caller
/// turns into the same refusal `InitChannelList` returns.
fn project(schema: &Schema, stored: Option<&Doc>) -> Option<Doc> {
    match schema {
        Schema::Struct { .. } => {
            let mut out: Vec<(String, Doc)> = Vec::new();
            for field in schema.json_fields() {
                let Some(child) = schema.field(field.json) else {
                    continue;
                };
                let value = project(child, stored.and_then(|s| s.get(field.json)))?;
                if is_dropped_by_omit(child, &value) {
                    continue;
                }
                out.push((field.json.to_string(), value));
            }
            Some(Doc::Object(out))
        }
        Schema::Map { elem, .. } => match stored {
            // A nil map marshals as `null`, not `{}`. The distinction survives in the
            // fixture: `random_reaction_emoji` is `null` while `irc.channels` is `[]`.
            None | Some(Doc::Null) => Some(Doc::Null),
            Some(Doc::Object(entries)) => {
                let mut out = Vec::with_capacity(entries.len());
                for (key, value) in entries {
                    out.push((key.clone(), project(elem, Some(value))?));
                }
                Some(Doc::Object(out))
            }
            Some(_) => None,
        },
        Schema::Slice { elem, .. } => match stored {
            None | Some(Doc::Null) => Some(Doc::Null),
            Some(Doc::Array(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(project(elem, Some(item))?);
                }
                Some(Doc::Array(out))
            }
            Some(_) => None,
        },
        Schema::Scalar { .. } => project_scalar(schema, stored),
    }
}

/// A scalar's round trip: the stored value when the JSON type agrees with the Go type,
/// the zero value when the document holds nothing or holds `null`.
///
/// `None` is a decode error, and the set of mismatches is narrower than it looks. A
/// number with a fraction in an int field is one of them -- measured, not assumed:
/// `{"media_group_delay_ms":1500.0}` fails with `cannot unmarshal number 1500.0 into Go
/// struct field TelegramSettings.media_group_delay_ms of type int`, so the conversion
/// that looks obvious (the value *is* 1500) is exactly what Go refuses. The reverse is
/// allowed: an integer literal loads into a `float64`.
fn project_scalar(schema: &Schema, stored: Option<&Doc>) -> Option<Doc> {
    let Some(stored) = stored.filter(|v| !matches!(v, Doc::Null)) else {
        return Some(zero(schema));
    };
    let name = schema.name().unwrap_or("");
    match stored {
        // A byte holder takes the bytes as they came; a free `any` takes anything.
        _ if matches!(name, "json.RawMessage" | "RawNode" | "any") => Some(stored.clone()),
        Doc::Bool(b) => matches!(name, "bool").then(|| Doc::Bool(*b)),
        Doc::String(s) => (!is_numeric(name)).then_some(Doc::String(s.clone())),
        Doc::Int(v) if is_int_type(name) => Some(Doc::Int(*v)),
        Doc::Int(v) if is_float_type(name) => Some(Doc::Float(*v as f64)),
        Doc::Float(_) if is_int_type(name) => None,
        Doc::Float(f) => Some(Doc::Float(*f)),
        // An object or array where the field is a scalar.
        _ => None,
    }
}

fn is_numeric(name: &str) -> bool {
    is_int_type(name) || is_float_type(name)
}

/// The zero value of a type, as `encoding/json` writes it.
fn zero(schema: &Schema) -> Doc {
    match schema {
        // A nil map or slice is `null`. Only a non-nil empty one is `[]` / `{}`, and
        // the document is what says which one this is -- see `project`.
        Schema::Map { .. } | Schema::Slice { .. } => Doc::Null,
        Schema::Struct { .. } => {
            let mut out = Vec::new();
            for field in schema.json_fields() {
                let Some(child) = schema.field(field.json) else {
                    continue;
                };
                let value = zero(child);
                if is_dropped_by_omit(child, &value) {
                    continue;
                }
                out.push((field.json.to_string(), value));
            }
            Doc::Object(out)
        }
        Schema::Scalar { .. } => match schema.name().unwrap_or("") {
            "bool" => Doc::Bool(false),
            n if is_int_type(n) => Doc::Int(0),
            n if is_float_type(n) => Doc::Float(0.0),
            // Strings, and the named string types (`TurnProfileMode`). `RawMessage` and
            // `RawNode` are nil-able byte holders, so their zero is `null`.
            "json.RawMessage" | "RawNode" | "any" => Doc::Null,
            _ => Doc::String(String::new()),
        },
    }
}

fn is_int_type(name: &str) -> bool {
    name.starts_with("int") || name.starts_with("uint")
}

fn is_float_type(name: &str) -> bool {
    name.starts_with("float")
}

/// Whether the field's own encoding option drops this value.
///
/// `omitzero` and `omitempty` are *not* the same test, and the difference is exactly
/// where the channel settings live: `streaming` carries `omitzero`, so a zero
/// `StreamingConfig` disappears, while `group_trigger` carries `omitempty`, so an empty
/// `GroupTriggerConfig` is kept -- a struct is never "empty" to `omitempty`, which is
/// the same rule that keeps `isolation: {}` in the config file.
fn is_dropped_by_omit(schema: &Schema, value: &Doc) -> bool {
    match schema.omit() {
        None => false,
        Some("omitzero") => is_go_zero(schema, value),
        Some(_) => crate::marshal::is_empty_by_go(value, schema),
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
        (Doc::Object(entries), Schema::Map { .. }) => entries.is_empty(),
        (Doc::Array(items), Schema::Slice { .. }) => items.is_empty(),
        _ => crate::marshal::is_empty_by_go(value, schema),
    }
}

/// `preserveExplicitDisabledStreaming` (`config_channel.go:260`).
///
/// A user who writes `"streaming": {"enabled": false}` means *off*, and the typed
/// struct cannot say that: `false` is the zero value, so `streaming,omitzero` drops the
/// whole section and the reader would fall back to its own default. So Go puts the
/// explicit `false` back.
///
/// The re-insert goes through a `map[string]any` round trip, and a Go map marshals
/// sorted -- so when this fires, the *entire* settings object comes back in alphabetical
/// order, not just the new key. That is visible in the bytes and easy to get wrong in
/// the comfortable direction: a port that appends `streaming` at the end produces the
/// same document to anything that parses it and a different one to anything that
/// compares them.
fn preserve_explicit_disabled_streaming(settings: &mut Doc, stored: Option<&Doc>) {
    let Doc::Object(entries) = settings else {
        return;
    };
    if entries.is_empty() {
        return;
    }
    let Some(Doc::Object(source)) = stored else {
        return;
    };
    // "the original said streaming.enabled === false", with `false` required, not
    // merely "the key is there": `{"streaming":{}}` says nothing and changes nothing.
    let explicit_off = source
        .iter()
        .find(|(key, _)| key == "streaming")
        .and_then(|(_, value)| value.as_object())
        .and_then(|streaming| {
            streaming
                .iter()
                .find(|(key, _)| key == "enabled")
                .map(|(_, value)| matches!(value, Doc::Bool(false)))
        })
        .unwrap_or(false);
    if !explicit_off || entries.iter().any(|(key, _)| key == "streaming") {
        return;
    }
    entries.push((
        "streaming".to_string(),
        Doc::Object(vec![("enabled".to_string(), Doc::Bool(false))]),
    ));
    sort_keys_recursively(settings);
}

/// What marshalling a `map[string]any` does to the key order: sorted, all the way down.
fn sort_keys_recursively(document: &mut Doc) {
    match document {
        Doc::Object(entries) => {
            for (_, value) in entries.iter_mut() {
                sort_keys_recursively(value);
            }
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        }
        Doc::Array(items) => {
            for item in items {
                sort_keys_recursively(item);
            }
        }
        _ => {}
    }
}
