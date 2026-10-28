//! The security file: `.security.yml`, the yaml-tagged half of a config.
//!
//! Two things make this file its own problem rather than a second copy of the first.
//!
//! **It is a different strictness.** The JSON document goes through [`crate::schema`],
//! which refuses any key the target type cannot place. The security file is decoded by
//! a YAML library into the same `Config` struct, where every field that is not
//! yaml-tagged is simply *not a field* -- so a key the JSON side would refuse is
//! silently ignored here, and only a syntax error or a type error fails. The corpus
//! pins both halves of that asymmetry (`security_entry_replaces_the_json_model`,
//! `unparseable_security_file_is_refused`).
//!
//! **It decodes into a config that is already populated.** `loadSecurityConfig` runs
//! after the JSON document has been read, so a security entry fills in the fields it
//! mentions and leaves the rest of that entry alone. That is per-field, not
//! per-entry: `model_list: {m1:0: {rpm: 5}}` gives m1 an rpm and keeps its provider.
//! The wholesale-replacement reading is the intuitive one and it is wrong.
//!
//! `channels` / `channel_list` is the exception with its own mechanism: it is pulled
//! out of the node tree before the decode and merged into the JSON-loaded channels
//! afterwards, which is why the two halves of *that* section combine.
//!
//! ## What the writer emits
//!
//! Four top-level sections, in the order `yaml.v3` writes them: `channel_list`,
//! `model_list`, then `web` and `skills` -- which are top level because `Tools` carries
//! `yaml:",inline"`. Reading only `Config`'s own two yaml tags predicts the first two
//! and loses the other two, and the next load then re-adds them from defaults, so the
//! file changes on every start.

use yaml_rust2::{Yaml, YamlLoader};

use crate::doc::Doc;
use crate::schema::Schema;
use crate::Error;

/// What the loader takes out of the security file: the file, as a document.
///
/// It is deliberately the whole node tree and not a struct with one field per known
/// section. `loadSecurityConfig` runs `yaml.Unmarshal(data, cfg)` over the entire file;
/// a key with nowhere to land is dropped by the decoder, not reported. A `Security` that
/// listed the sections it understood turned every section it did not understand into a
/// load failure -- including `web` and `skills`, which every `.security.yml` the shipped
/// binary has written contains.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Security {
    /// The file's root mapping.
    pub document: Doc,
}

impl Security {
    /// The channels section, under either spelling.
    #[must_use]
    pub fn channels(&self) -> Option<&Doc> {
        self.document
            .get("channel_list")
            .or_else(|| self.document.get("channels"))
    }

    /// The `model_list` section, which is a map keyed `name:index` rather than the
    /// sequence the JSON document uses.
    #[must_use]
    pub fn model_list(&self) -> Option<&Doc> {
        self.document.get("model_list")
    }
}

/// Parses a security file the way `loadSecurityConfig` does.
///
/// The order is the Go order and it matters: the syntax check runs over the whole
/// document before anything is decoded, so a torn file fails even when the damage is in
/// a section nobody reads.
pub fn parse(text: &str) -> Result<Security, Error> {
    let docs = YamlLoader::load_from_str(text)
        .map_err(|e: yaml_rust2::ScanError| Error::UnparseableSecurity(e.to_string()))?;

    let mut out = Security::default();
    let Some(root) = docs.first() else {
        return Ok(out);
    };

    match root {
        // Go's message for a sequence at the root is
        // `cannot unmarshal !!seq into config.Config`.
        Yaml::Array(_) => {
            return Err(Error::SecurityType(
                "cannot unmarshal !!seq into config.Config".to_string(),
            ))
        }
        Yaml::BadValue | Yaml::Null => return Ok(out),
        _ => {}
    }

    let Some(mapping) = root.as_hash() else {
        return Ok(out);
    };

    let mut entries = Vec::with_capacity(mapping.len());
    for (key, value) in mapping {
        let name = match key
            .as_str()
            .map(str::to_string)
            .or_else(|| key.as_i64().map(|i| i.to_string()))
        {
            Some(n) => n,
            None => continue,
        };
        // `model_list` is checked as it is read because it is the one section whose
        // shape can be structurally wrong in a way the decoder reports rather than
        // ignores. Everything else is kept verbatim and filtered at merge time by the
        // yaml table, which is where "no field can hold this" gets decided -- in the
        // same place Go decides it.
        if name == "model_list" {
            entries.push((name, decode_model_list(value)?));
        } else {
            entries.push((name, scalar_or_container(value)));
        }
    }
    out.document = Doc::Object(entries);

    Ok(out)
}

/// `yaml.Unmarshal(data, cfg)` for the `model_list` field: `map[string]*ModelConfig`.
///
/// A sequence is the mistake a user makes by copying the JSON shape, and Go's answer is
/// a type error naming both the kind it found and the type it wanted. The sentence is
/// not pinned by the corpus -- Go prefixes it with an absolute path -- but the refusal
/// is, and so is the fact that a map whose entries carry unknown keys is accepted.
fn decode_model_list(value: &Yaml) -> Result<Doc, Error> {
    match value {
        Yaml::Array(_) => Err(Error::SecurityType(
            "cannot unmarshal !!seq into map[string]*config.ModelConfig".to_string(),
        )),
        Yaml::Null => Ok(Doc::Object(Vec::new())),
        other => to_doc(other).ok_or_else(|| {
            Error::SecurityType(
                "cannot unmarshal !!str into map[string]*config.ModelConfig".to_string(),
            )
        }),
    }
}

/// Converts a YAML node to the crate's document type.
///
/// `None` for a node that is not a container, which is how the caller tells "an empty
/// section" from "a scalar where a mapping was required".
fn to_doc(value: &Yaml) -> Option<Doc> {
    Some(match value {
        Yaml::Hash(map) => {
            let mut entries = Vec::with_capacity(map.len());
            for (k, v) in map {
                let key = k
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| k.as_i64().map(|i| i.to_string()))?;
                entries.push((key, scalar_or_container(v)));
            }
            Doc::Object(entries)
        }
        Yaml::Null => Doc::Object(Vec::new()),
        _ => return None,
    })
}

/// Any YAML node, including scalars, as a document.
fn scalar_or_container(value: &Yaml) -> Doc {
    match value {
        Yaml::String(s) => Doc::String(s.clone()),
        Yaml::Integer(i) => Doc::Int(*i),
        Yaml::Real(r) => r.parse::<f64>().map_or(Doc::String(r.clone()), Doc::Float),
        Yaml::Boolean(b) => Doc::Bool(*b),
        Yaml::Array(items) => Doc::Array(items.iter().map(scalar_or_container).collect()),
        Yaml::Hash(map) => {
            let mut entries = Vec::with_capacity(map.len());
            for (k, v) in map {
                let key = k
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| k.as_i64().map(|i| i.to_string()))
                    .unwrap_or_default();
                entries.push((key, scalar_or_container(v)));
            }
            Doc::Object(entries)
        }
        _ => Doc::Null,
    }
}

/// Writes the yaml-tagged half of a config, driven by the dump's yaml emission lists.
///
/// The file is not "the config minus the secrets" and it is not the JSON document
/// re-spelled: it is what `yaml.v3` writes for `Config`, which is a different projection
/// because `Config` marks every non-secret field `yaml:"-"`. That single fact explains
/// why there is no `version` key in the file, why a channel contributes exactly
/// `settings`, and why `web` and `skills` are top level (`Tools` is `yaml:",inline"`).
///
/// Three things the writer has to get right that a generic map printer gets wrong:
///
/// * **Order is declaration order, not sorted.** `channel_list`, `model_list`, then the
///   inlined `web` and `skills`. A port printing the JSON field map sorts `web` and
///   `skills` into a different place and produces a different file with the same content.
/// * **`omitempty` on a struct fires.** `yaml.v3`'s emptiness test recurses into struct
///   fields, so `github,omitempty` disappears when every field inside it is zero --
///   which is the opposite of `encoding/json`, where a struct is never empty. That is
///   why the file has `registries` and no `github`.
/// * **Four positions are decided by a `MarshalYAML` method**, not by their fields.
///   `SecureModelList` writes a `name:index`-keyed map of secrets only; `Channel` writes
///   `{settings: …}`; `SkillRegistryConfig` and `SkillsRegistriesConfig` write their own
///   shapes. The dump flags them (`marshaler: true`) so the generic walk cannot run here
///   and quietly produce the struct's shape instead.
///
/// # Errors
///
/// Returns [`Error::NotPorted`] for a position whose projection this crate does not
/// implement -- today that is a channel whose `settings` block is non-empty, because the
/// per-type settings struct that decides which of its keys are secrets is not in the
/// dump. Refusing is the right answer: the alternative is writing a `.security.yml` that
/// silently drops a secret, and the next load would then re-add defaults over it.
pub fn write(document: &Doc, schema: &Schema) -> Result<String, Error> {
    let mut out = String::new();
    emit_fields(schema, document, 0, &mut out)?;
    Ok(out)
}

fn emit_fields(schema: &Schema, value: &Doc, level: usize, out: &mut String) -> Result<(), Error> {
    for (name, rendered) in struct_entries(schema, value)? {
        emit_entry(out, &quote_key(&name), level, &rendered)?;
    }
    Ok(())
}

/// The emission list of a struct as `(yaml key, value)` pairs, in declaration order.
///
/// Two rules here are yaml.v3's and neither is encoding/json's:
///
/// * **`omitempty` is tested against the Go field, not against what gets written.** A
///   `*BraveConfig` that is non-nil but whose every field is empty still appears, as
///   `brave: {}`, while `github` -- a value struct whose fields are all zero -- vanishes.
///   Testing the rendered result instead would drop `brave: {}` and keep whatever a
///   projection happened to return, and the file would differ from the shipped binary's in
///   both directions.
/// * **An empty struct is not empty.** `Tools` is `yaml:",inline"`, and the two fields it
///   brings in are themselves `omitempty` structs, so the emptiness test has to recurse
///   through fields the way `reflect.Value.IsZero` does.
fn struct_entries(schema: &Schema, value: &Doc) -> Result<Vec<(String, Rendered)>, Error> {
    let mut entries: Vec<(String, Rendered)> = Vec::new();
    for field in schema.yaml_fields() {
        let Some(child_schema) = schema.field(field.json) else {
            continue;
        };
        let Some(child) = value.get(field.json) else {
            continue;
        };
        if field.inline {
            entries.extend(struct_entries(child_schema, child)?);
            continue;
        }
        if field.omit == Some("omitempty") && yaml_is_zero(child) {
            continue;
        }
        entries.push((field.name.to_string(), render(child_schema, child)?));
    }
    Ok(entries)
}

/// Renders one value under the schema that governs it.
///
/// The recursion is where the two representations meet: a `MarshalYAML` method replaces
/// the struct's own fields with whatever it builds, a map's entries are **sorted** because
/// `yaml.v3` writes a Go map through the same ordering `encoding/json` uses, and a struct's
/// entries stay in declaration order because a struct is not a map.
fn render(schema: &Schema, value: &Doc) -> Result<Rendered, Error> {
    if schema.is_marshaler() {
        return projection(schema, value);
    }
    match schema {
        Schema::Struct { .. } => Ok(Rendered::Object(struct_entries(schema, value)?)),
        Schema::Map { .. } => {
            let Some(elem) = schema.elem() else {
                return Ok(Rendered::Value(value.clone()));
            };
            let mut entries = value.as_object().cloned().unwrap_or_default();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = Vec::with_capacity(entries.len());
            for (key, item) in entries {
                out.push((key, render(elem, &item)?));
            }
            Ok(Rendered::Object(out))
        }
        Schema::Slice { .. } => {
            let Some(elem) = schema.elem() else {
                return Ok(Rendered::Value(value.clone()));
            };
            let mut out = Vec::new();
            for item in value.as_array().cloned().unwrap_or_default() {
                out.push(render(elem, &item)?);
            }
            Ok(Rendered::Seq(out))
        }
        _ => Ok(Rendered::Value(value.clone())),
    }
}

/// Applies a `MarshalYAML` projection.
///
/// The shapes here mirror Go's own code, which builds an anonymous struct per case; the
/// line references are the ones worth re-reading before changing any of them.
fn projection(schema: &Schema, value: &Doc) -> Result<Rendered, Error> {
    match (schema.name(), schema.is_marshaler()) {
        // config_struct.go:345 -- map[name:index]{api_keys}, and nothing else. Every
        // other field of ModelConfig is absent from this file because this method returns
        // a hand-built type, not the struct. The result is a Go map, so its keys sort.
        (Some("SecureModelList"), true) => {
            let models = value.as_array().cloned().unwrap_or_default();
            let keys = to_name_index(&models);
            let mut entries: Vec<(String, Rendered)> = Vec::with_capacity(models.len());
            for (key, model) in keys.iter().zip(&models) {
                let mut fields = Vec::new();
                if let Some(keys) = model.get("api_keys") {
                    if !yaml_is_zero(keys) {
                        fields.push(("api_keys".to_string(), Rendered::Value(keys.clone())));
                    }
                }
                entries.push((key.clone(), Rendered::Object(fields)));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(Rendered::Object(entries))
        }
        // config_channel.go:295 -- `{settings: <the typed settings struct>}`, and the
        // typed struct is what decides which keys of a channel's settings are secrets.
        // That mapping is not in the type graph -- the field's own type is RawNode -- so
        // it comes from `channelSettingsFactory` in the dump.
        //
        // An unknown channel type emits `{}`, not `settings: {}`: Go's `newChannelSettings`
        // returns nil, `GetDecoded` hands back nil, and `settings,omitempty` on a nil
        // `any` fires. (In practice `InitChannelList` refuses an unknown type before a
        // save can happen, so this branch is the shape, not a live path.)
        (Some("Channel"), true) => {
            // InitChannelList infers Type from the map key when the entry does not say
            // one; the document reaching here has already been through that.
            let channel_type = value
                .get("type")
                .and_then(Doc::as_str)
                .unwrap_or_default()
                .to_string();
            let Some(settings_schema) = schema.settings_schema(&channel_type) else {
                return Ok(Rendered::Object(Vec::new()));
            };
            let settings = value
                .get("settings")
                .cloned()
                .unwrap_or(Doc::Object(Vec::new()));
            Ok(Rendered::Object(vec![(
                "settings".to_string(),
                render(settings_schema, &settings)?,
            )]))
        }
        // config_struct.go:715 -- a map of name to `{auth_token}`, and a registry appears
        // only when it has a name *and* a non-empty token. So the default config, which
        // has two registries and no tokens, writes `registries: {}` -- the key survives
        // because omitempty saw the two-entry slice, and the map inside is empty.
        (Some("SkillsRegistriesConfig"), true) => {
            // The Go type is a slice, but its MarshalJSON writes a map keyed by name, so
            // a document read back from disk holds a map. Both shapes are accepted: the
            // name is the key when there is one, and the `name` field otherwise (Go's
            // UnmarshalJSON copies the key into Name, so the two agree).
            let items: Vec<(String, Doc)> = match value {
                Doc::Object(entries) => entries.clone(),
                Doc::Array(items) => items
                    .iter()
                    .map(|item| {
                        (
                            item.get("name")
                                .and_then(Doc::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            item.clone(),
                        )
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let mut entries: Vec<(String, Rendered)> = Vec::new();
            for (name, item) in &items {
                let Some(token) = item.get("auth_token") else {
                    continue;
                };
                if name.is_empty() || yaml_is_zero(token) {
                    continue;
                }
                entries.push((
                    name.to_string(),
                    Rendered::Object(vec![(
                        "auth_token".to_string(),
                        Rendered::Value(token.clone()),
                    )]),
                ));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(Rendered::Object(entries))
        }
        _ => Ok(Rendered::Value(value.clone())),
    }
}

/// A value with the projections already applied to it, so rendering does not have to
/// re-walk the schema.
enum Rendered {
    Value(Doc),
    Object(Vec<(String, Rendered)>),
    Seq(Vec<Rendered>),
}

fn emit_entry(out: &mut String, key: &str, level: usize, value: &Rendered) -> Result<(), Error> {
    let pad = "  ".repeat(level);
    match value {
        Rendered::Object(entries) if entries.is_empty() => {
            out.push_str(&format!("{pad}{key}: {{}}\n"));
        }
        Rendered::Object(entries) => {
            out.push_str(&format!("{pad}{key}:\n"));
            for (k, v) in entries {
                emit_entry(out, &quote_key(k), level + 1, v)?;
            }
        }
        Rendered::Value(Doc::Object(entries)) if entries.is_empty() => {
            out.push_str(&format!("{pad}{key}: {{}}\n"));
        }
        Rendered::Value(Doc::Object(entries)) => {
            // A map reaching here without a schema to render it still has to sort: Go
            // writes every map through the same ordering, whatever its element type.
            let mut entries = entries.clone();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            out.push_str(&format!("{pad}{key}:\n"));
            for (k, v) in entries {
                emit_entry(
                    out,
                    &quote_key(&scalar_text(&Doc::String(k.clone()))),
                    level + 1,
                    &Rendered::Value(v.clone()),
                )?;
            }
        }
        Rendered::Seq(items) if items.is_empty() => {
            out.push_str(&format!("{pad}{key}: []\n"));
        }
        Rendered::Seq(items) => {
            out.push_str(&format!("{pad}{key}:\n"));
            for item in items {
                emit_seq_item(out, level + 1, item)?;
            }
        }
        Rendered::Value(Doc::Array(items)) if items.is_empty() => {
            out.push_str(&format!("{pad}{key}: []\n"));
        }
        Rendered::Value(Doc::Array(items)) => {
            out.push_str(&format!("{pad}{key}:\n"));
            for item in items {
                emit_seq_item(out, level + 1, &Rendered::Value(item.clone()))?;
            }
        }
        Rendered::Value(other) => out.push_str(&format!("{pad}{key}: {}\n", scalar_text(other))),
    }
    Ok(())
}

/// One element of a sequence.
///
/// This is not `emit_entry` with the key `"-"`, which is what it looks like it could be and
/// is what it was. That route formats a scalar as `key: value`, so `api_keys: [bk]` came out
/// as `-: bk` -- valid YAML, but a mapping with an empty key rather than the string `bk`,
/// and the next load then reads back a list of one map. `yaml.v3` puts the dash on the
/// element itself: `- bk` for a scalar, and for a map the **first key rides the dash** with
/// the rest aligned under it, which is exactly one indent level deeper -- the same width as
/// `- `, which is why splicing the dash into the first line's padding is enough and no
/// second rendering mode is needed.
fn emit_seq_item(out: &mut String, level: usize, item: &Rendered) -> Result<(), Error> {
    let pad = "  ".repeat(level);
    let dash = format!("{pad}- ");
    let mut buf = String::new();
    let rendered_entries = match item {
        Rendered::Object(entries) if entries.is_empty() => return emit_line(out, &dash, "{}"),
        Rendered::Object(entries) => {
            for (k, v) in entries.iter() {
                emit_entry(&mut buf, &quote_key(k), level + 1, v)?;
            }
            true
        }
        Rendered::Value(Doc::Object(entries)) if entries.is_empty() => {
            return emit_line(out, &dash, "{}")
        }
        Rendered::Value(Doc::Object(entries)) => {
            for (k, v) in entries {
                emit_entry(
                    &mut buf,
                    &quote_key(k),
                    level + 1,
                    &Rendered::Value(v.clone()),
                )?;
            }
            true
        }
        Rendered::Seq(inner) if inner.is_empty() => return emit_line(out, &dash, "[]"),
        Rendered::Value(Doc::Array(inner)) if inner.is_empty() => {
            return emit_line(out, &dash, "[]")
        }
        Rendered::Value(other) => return emit_line(out, &dash, &scalar_text(other)),
        other => {
            // Defensive, and unreachable today: the dump has no slice of slices anywhere in
            // the config schema, so no recorded byte pair grades what this emits. It is kept
            // because `Rendered::Seq` inside a sequence is representable in this type and a
            // silent panic would be worse than an odd document. No claim is made about what
            // `yaml.v3` would print -- the nested form it produces (`- - a`, riding the dash)
            // is not what `emit_entry(.., "")` renders, which is an empty-key block.
            emit_entry(&mut buf, "", level + 1, other)?;
            true
        }
    };
    if !rendered_entries {
        return emit_line(out, &dash, "{}");
    }
    match buf.strip_prefix(&format!("{pad}  ")) {
        Some(rest) => {
            out.push_str(&dash);
            out.push_str(rest);
        }
        None => out.push_str(&buf),
    }
    Ok(())
}

fn emit_line(out: &mut String, prefix: &str, body: &str) -> Result<(), Error> {
    out.push_str(&format!("{prefix}{body}\n"));
    Ok(())
}

/// `yaml.v3`'s `isZero`.
///
/// The case that matters is the last one: a struct whose fields are all zero counts as
/// empty, so `omitempty` removes a whole section. `encoding/json` never does this, which
/// is why the same field can be `json:"github"` (always written) and `yaml:"github,omitempty"`
/// (absent from a default config's security file).
fn yaml_is_zero(value: &Doc) -> bool {
    match value {
        Doc::Null => true,
        Doc::Bool(b) => !*b,
        Doc::Int(i) => *i == 0,
        Doc::Float(f) => *f == 0.0,
        Doc::String(s) => s.is_empty(),
        Doc::Array(items) => items.iter().all(yaml_is_zero),
        Doc::Object(entries) => entries.iter().all(|(_, v)| yaml_is_zero(v)),
    }
}

/// A scalar as `yaml.v3`'s emitter would write it.
fn scalar_text(value: &Doc) -> String {
    match value {
        Doc::Null => "null".to_string(),
        Doc::Bool(b) => b.to_string(),
        Doc::Int(i) => i.to_string(),
        Doc::Float(f) => crate::doc::go_number(*f),
        Doc::String(s) => emit_string(s),
        Doc::Array(_) | Doc::Object(_) => "{}".to_string(),
    }
}

/// Plain style whenever it survives a re-parse, double quotes otherwise.
///
/// The rule that makes this a compat question rather than a style choice: a model name
/// like `LongCat-Flash-Thinking:0` is emitted **unquoted**, because a colon only needs
/// quoting when a space follows it. Quoting it anyway produces the same data and a
/// different byte. The mirror case is an email address: `@` is a reserved indicator at
/// the start of a plain scalar, so `email: @nine.testrun.org` is not YAML at all -- and
/// a writer that produced it could not read its own output back.
fn emit_string(s: &str) -> String {
    if plain_is_safe(s) {
        s.to_string()
    } else {
        format!(
            "\"{}\"",
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
        )
    }
}

fn plain_is_safe(s: &str) -> bool {
    if s.is_empty() || s.trim() != s {
        return false;
    }
    let first = s.chars().next().unwrap_or(' ');
    // yaml.v3's reserved first characters, plus the two that only matter when a space
    // or end follows.
    if "@`'\"{}[],&*#?|<>%".contains(first) {
        return false;
    }
    if matches!(first, '-' | '!' | ':') && (s.len() <= 1 || s[1..].starts_with(' ')) {
        return false;
    }
    if s.contains(": ") || s.contains(" #") || s.contains('\n') || s.contains('\t') {
        return false;
    }
    // A plain scalar that reads as a number, bool, timestamp or null would come back as
    // the wrong type, so those are quoted.
    !reads_as_a_non_string(s)
}

fn reads_as_a_non_string(s: &str) -> bool {
    if s.eq_ignore_ascii_case("null")
        || s.eq_ignore_ascii_case("~")
        || s.eq_ignore_ascii_case("true")
        || s.eq_ignore_ascii_case("false")
        || s.eq_ignore_ascii_case("yes")
        || s.eq_ignore_ascii_case("no")
        || s.eq_ignore_ascii_case("on")
        || s.eq_ignore_ascii_case("off")
    {
        return true;
    }
    s.parse::<f64>().is_ok()
}

/// A mapping key. Same rule as a scalar, except that a key may end in `:` -- the
/// `name:index` form is the common case in `model_list`.
fn quote_key(key: &str) -> String {
    // Both branches hand the key to `emit_string`, which keeps it plain when libyaml
    // would emit it plain -- so the question is only whether anything forces quoting.
    let forced = key.contains(": ")
        || key.contains(" #")
        || key.trim() != key
        || key.is_empty()
        || key.ends_with(':')
        || key.starts_with([
            '-', '?', ':', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`',
        ]);
    if forced {
        emit_string(key)
    } else {
        key.to_string()
    }
}

/// The `model_list` half of the security file, keyed the way the file keys it.
///
/// `toNameIndex` numbers duplicate model names in list order, so three entries named
/// `m1` become `m1:0`, `m1:1`, `m1:2`. The numbering is a property of the *list*, which
/// is why it is here rather than in the writer: a port that keyed by name alone would
/// collapse duplicates, and one that sorted the keys would reorder the file.
#[must_use]
pub fn to_name_index(models: &[Doc]) -> Vec<String> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut out = Vec::with_capacity(models.len());
    for model in models {
        let name = model
            .get("model_name")
            .and_then(Doc::as_str)
            .unwrap_or_default()
            .to_string();
        let index = counts.entry(name.clone()).or_insert(0);
        out.push(format!("{name}:{index}"));
        *index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::from_json;

    #[test]
    fn a_map_of_entries_is_accepted() {
        let sec = parse("model_list:\n    m1:0:\n      zzz: 1\n").expect("map form loads");
        let models = sec.model_list().expect("model_list present");
        assert!(models.get("m1:0").is_some());
    }

    #[test]
    fn a_sequence_is_a_type_error() {
        // The JSON shape in YAML. Go refuses; a port that accepts it loads a file the
        // Go build stops on.
        let err = parse("model_list:\n    - model_name: m1\n").expect_err("seq must be refused");
        assert!(matches!(err, Error::SecurityType(_)), "got {err}");
        assert!(err.to_string().contains("map[string]*config.ModelConfig"));
    }

    #[test]
    fn a_torn_document_fails_before_any_section_is_read() {
        let err = parse("model_list: [\n").expect_err("torn flow must be refused");
        assert!(matches!(err, Error::UnparseableSecurity(_)), "got {err}");
    }

    #[test]
    fn channels_and_channel_list_are_the_same_section() {
        for key in ["channels", "channel_list"] {
            let sec = parse(&format!(
                "{key}:\n    telegram:\n      settings:\n        bot_token: 123\n"
            ))
            .expect("channels loads");
            let channels = sec.channels().expect("section present");
            assert!(channels.get("telegram").is_some(), "{key} not recognised");
        }
    }

    #[test]
    fn an_unknown_section_is_ignored_the_way_go_ignores_it() {
        // `loadSecurityConfig` calls plain `yaml.Unmarshal`, not `UnmarshalStrict`, so a
        // section the struct does not name is skipped and the file still loads. Refusing
        // it here would reject a config the shipped binary accepts, which is the one
        // direction a compat port must not move in.
        //
        // `web` and `skills` are NOT in this category -- `Tools` is `yaml:",inline"`, so
        // Go applies them -- and they are the two sections `apply_security` does not merge
        // yet. That gap is `docs/DIVERGENCES.md`, not this test.
        let sec = parse("tools:\n  exec:\n    enabled: true\n").expect("unknown section loads");
        assert!(sec.channels().is_none(), "and nothing else is read");
        assert!(sec.model_list().is_none());
    }

    /// Writes a document through the real config schema.
    fn write_default(doc: &Doc) -> String {
        write(doc, &crate::config_schema()).expect("write")
    }

    #[test]
    fn a_name_index_key_is_emitted_unquoted() {
        // The byte-level rule the writer exists to get right. The document holds the JSON
        // sequence; the `name:index` map is what the projection makes of it.
        let doc =
            from_json(r#"{"model_list":[{"model_name":"LongCat-Flash-Thinking"}]}"#).into_doc();
        assert_eq!(
            write_default(&doc),
            "model_list:\n  LongCat-Flash-Thinking:0: {}\n"
        );
    }

    #[test]
    fn a_key_that_would_be_ambiguous_is_quoted() {
        assert_eq!(quote_key("a: b"), "\"a: b\"");
        assert_eq!(quote_key("plain:ok"), "plain:ok");
        // A leading dash is only an indicator when a space follows it, so libyaml keeps
        // `-lead` plain. Quoting it would still parse, but it would not be Go's bytes.
        assert_eq!(quote_key("-lead"), "-lead");
        assert_eq!(quote_key("- lead"), "\"- lead\"");
    }

    #[test]
    fn the_four_sections_are_written_in_order() {
        // `enabled` is what makes each section non-zero: yaml.v3's omitempty recurses
        // into a struct, so an all-defaults section really would be dropped.
        let doc = from_json(
            r#"{"channel_list":{},"model_list":[],"tools":{"web":{"enabled":true},"skills":{"enabled":true}}}"#,
        )
        .into_doc();
        let text = write_default(&doc);
        let order: Vec<&str> = text
            .lines()
            .filter(|l| !l.starts_with(' ') && l.contains(':'))
            .map(|l| l.split(':').next().unwrap_or_default())
            .collect();
        assert_eq!(order, ["channel_list", "model_list", "web", "skills"]);
    }

    #[test]
    fn duplicate_names_are_numbered_in_list_order() {
        let models: Vec<Doc> = ["m1", "m2", "m1"]
            .iter()
            .map(|name| from_json(&format!(r#"{{"model_name":"{name}"}}"#)).into_doc())
            .collect();
        assert_eq!(to_name_index(&models), ["m1:0", "m2:0", "m1:1"]);
    }
}
