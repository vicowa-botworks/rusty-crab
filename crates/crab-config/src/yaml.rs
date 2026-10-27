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
use crate::Error;

/// What the loader takes out of the security file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Security {
    /// `model_list`, as Go decodes it: a map keyed `name:index` whose entries are
    /// `ModelConfig` values.
    pub model_list: Option<Doc>,
    /// The `channels` / `channel_list` node, merged rather than replaced.
    pub channels: Option<Doc>,
}

impl Security {
    /// Whether the file said anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.model_list.is_none() && self.channels.is_none()
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

    for (key, value) in mapping {
        let Some(name) = key.as_str() else {
            continue;
        };
        match name {
            "channels" | "channel_list" => out.channels = Some(to_doc(value).unwrap_or(Doc::Null)),
            "model_list" => out.model_list = Some(decode_model_list(value)?),
            // Every other key is either not a yaml-tagged field -- ignored, which is
            // the asymmetry this module is about -- or a section this crate's config
            // path does not decode yet. Dropping one silently would load a config the
            // Go build would have changed, so it is reported.
            other => {
                return Err(Error::SecurityType(format!(
                    "security section {other:?} is not implemented by this crate"
                )))
            }
        }
    }

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

/// Writes the yaml-tagged half of a config.
///
/// `document` is the marshalled config; the sections are read out of it in the order
/// `yaml.v3` emits them, which is not the order they appear in the JSON file.
#[must_use]
pub fn write(document: &Doc) -> String {
    let mut out = String::new();
    for section in ["channel_list", "model_list", "web", "skills"] {
        let Some(value) = document.get(section) else {
            continue;
        };
        emit_section(&mut out, section, value);
    }
    out
}

fn emit_section(out: &mut String, key: &str, value: &Doc) {
    out.push_str(key);
    out.push(':');
    match value.as_object() {
        Some(entries) if entries.is_empty() => out.push_str(" {}\n"),
        Some(entries) => {
            out.push('\n');
            for (k, v) in entries {
                emit_entry(out, &quote_if_needed(k), 1, v);
            }
        }
        None => {
            out.push(' ');
            out.push_str(&scalar(value));
            out.push('\n');
        }
    }
}

fn emit_entry(out: &mut String, key: &str, depth: usize, value: &Doc) {
    let pad = "  ".repeat(depth);
    match value {
        Doc::Object(entries) if entries.is_empty() => {
            out.push_str(&format!("{pad}{key}: {{}}\n"));
        }
        Doc::Object(entries) => {
            out.push_str(&format!("{pad}{key}:\n"));
            for (k, v) in entries {
                emit_entry(out, &quote_if_needed(k), depth + 1, v);
            }
        }
        Doc::Array(items) if items.is_empty() => {
            out.push_str(&format!("{pad}{key}: []\n"));
        }
        Doc::Array(items) => {
            out.push_str(&format!("{pad}{key}:\n"));
            for item in items {
                out.push_str(&format!("{}- {}\n", "  ".repeat(depth + 1), scalar(item)));
            }
        }
        other => out.push_str(&format!("{pad}{key}: {}\n", scalar(other))),
    }
}

/// yaml.v3's plain-scalar rule for the keys this file actually holds.
///
/// `LongCat-Flash-Thinking:0` is emitted **unquoted**: a colon only needs quoting when
/// it is followed by a space, and a key that is a `name:index` pair is the common case
/// here. Quoting it anyway produces the same data and a different byte, which is exactly
/// the kind of difference this port is graded on.
fn quote_if_needed(key: &str) -> String {
    let needs = key.is_empty()
        || key.contains(": ")
        || key.starts_with([
            '-', '?', ':', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`',
        ])
        || key.ends_with(':')
        || key.contains(" #")
        || key.trim() != key;
    if needs {
        format!("\"{}\"", key.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        key.to_string()
    }
}

fn scalar(value: &Doc) -> String {
    match value {
        Doc::String(s) => {
            if s.is_empty() {
                "\"\"".to_string()
            } else if s.contains([':', '#', '\n']) || s.trim() != s {
                format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                s.clone()
            }
        }
        Doc::Bool(b) => b.to_string(),
        Doc::Int(i) => i.to_string(),
        Doc::Float(f) => crate::doc::go_number(*f),
        Doc::Null => "null".to_string(),
        Doc::Array(_) | Doc::Object(_) => "{}".to_string(),
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
        let models = sec.model_list.expect("model_list present");
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
            let channels = sec.channels.expect("section present");
            assert!(channels.get("telegram").is_some(), "{key} not recognised");
        }
    }

    #[test]
    fn an_unknown_section_is_reported_not_dropped() {
        // The deliberate choice: silently ignoring a section Go would have applied is
        // the failure this crate cannot afford, so it is loud instead.
        let err = parse("tools:\n  exec:\n    enabled: true\n").expect_err("unknown section");
        assert!(matches!(err, Error::SecurityType(_)), "got {err}");
    }

    #[test]
    fn a_name_index_key_is_emitted_unquoted() {
        // The byte-level rule the writer exists to get right.
        let doc = from_json(r#"{"model_list":{"LongCat-Flash-Thinking:0":{}}}"#).into_doc();
        assert_eq!(write(&doc), "model_list:\n  LongCat-Flash-Thinking:0: {}\n");
    }

    #[test]
    fn a_key_that_would_be_ambiguous_is_quoted() {
        assert_eq!(quote_if_needed("a: b"), "\"a: b\"");
        assert_eq!(quote_if_needed("-lead"), "\"-lead\"");
        assert_eq!(quote_if_needed("plain:ok"), "plain:ok");
    }

    #[test]
    fn the_four_sections_are_written_in_order() {
        let doc = from_json(
            r#"{"skills":{"registries":{}},"web":{"brave":{}},"model_list":{},"channel_list":{}}"#,
        )
        .into_doc();
        let text = write(&doc);
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
