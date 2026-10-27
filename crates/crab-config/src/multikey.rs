//! `expandMultiKeyModels` — one config entry per API key, for key-level failover.
//!
//! A model that carries several keys is not one model with a pool: `LoadConfig`
//! (config.go:1535) rewrites `model_list` so that each extra key becomes its *own*
//! entry, and the original gains a `fallbacks` list pointing at them. The extra entries
//! are what Go marks `isVirtual`, and `SaveConfig` drops them again — so the file keeps
//! one entry while the loaded value carries N, and the fallbacks the loader invented are
//! written back. That asymmetry is the whole reason this is a stage rather than a detail:
//! a port that expands on load and forgets to filter on save duplicates the user's model
//! list on every start, and one that filters but does not expand loses their failover.
//!
//! ## The copy is field-by-field into a fresh struct
//!
//! Both the primary entry and each virtual one are built by naming fields, not by
//! cloning. Two consequences the struct tags do not suggest:
//!
//! * **`enabled` is not in the list**, so the copy's struct leaves it false where the user
//!   had written true. A single-key model is returned *as it was* — the `len(keys) <= 1`
//!   arm appends the same pointer — so its `Enabled` survives. That difference is in the
//!   struct and not in the file: `enabled` is `omitempty`, so false is dropped and a reader
//!   sees the absent key as enabled either way. It is stated here because the code reads
//!   like an oversight otherwise, and because a port that copies `enabled` would diverge
//!   from Go in memory while matching it on disk.
//! * **The virtual entries come first.** The loop appends each `name__key_N` and the
//!   primary is appended after the loop, so a two-key `m1` loads as `[m1__key_1, m1]`,
//!   not `[m1, m1__key_1]`. Order is observable: it is the order `json.Marshal` writes
//!   the loaded value in.
//!
//! `fallbacks` is *prepended*, not appended: `append(fallbackNames, m.Fallbacks...)`, so
//! the generated keys are tried before whatever the user already listed.
//!
//! ## How the port knows which entries it made
//!
//! Go carries the fact on the struct (`isVirtual`). A document has no such field, and
//! inventing one would put a key in the file that the schema validator refuses. So
//! [`expand`] returns the positions it created and [`crate::Config`] carries them — the
//! same per-entry flag, one level up. Recomputing them at save time from the `__key_N`
//! suffix is not equivalent: a user's own model may legitimately be named that, and Go
//! would keep it.

use crate::doc::Doc;
use crate::schema::Schema;

/// The suffix Go gives an extra-key entry: `fmt.Sprintf("__key_%d", i)` for `i` in
/// `1..len(keys)`.
fn virtual_suffix(index: usize) -> String {
    format!("__key_{index}")
}

/// Runs the stage over a loaded document, returning the `model_list` positions the
/// loader created.
///
/// `schema` is the config schema; only `model_list`'s element type is consulted, and
/// only for the field order the rebuilt entries are written in. Go's fresh struct has
/// declaration order regardless of the order the file used, so rebuilding in the dump's
/// order is what makes the loaded value match.
pub(crate) fn expand(document: &mut Doc, schema: &Schema) -> Vec<usize> {
    let Some(elem) = model_elem(schema) else {
        return Vec::new();
    };
    let Some(list) = document
        .get_mut_at("model_list")
        .and_then(Doc::as_array_mut)
    else {
        return Vec::new();
    };

    let source = std::mem::take(list);
    let mut expanded: Vec<Doc> = Vec::with_capacity(source.len());
    let mut virtual_positions = Vec::new();

    for entry in source {
        let keys = api_keys(&entry);
        if keys.len() <= 1 {
            // The same entry, and not a copy: a single-key model keeps whatever the file
            // gave it, including `enabled`. "The same entry" is the same *struct*, though,
            // and a struct marshals every field that is not omitted -- so a file that never
            // mentioned `provider` still writes `"provider": ""`. Hence materialise.
            expanded.push(materialise(entry, elem));
            continue;
        }

        let name = entry
            .get("model_name")
            .and_then(Doc::as_str)
            .unwrap_or_default()
            .to_string();
        let existing_fallbacks = entry
            .get("fallbacks")
            .and_then(Doc::as_array)
            .cloned()
            .unwrap_or_default();

        let mut generated: Vec<Doc> = Vec::with_capacity(keys.len() - 1);
        let mut fallback_names: Vec<Doc> = Vec::with_capacity(keys.len() - 1);
        for (index, key) in keys.iter().enumerate().skip(1) {
            let expanded_name = format!("{name}{}", virtual_suffix(index));
            let mut copy = rebuild(&entry, elem, &expanded_name);
            copy.set("api_keys", Doc::Array(vec![key.clone()]));
            generated.push(copy);
            fallback_names.push(Doc::String(expanded_name));
        }

        let mut primary = rebuild(&entry, elem, &name);
        primary.set("api_keys", Doc::Array(vec![keys[0].clone()]));
        // Generated names first, then whatever the file already listed.
        fallback_names.extend(existing_fallbacks);
        primary.set("fallbacks", Doc::Array(fallback_names));

        let first_virtual = expanded.len();
        for entry in generated {
            virtual_positions.push(expanded.len());
            expanded.push(entry);
        }
        debug_assert_eq!(
            virtual_positions.len() - (expanded.len() - first_virtual),
            0
        );
        expanded.push(primary);
    }

    *list = expanded;
    virtual_positions
}

/// One rebuilt entry: the fields Go names in its copy, in declaration order, with
/// `enabled` left out because Go's copy does not name it.
fn rebuild(entry: &Doc, elem: &Schema, model_name: &str) -> Doc {
    let mut out = Vec::with_capacity(20);
    for field in elem.json_fields() {
        let key = field.json;
        if key == "enabled" {
            continue;
        }
        if key == "model_name" {
            out.push((key.to_string(), Doc::String(model_name.to_string())));
            continue;
        }
        match entry.get(key) {
            Some(value) => out.push((key.to_string(), value.clone())),
            // Absent means Go's copy assigned the zero value. Only a field with no omit
            // option is then *written*, so only those need materialising here; the rest
            // would be dropped by the marshaller anyway, and writing `{}` for one would
            // be a document Go does not produce.
            None if field.omit.is_none() => {
                out.push((key.to_string(), zero_for(elem, key)));
            }
            None => {}
        }
    }
    Doc::Object(out)
}

/// The Go zero value for a field the copy always writes.
fn zero_for(elem: &Schema, key: &str) -> Doc {
    match elem.field(key) {
        Some(Schema::Struct { .. }) | Some(Schema::Map { .. }) => Doc::Object(Vec::new()),
        Some(Schema::Slice { .. }) => Doc::Array(Vec::new()),
        Some(Schema::Scalar { name, .. }) => match name {
            Some("bool") => Doc::Bool(false),
            Some("int") | Some("int64") => Doc::Int(0),
            Some("float64") | Some("float32") => Doc::Float(0.0),
            _ => Doc::String(String::new()),
        },
        // A field the dump does not name cannot be one Go copies.
        None => Doc::Null,
    }
}

/// The entry's `api_keys`, as strings.
///
/// The document carries them because the security file put them there; the marshaller
/// never writes them, which is why they are invisible in every recorded value while
/// still deciding this stage's arithmetic.
fn api_keys(entry: &Doc) -> Vec<Doc> {
    entry
        .get("api_keys")
        .and_then(Doc::as_array)
        .cloned()
        .unwrap_or_default()
}

/// `model_list`'s element schema, the one position this stage reads the dump for.
/// Rebuilds a `model_list` entry in the order and with the fields `ModelConfig` has.
///
/// It fills in what the struct has and the file omitted; it does **not** drop what the file
/// has and the omit option would. Both directions look like the same job and only one of
/// them is this function's: emptiness is the marshaller's rule, applied where the bytes are
/// written, and it is applied to both files. A fault that ignores `field.omit` here passes
/// the whole corpus, which is the proof that the two are one rule and not two — so the check
/// lives in `marshal` alone and this function only reorders and fills.
///
/// The JSON loader decodes each entry into a struct, and `json.Marshal` then writes every
/// field whose omit option cannot fire -- `model_name`, `model` and `provider` carry no
/// option at all, so a config that never mentions `provider` still comes back with
/// `"provider": ""`. Echoing the file's keys instead gets that wrong in the direction that
/// matters most for this seam: the port's output is then *smaller* than the document the
/// shipped binary writes, and a user who loads and saves loses the field from their file.
///
/// `api_keys` is carried through untouched rather than projected. It is a `SecureStrings`,
/// which `encoding/json` never writes -- but the `.security.yml` asks the type directly and
/// gets the values, and the port renders both files from this one document. Projecting it
/// away would write a security file with no keys in it, which is the one file that must not
/// be wrong.
fn materialise(entry: Doc, elem: &Schema) -> Doc {
    let stored = match &entry {
        Doc::Object(entries) => entries.clone(),
        // Not a mapping. Go's decode would have refused the document before this stage, so
        // there is no Go behaviour to match and no reason to invent one.
        _ => return entry,
    };
    let lookup = |key: &str| stored.iter().find(|(k, _)| k == key).map(|(_, v)| v);

    let mut out: Vec<(String, Doc)> = Vec::with_capacity(stored.len());
    for field in elem.json_fields() {
        let value = lookup(field.json);
        if field.json == "api_keys" {
            if let Some(value) = value {
                out.push((field.json.to_string(), value.clone()));
            }
            continue;
        }
        let Some(value) = value else {
            // The field is not in the file. A struct marshals it anyway when no omit option
            // can fire, which is the whole reason this function exists: `provider` is one of
            // the three fields with no option, and a config that never mentions it still
            // writes `"provider": ""`.
            if field.omit.is_none() {
                out.push((field.json.to_string(), zero_for(elem, field.json)));
            }
            continue;
        };
        out.push((field.json.to_string(), value.clone()));
    }
    Doc::Object(out)
}

fn model_elem(schema: &Schema) -> Option<&Schema> {
    schema
        .field("model_list")
        .and_then(|list| match list {
            Schema::Slice { elem, .. } => Some(&**elem),
            _ => None,
        })
        .filter(|elem| matches!(elem, Schema::Struct { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::config_schema;

    fn model(body: &str) -> Doc {
        crate::doc::from_json(&format!("{{\"model_list\":[{body}]}}"))
            .doc
            .get("model_list")
            .cloned()
            .expect("parsed")
    }

    fn first(list: &Doc) -> Option<&Doc> {
        list.as_array().and_then(|entries| entries.first())
    }

    #[test]
    fn one_key_is_left_alone() {
        let mut doc = crate::doc::from_json(
            "{\"model_list\":[{\"model_name\":\"m\",\"provider\":\"p\",\"model\":\"q\",\"enabled\":false}]}",
        )
        .doc;
        assert!(expand(&mut doc, &config_schema()).is_empty());
        // The document keeps `enabled`. Dropping it is the marshaller's rule, applied where
        // the bytes are written, and `model_entry_drops_its_empty_optional_fields` pins the
        // byte-level half -- this one pins that the stage does not pre-empt it. The two
        // assertions together are the reason there is no omit check in `materialise`.
        assert_eq!(
            doc.get("model_list")
                .and_then(first)
                .and_then(|e| e.get("enabled")),
            Some(&Doc::Bool(false))
        );
    }

    #[test]
    fn no_keys_is_left_alone_too() {
        let mut doc = crate::doc::from_json(
            "{\"model_list\":[{\"model_name\":\"m\",\"provider\":\"p\",\"model\":\"q\"}]}",
        )
        .doc;
        assert!(expand(&mut doc, &config_schema()).is_empty());
        assert_eq!(
            doc.get("model_list")
                .and_then(|l| l.as_array())
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn two_keys_virtualise_first_and_gain_fallbacks() {
        let mut doc = crate::doc::from_json(
            &("{\"model_list\":[{\"model_name\":\"m\",\"provider\":\"p\",\"model\":\"q\","
                .to_string()
                + "\"api_keys\":[\"a\",\"b\"],\"enabled\":false}]}"),
        )
        .doc;
        let virtuals = expand(&mut doc, &config_schema());
        let list = doc.get("model_list").cloned().expect("list");
        let entries = list.as_array().expect("list");
        assert_eq!(entries.len(), 2);
        // The virtual entry is first, and it is the position the loader created.
        assert_eq!(virtuals, vec![0]);
        assert_eq!(
            entries[0].get("model_name").and_then(Doc::as_str),
            Some("m__key_1")
        );
        assert_eq!(
            entries[1].get("model_name").and_then(Doc::as_str),
            Some("m")
        );
        // `enabled` is not in Go's copy, so the disabled model comes back enabled --
        // that is, it comes back with no `enabled` key at all, which the omit rule then
        // writes as nothing.
        assert!(entries[0].get("enabled").is_none());
        assert!(entries[1].get("enabled").is_none());
        assert_eq!(
            entries[1]
                .get("fallbacks")
                .and_then(Doc::as_array)
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn generated_fallbacks_come_before_the_users_own() {
        let list = model(
            "{\"model_name\":\"m\",\"provider\":\"p\",\"model\":\"q\",\"api_keys\":[\"a\",\"b\",\"c\"],\"fallbacks\":[\"z\"]}",
        );
        let mut doc = Doc::Object(vec![("model_list".into(), list)]);
        expand(&mut doc, &config_schema());
        let entries = doc.get("model_list").and_then(Doc::as_array).expect("list");
        assert_eq!(entries.len(), 3);
        let fallbacks = entries[2]
            .get("fallbacks")
            .and_then(Doc::as_array)
            .expect("fallbacks");
        let names: Vec<&str> = fallbacks.iter().filter_map(Doc::as_str).collect();
        assert_eq!(names, vec!["m__key_1", "m__key_2", "z"]);
    }

    #[test]
    fn each_entry_carries_exactly_one_key() {
        let list = model(
            "{\"model_name\":\"m\",\"provider\":\"p\",\"model\":\"q\",\"api_keys\":[\"a\",\"b\"]}",
        );
        let mut doc = Doc::Object(vec![("model_list".into(), list)]);
        expand(&mut doc, &config_schema());
        let entries = doc.get("model_list").and_then(Doc::as_array).expect("list");
        let keys: Vec<Option<&str>> = entries
            .iter()
            .map(|e| {
                e.get("api_keys")
                    .and_then(Doc::as_array)
                    .and_then(|k| k.first())
                    .and_then(Doc::as_str)
            })
            .collect();
        assert_eq!(keys, vec![Some("b"), Some("a")]);
    }
}
