//! The unknown-field validator: `pkg/config/diagnostics.go`'s reflection pass,
//! over a schema table extracted from the same structs.
//!
//! Go has no `DisallowUnknownFields` here. It unmarshals the document into
//! `any`, walks it against `reflect.TypeOf(target)`, and refuses any key the type
//! cannot place -- at any depth, naming the path to the offender. That is why a
//! typo inside one channel's options (`channel_list.telegram.nonsense`) and one
//! inside a model entry (`model_list[0].zzz`) are both fatal, and why the message
//! says *where*.
//!
//! A Rust port gets this for free-looking from `deny_unknown_fields`, and gets it
//! wrong in four ways at once:
//!
//! * serde refuses at the **first** unknown key; Go collects them all and reports
//!   the whole list, sorted.
//! * serde's error names the struct, not the JSON path, and never indexes a
//!   sequence element.
//! * serde's `deny_unknown_fields` does not compose with flattened or untagged
//!   types, and this tree has a `map[string]*Channel` whose value type is a
//!   struct with a free-form `settings` sub-map -- the two need different rules.
//! * Go's traversal **stops descending when the shapes disagree**: a scalar where
//!   the type says struct yields no issues at all, because the code returns nil
//!   rather than a type error. The decode that follows is what complains, and it
//!   complains differently.
//!
//! So the traversal below is written to match `collectUnknownJSONFields` line for
//! line, including the branches that quietly return nothing.

use serde_json::Value;

use crate::doc::Doc;

/// One position in the config schema.
///
/// Mirrors the dump produced by `pkg/config/schema_dump.go` in the picoclaw
/// repository. That file is the source of truth: this is a *generated* artifact,
/// and the refresh command is in [`SCHEMA_JSON`]'s docs.
#[derive(Debug, Clone)]
pub enum Schema {
    /// A struct: the listed JSON names, each with what it leads to.
    Struct {
        fields: Vec<(&'static str, Schema)>,
        omit: Option<&'static str>,
        /// The Go type name, for the four positions whose emission is decided by a
        /// `MarshalYAML` method rather than by the field list.
        name: Option<&'static str>,
        /// What `yaml.v3` writes for this struct: the emitted fields in declaration
        /// order. Empty for a struct no yaml path reaches.
        yaml: Vec<YamlField>,
        /// `Channel` only: the JSON keys that belong to the channel itself rather than
        /// to its `settings`. `migration.go` consults the Go map this came from.
        base_fields: Vec<&'static str>,
        /// `Channel` only: channel type -> the struct its `settings` block decodes into.
        settings_schemas: Vec<(&'static str, Schema)>,
        /// The type implements `yaml.Marshaler`, so its own method decides what is
        /// emitted and the generic walk must not run for it.
        marshaler: bool,
    },
    /// A map: every key is allowed, every value must satisfy `elem`. The path segment
    /// is the key itself, so `channel_list.telegram` is a real path.
    Map {
        elem: Box<Schema>,
        omit: Option<&'static str>,
        name: Option<&'static str>,
        marshaler: bool,
    },
    /// A slice: the shape is checked per element, and the path gains `[i]`.
    Slice {
        elem: Box<Schema>,
        omit: Option<&'static str>,
        /// The named type behind the alias, when there is one (`SecureModelList`).
        name: Option<&'static str>,
        /// A named slice or map type can declare `MarshalYAML` just as a struct can --
        /// `SecureModelList` and `SkillsRegistriesConfig` both do. Keeping the flag only
        /// on `Struct` silently loses it there, and the generic walk then writes the
        /// element list where Go writes a projection.
        marshaler: bool,
    },
    /// Anything else. Go's `default:` arm returns no issues, so a scalar never
    /// reports anything no matter what the document holds there.
    Scalar {
        omit: Option<&'static str>,
        name: Option<&'static str>,
        marshaler: bool,
    },
}

/// One entry of a struct's yaml emission list, straight out of the dump.
#[derive(Debug, Clone)]
pub struct YamlField {
    /// The key this field holds in the JSON document.
    pub json: &'static str,
    /// The key `yaml.v3` writes.
    pub name: &'static str,
    /// `yaml:",inline"`: the field's children are emitted at this level.
    pub inline: bool,
    /// `omitempty`. yaml.v3 has no `omitzero`.
    pub omit: Option<&'static str>,
}

impl Schema {
    /// The element schema of a map or slice.
    #[must_use]
    pub fn elem(&self) -> Option<&Schema> {
        match self {
            Self::Map { elem, .. } | Self::Slice { elem, .. } => Some(elem),
            _ => None,
        }
    }

    /// The struct a channel of this type decodes its settings into, if the channel type
    /// is one `channelSettingsFactory` knows.
    #[must_use]
    pub fn settings_schema(&self, channel_type: &str) -> Option<&Schema> {
        match self {
            Self::Struct {
                settings_schemas, ..
            } => settings_schemas
                .iter()
                .find(|(name, _)| *name == channel_type)
                .map(|(_, schema)| schema),
            _ => None,
        }
    }

    /// The channel-level field names: everything else in a legacy flat channel entry
    /// belongs in `settings`. Empty for anything that is not `Channel`.
    #[must_use]
    pub fn base_fields(&self) -> &[&'static str] {
        match self {
            Self::Struct { base_fields, .. } => base_fields,
            _ => &[],
        }
    }

    /// The Go type name, for structs.
    #[must_use]
    pub fn name(&self) -> Option<&'static str> {
        match self {
            Self::Struct { name, .. }
            | Self::Map { name, .. }
            | Self::Slice { name, .. }
            | Self::Scalar { name, .. } => *name,
        }
    }

    /// Whether this position's emission is decided by a `MarshalYAML` method.
    #[must_use]
    pub const fn is_marshaler(&self) -> bool {
        matches!(
            self,
            Self::Struct {
                marshaler: true,
                ..
            } | Self::Slice {
                marshaler: true,
                ..
            } | Self::Map {
                marshaler: true,
                ..
            } | Self::Scalar {
                marshaler: true,
                ..
            }
        )
    }

    /// The yaml emission list, in declaration order.
    #[must_use]
    pub fn yaml_fields(&self) -> &[YamlField] {
        match self {
            Self::Struct { yaml, .. } => yaml,
            _ => &[],
        }
    }

    /// The field's encoding option: `Some("omitempty")`, `Some("omitzero")`, or
    /// `None`.
    ///
    /// The validator never asks. The marshaller does, and the answer has to come from
    /// the same extraction as the field names, or the two drift.
    #[must_use]
    pub const fn omit(&self) -> Option<&'static str> {
        match self {
            Self::Struct { omit, .. } | Self::Map { omit, .. } | Self::Slice { omit, .. } => *omit,
            Self::Scalar { omit, .. } => *omit,
        }
    }
}

/// The schema, as the extractor emitted it.
///
/// Refresh with, from the picoclaw checkout:
///
/// ```text
/// go run pkg/config/schema_dump.go pkg/config Config > schema.json
/// ```
///
/// then re-embed this file. The dump is a build-time artifact of the Go structs,
/// so it moves exactly when the structs move -- and `unknown_*_is_refused` in the
/// fixture is what notices a re-embed that was never done.
const SCHEMA_JSON: &str = include_str!("schema.json");

/// The root `Config` schema.
#[must_use]
pub fn config_schema() -> Schema {
    // Parsed once per process: the table is ~30 KB and the replay runs it per
    // case, so a lazy static would be the cheaper choice -- but a `OnceLock` here
    // would make the first call's failure mode (a corrupt embed) a panic at an
    // arbitrary point in the run. Parsing per call keeps the panic, if it ever
    // happens, next to the data that caused it.
    let value: Value = serde_json::from_str(SCHEMA_JSON)
        .expect("the embedded schema dump must be valid JSON; regenerate it with schema_dump.go");
    from_value(&value)
}

fn from_value(value: &Value) -> Schema {
    // Read once, because a named slice or map type carries it too.
    let marshaler = value
        .get("marshaler")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Read once, for the same reason: the name is what says which named type this node
    // is, and a named slice or map has one just as a struct does.
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .map(|n| Box::leak(n.to_string().into_boxed_str()) as &'static str);
    match value.get("kind").and_then(Value::as_str) {
        Some("struct") => {
            let omit = omit_of(value);
            let base_fields = value
                .get("base_fields")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|i| i.as_str())
                        .map(|s| Box::leak(s.to_string().into_boxed_str()) as &'static str)
                        .collect()
                })
                .unwrap_or_default();
            let settings_schemas = match value.get("settings_schemas") {
                Some(Value::Object(entries)) => entries
                    .iter()
                    .map(|(k, v)| {
                        (
                            Box::leak(k.clone().into_boxed_str()) as &'static str,
                            from_value(v),
                        )
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let yaml = value
                .get("yaml_fields")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|f| {
                            let json = f.get("json").and_then(Value::as_str)?;
                            let name = f.get("name").and_then(Value::as_str)?;
                            Some(YamlField {
                                json: Box::leak(json.to_string().into_boxed_str()) as &'static str,
                                name: Box::leak(name.to_string().into_boxed_str()) as &'static str,
                                inline: f.get("inline").and_then(Value::as_bool).unwrap_or(false),
                                omit: match f.get("omit").and_then(Value::as_str) {
                                    Some("omitempty") => Some("omitempty"),
                                    _ => None,
                                },
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut fields = Vec::new();
            if let Some(obj) = value.get("fields").and_then(Value::as_object) {
                for (name, child) in obj {
                    fields.push((
                        Box::leak(name.clone().into_boxed_str()) as &'static str,
                        from_value(child),
                    ));
                }
            }
            // Sorted so the traversal order does not depend on the JSON document's
            // key order. It cannot change the answer -- Go looks a name up in a map
            // -- but it makes a debug dump of the schema stable.
            fields.sort_by_key(|(name, _)| *name);
            Schema::Struct {
                fields,
                omit,
                name,
                yaml,
                base_fields,
                settings_schemas,
                marshaler,
            }
        }
        Some("map") => Schema::Map {
            elem: Box::new(value.get("elem").map_or_else(
                || Schema::Scalar {
                    omit: None,
                    name: None,
                    marshaler: false,
                },
                from_value,
            )),
            omit: omit_of(value),
            name,
            marshaler,
        },
        Some("slice") => Schema::Slice {
            elem: Box::new(value.get("elem").map_or_else(
                || Schema::Scalar {
                    omit: None,
                    name: None,
                    marshaler: false,
                },
                from_value,
            )),
            omit: omit_of(value),
            name,
            marshaler,
        },
        _ => Schema::Scalar {
            omit: omit_of(value),
            name,
            marshaler,
        },
    }
}

/// The `omit` the extractor recorded for this position, if any.
fn omit_of(value: &Value) -> Option<&'static str> {
    match value.get("omit").and_then(Value::as_str) {
        Some("omitempty") => Some("omitempty"),
        Some("omitzero") => Some("omitzero"),
        // Anything else is a dump from an extractor that predates the field, or a
        // value neither option spells. Treating an unknown spelling as "no option"
        // would silently keep a key Go drops, so it says so instead.
        Some(other) => panic!("unknown omit option {other:?} in the schema dump"),
        None => None,
    }
}

impl Schema {
    /// The JSON names this position accepts, for a struct.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Schema> {
        match self {
            Self::Struct { fields, .. } => fields.iter().find(|(k, _)| *k == name).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Every key in `document` that `schema` cannot place, in Go's order.
///
/// Go sorts with `sort.Strings` -- raw byte order, which is what Rust's `sort()`
/// on `String` also does -- and joins with `", "`. It does **not** deduplicate: a
/// document that repeats a bad key inside two map entries reports both.
#[must_use]
pub fn unknown_fields(document: &Doc, schema: &Schema) -> Vec<String> {
    let mut issues = Vec::new();
    collect(document, schema, "", &mut issues);
    issues.sort();
    issues
}

/// Refuses the document if any key cannot be placed.
///
/// Returns the same list Go would have joined into its message.
pub fn validate_against(document: &Doc, schema: &Schema) -> Result<(), Vec<String>> {
    let issues = unknown_fields(document, schema);
    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

/// `collectUnknownJSONFields`, arm by arm.
fn collect(raw: &Doc, target: &Schema, path: &str, issues: &mut Vec<String>) {
    match target {
        Schema::Struct { .. } => {
            // `raw.(map[string]any)`, and `return nil` when it is not one. A
            // scalar where the type says struct is not this function's problem:
            // the decode reports it, with a different sentence.
            let Some(entries) = raw.as_object() else {
                return;
            };
            for (key, value) in entries {
                match target.field(key) {
                    None => issues.push(append_json_path(path, key)),
                    Some(child) => collect(value, child, &append_json_path(path, key), issues),
                }
            }
        }
        Schema::Slice { elem, .. } => {
            let Some(items) = raw.as_array() else {
                return;
            };
            for (i, item) in items.iter().enumerate() {
                let item_path = format!("{path}[{i}]");
                collect(item, elem, &item_path, issues);
            }
        }
        Schema::Map { elem, .. } => {
            let Some(entries) = raw.as_object() else {
                return;
            };
            for (key, value) in entries {
                let key_path = append_json_path(path, key);
                collect(value, elem, &key_path, issues);
            }
        }
        Schema::Scalar { .. } => {}
    }
}

/// `appendJSONPath`: the root has no leading dot, everything else does.
fn append_json_path(path: &str, segment: &str) -> String {
    if path.is_empty() {
        segment.to_string()
    } else {
        format!("{path}.{segment}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::from_json;

    fn schema() -> Schema {
        config_schema()
    }

    /// The tests speak JSON text rather than a value macro, because the thing under
    /// test is a traversal over the crate's own document type.
    fn doc(text: &str) -> Doc {
        from_json(text).into_doc()
    }

    #[test]
    fn a_default_config_is_clean() {
        // The table and the schema are both derived from the same structs, so a
        // mismatch here means one of them was regenerated without the other.
        let document = crate::defaults::default_config("/home/oracle");
        let issues = unknown_fields(&document, &schema());
        assert!(
            issues.is_empty(),
            "the default table carries keys the schema refuses: {issues:?}"
        );
    }

    #[test]
    fn a_typo_inside_a_channel_is_named_by_path() {
        // The exact shape of the corpus case unknown_channel_option_is_refused.
        let document =
            doc(r#"{"version":3,"channel_list":{"telegram":{"enabled":true,"nonsense":1}}}"#);
        assert_eq!(
            unknown_fields(&document, &schema()),
            ["channel_list.telegram.nonsense"]
        );
    }

    #[test]
    fn a_typo_inside_a_model_entry_carries_the_index() {
        let document = doc(r#"{"version":3,"model_list":[{"model_name":"m1","zzz":1}]}"#);
        assert_eq!(unknown_fields(&document, &schema()), ["model_list[0].zzz"]);
    }

    #[test]
    fn several_offenders_are_collected_and_sorted() {
        // serde would stop at the first; Go reports the list. The order here is
        // byte order, not document order -- bot_token precedes allowed_user_ids in
        // the document and follows it in the answer.
        let document = doc(
            r#"{"version":3,"channel_list":{"telegram":{"bot_token":"1","allowed_user_ids":[1],"enabled":true}}}"#,
        );
        assert_eq!(
            unknown_fields(&document, &schema()),
            [
                "channel_list.telegram.allowed_user_ids",
                "channel_list.telegram.bot_token"
            ]
        );
    }

    #[test]
    fn providers_is_not_a_config_field() {
        // The bug the corpus pins: migrateV0ToV1 leaves `providers` in the map and
        // the validator has no field to match it to. If this ever stops reporting
        // it, either the migration started deleting the key or the schema grew a
        // field -- and the port has to follow whichever way it went.
        let document = doc(r#"{"providers":{"openrouter":{"api_key":"sk-1"}}}"#);
        assert_eq!(unknown_fields(&document, &schema()), ["providers"]);
    }

    #[test]
    fn a_scalar_where_the_type_says_struct_reports_nothing() {
        // The arm that returns nil. Not a hole to exploit: the decode that follows
        // refuses with a type error, which is a different variant of the crate's
        // Error. What this pins is that the validator does not invent a path.
        let document = doc(r#"{"agents":"not an object"}"#);
        assert!(unknown_fields(&document, &schema()).is_empty());
    }

    #[test]
    fn a_scalar_where_the_type_says_slice_reports_nothing() {
        let document = doc(r#"{"model_list":"not an array"}"#);
        assert!(unknown_fields(&document, &schema()).is_empty());
    }

    #[test]
    fn map_keys_are_paths_and_indexes_are_bracketed() {
        assert_eq!(append_json_path("", "a"), "a");
        assert_eq!(append_json_path("a", "b"), "a.b");
    }

    #[test]
    fn validate_reports_the_same_list_the_message_would_join() {
        let document = doc(r#"{"bogus":1}"#);
        let err = validate_against(&document, &schema()).expect_err("bogus must be refused");
        assert_eq!(err, ["bogus"]);
    }
}
