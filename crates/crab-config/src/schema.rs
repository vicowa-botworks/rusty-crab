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
        /// What `encoding/json` writes for this struct: the emitted keys in declaration
        /// order, each with its omit option. This is the order a re-marshalled config
        /// uses, and the only complete list of the keys a position can hold -- a field
        /// with no omit option is written even when its value is zero.
        json: Vec<JsonField>,
        /// `Channel` only: the JSON keys that belong to the channel itself rather than
        /// to its `settings`. `migration.go` consults the Go map this came from.
        base_fields: Vec<&'static str>,
        /// `Channel` only: channel type -> the struct its `settings` block decodes into.
        settings_schemas: Vec<(&'static str, Schema)>,
        /// `Channel` only: the singleton registry -- the channel types that allow at most
        /// one *enabled* channel. `validateSingletonChannels` counts against exactly this
        /// set, and in Go the set is built by `registerSingletonChannel` calls at init()
        /// time, so there is no literal for a port to read.
        singleton_channel_types: Vec<&'static str>,
        /// This struct's `streaming` bounds are checked by `validateChannelStreamingConfig`.
        /// The flag comes from that function's type switch, and its absence is a verdict:
        /// the switch's default arm returns nil, so a settings struct not named there loads
        /// any bounds the file carries.
        streaming_validated: bool,
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

/// One entry of a struct's JSON emission list, straight out of the dump.
#[derive(Debug, Clone)]
pub struct JsonField {
    /// The key `encoding/json` writes.
    pub json: &'static str,
    /// `omitzero` or `omitempty`. Absent means the key survives a zero value, which is
    /// most of what a channel's `settings` object holds.
    pub omit: Option<&'static str>,
}

impl Schema {
    /// The struct's JSON emission list: the keys `encoding/json` writes, in declaration
    /// order. Empty for anything that is not a struct.
    #[must_use]
    pub fn json_fields(&self) -> &[JsonField] {
        match self {
            Self::Struct { json, .. } => json,
            _ => &[],
        }
    }
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

    /// The singleton registry: channel types that allow at most one **enabled** channel.
    /// Empty for anything that is not `Channel`, which is why an empty list means "check
    /// nothing" rather than "the dump is old" -- see the note on the field.
    #[must_use]
    pub fn singleton_channel_types(&self) -> &[&'static str] {
        match self {
            Self::Struct {
                singleton_channel_types,
                ..
            } => singleton_channel_types,
            _ => &[],
        }
    }

    /// Whether `validateChannelStreamingConfig` validates this struct's streaming bounds.
    /// False is Go's default arm: the channel loads whatever bounds its file carries.
    #[must_use]
    pub const fn is_streaming_validated(&self) -> bool {
        match self {
            Self::Struct {
                streaming_validated,
                ..
            } => *streaming_validated,
            _ => false,
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
            let singleton_channel_types = value
                .get("singleton_channel_types")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|i| i.as_str())
                        .map(|s| Box::leak(s.to_string().into_boxed_str()) as &'static str)
                        .collect()
                })
                .unwrap_or_default();
            let streaming_validated = value
                .get("streaming_validated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
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
            // Both omit spellings are kept here, unlike the yaml list: `omitzero` and
            // `omitempty` disagree about structs, and which one a field carries decides
            // whether `streaming: {}` reaches the document.
            let json = value
                .get("json_fields")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|f| {
                            let json = f.get("json").and_then(Value::as_str)?;
                            Some(JsonField {
                                json: Box::leak(json.to_string().into_boxed_str()) as &'static str,
                                omit: match f.get("omit").and_then(Value::as_str) {
                                    Some("omitempty") => Some("omitempty"),
                                    Some("omitzero") => Some("omitzero"),
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
                json,
                base_fields,
                settings_schemas,
                singleton_channel_types,
                streaming_validated,
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

/// `FlexibleStringSlice.UnmarshalJSON` (`config_struct.go:22`) is a `[]string` that also
/// accepts a bare string and a bare number, and formats the elements of a mixed array one at
/// a time. Go runs it while decoding into the typed struct, so the loaded value holds a list
/// even where the file held a scalar: `"alice"` loads as `["alice"]` and `123456789` as
/// `["123456789"]`. A port that only *accepts* those files keeps the file's bytes and
/// disagrees with every recorded value at one of those fields, so the coercion -- not just the
/// tolerance -- has to be modelled.
///
/// The schema is what identifies the field: the dump carries the named type on the slice
/// (`{"kind":"slice","name":"FlexibleStringSlice"}`), so nothing needs a list of field names.
///
/// Three parts of Go's own decoder are not symmetric, and each is easy to flatten:
///
///   * `null` is answered before anything else and sets the slice to nil, which marshals back
///     as `null` -- it is not a one-element list. The empty string is a value and does become
///     `[""]`.
///   * a number goes through `%.0f`, which rounds half to even (1.5 and 2.5 are both `"2"`)
///     and keeps the sign of a value that rounds to zero (-0.4 is `"-0"`).
///   * only an *element* of an array reaches `%v`. A bare object or bool at the field falls
///     through every arm of the decoder and is refused -- but the sentence names the kind it
///     wanted, `expected string but got bool`, and never this type's name. Re-measured at
///     picoclaw `99ea66d6` against `LoadConfig` at `channel_list.telegram.allow_from` and at
///     `tools.web.private_host_whitelist`, which answer identically; [`misplaced_typed_values`]
///     now raises that sentence from the root walk, where the channel decode used to invent a
///     `config.FlexibleStringSlice` sentence Go does not print.
pub(crate) const FLEXIBLE_STRING_SLICE: &str = "FlexibleStringSlice";

/// `SecureStrings` is `[]*SecureString`, and it is **not** a [`FLEXIBLE_STRING_SLICE`]. That one
/// distinction is issue #15: the port had a single rule for named string slices, so it accepted
/// at `api_keys` every shape the shipped binary refuses.
///
/// Which decoder method each file reaches is what decides the rule, so each half names its
/// method and its line:
///
/// * `config.json` reaches `SecureStrings.UnmarshalJSON` (`pkg/config/config_struct.go:159`).
///   It exists -- only `UnmarshalYAML` does not -- and it is where both of the document's rules
///   come from: the nested `json.Unmarshal` into `[]*SecureString` inside that method is what
///   makes the field need an array, and `SecureString.UnmarshalJSON` (`:241`), which decodes a
///   `string`, is what makes every element need to be one.
/// * A **`null` element is exempt**, for a reason that is code rather than implication: a JSON
///   null decodes into a `*SecureString` as a nil pointer without that element's
///   `UnmarshalJSON` ever running, and the filter at `:168-176` drops nil pointers before
///   deciding anything. So `[null]` is behaviour of the type itself -- zero keys, and the next
///   `save` omits the field -- and `[null, 1]` blames the number, not the null.
/// * `.security.yml` reaches no method on the type at all, so yaml's generic decoder judges the
///   field: it has to be a sequence. Each *element* then lands on
///   `SecureString.UnmarshalYAML` (`:276`), which takes the node's raw text, so `api_keys: [42]`
///   **loads** there.
///
/// The document asks for strings inside the array; the file does not. Measured at picoclaw
/// `main`, one process per shape (the corpus records only that a load failed and at which op,
/// never the sentence, so these are from `/tmp/opencode/picoclaw-probes/securestrings/probe.go`
/// and `/tmp/opencode/picoclaw-probes/secstr-null/probe.go`, and nothing pins them):
///
/// ```text
/// api_keys: "sk-1"     REFUSED  expected []*config.SecureString but got string
/// api_keys: 42         REFUSED  expected []*config.SecureString but got number
/// api_keys: [42]       REFUSED  expected string but got number
/// api_keys: {}         REFUSED  expected []*config.SecureString but got object
/// api_keys: true       REFUSED  expected []*config.SecureString but got bool
/// api_keys: ["a"]      LOADED
/// api_keys: null       LOADED   (nil slice)
/// api_keys: [null]     LOADED   (nil slice -- the nil element is filtered out)
/// api_keys: [null,"a"] LOADED   (one key: "a")
/// ```
///
/// And the security file's own sentence, which is why this predicate cannot be shared: there,
/// `api_keys: 42` is refused as `cannot unmarshal !!int `42` into config.SecureStrings`.
pub(crate) const SECURE_STRINGS: &str = "SecureStrings";

/// The type name Go puts in its yaml `TypeError` for [`SECURE_STRINGS`].
pub(crate) const SECURE_STRINGS_GO_TYPE: &str = "config.SecureStrings";

/// A slice field Go decodes as [`SECURE_STRINGS`].
pub(crate) fn is_secure_strings(schema: &Schema) -> bool {
    matches!(
        schema,
        Schema::Slice {
            name: Some(SECURE_STRINGS),
            ..
        }
    )
}

/// What Go's JSON decoder wanted at a [`SECURE_STRINGS`] position and what it was handed, the
/// two halves of its sentence, or `None` when the shape decodes. `null` is answered before
/// anything else in Go and leaves the slice nil, so it is accepted -- at the field *and* inside
/// the array, where a null element becomes a nil `*SecureString` that the filter at
/// `config_struct.go:168-176` drops. Skipping it is also what makes the blamed element agree
/// with Go's: for `[null, 1]` Go says `expected string but got number`, and reporting the null
/// instead would name the wrong position while still refusing.
pub(crate) fn secure_strings_expectation(value: &Doc) -> Option<(&'static str, &'static str)> {
    match value {
        Doc::Null => None,
        Doc::Array(items) => items.iter().find_map(|item| match item {
            Doc::String(_) | Doc::Null => None,
            other => Some(("string", json_kind(other))),
        }),
        other => Some((SECURE_STRING_ELEMENT, json_kind(other))),
    }
}

/// Whether the security file's yaml decoder can place `value` in a [`SECURE_STRINGS`] field: a
/// sequence, at any element shape, or `null`. See the type's own doc comment for why this is
/// not [`secure_strings_expectation`].
pub(crate) fn secure_strings_yaml_accepts(value: &Doc) -> bool {
    matches!(value, Doc::Null | Doc::Array(_))
}

/// The word Go's `config.json type error` sentence uses for a JSON value's kind.
pub(crate) fn json_kind(value: &Doc) -> &'static str {
    match value {
        Doc::Null => "null",
        Doc::Bool(_) => "bool",
        Doc::Int(_) | Doc::Float(_) => "number",
        Doc::String(_) => "string",
        Doc::Array(_) => "array",
        Doc::Object(_) => "object",
    }
}

/// `[]*config.SecureString`, the way Go names the slice type it wanted.
const SECURE_STRING_ELEMENT: &str = "[]*config.SecureString";

/// `config.SecureString`, the scalar Go reaches for at 36 positions -- a struct in the dump
/// because it has a `MarshalJSON`, a bare string on the wire.
const SECURE_STRING: &str = "SecureString";
/// `config.SkillsRegistriesConfig`, the one slice that answers to two different JSON shapes.
const SKILLS_REGISTRIES: &str = "SkillsRegistriesConfig";

/// The first position in `document` whose JSON kind the type there cannot hold, as
/// `(dotted path, what Go would name, the kind it got)`, walking in document order because
/// Go's decoder stops at the first mismatch.
///
/// `encoding/json` is typed and `LoadConfig` asks for no leniency, so a kind the target cannot
/// place fails the load wherever it appears -- which is the general statement [`collect`] could
/// only make about unknown *keys*. It cannot be implemented as "the decoder is strict", though:
/// three families of position are not, and each was measured one process per shape against
/// `LoadConfig` at picoclaw `99ea66d6` (`/tmp/opencode/picoclaw-probes/strict/`, with the
/// verdicts kept in `strict.txt` and `strict2.txt`) rather than assumed:
///
/// * **`null` is accepted at every position**, struct, map, slice, scalar and `SecureString`
///   alike. `encoding/json` answers a null before consulting the type and leaves the zero value,
///   so `{"agents":{"defaults":{"workspace":null}}}` and `{"tools":{"skills":null}}` both load.
///   It is therefore never descended and never judged.
/// * **Raw passthroughs accept any kind.** `json.RawMessage`
///   (`agents.defaults.context_manager_config`) took a string, an object and an array; `any` --
///   the element type of `model_list[].extra_body` -- takes anything, which is why that position
///   is strict at its *container* and free below it: `extra_body: []` refuses
///   (`expected map[string]interface {} but got array`) while `extra_body: {"a":{"b":[1,2]}}`
///   loads.
/// * **Two named types set their own kind rules.**
///   [`FLEXIBLE_STRING_SLICE`] exists to take what a `[]string` refuses -- `allow_from: 42` and
///   `allow_from: "a"` both load, as one-element lists -- and its decoder's last resort is a
///   string, so an *object* is the one shape it refuses (`expected string but got object`).
///   [`SKILLS_REGISTRIES`] answers a mapping and a sequence alike (issue #29), and the two arms
///   judge their contents differently: under the mapping arm a value decodes into a
///   `SkillRegistryConfig` whose *fields* are typed (`{"clawhub":{"base_url":1}}` refuses
///   `expected string but got number`) while its unknown keys are ignored, whereas the
///   sequence arm's unknown-key refusal comes from the diagnostics pass and is already made here
///   by [`collect`]. A non-object element refuses under either arm (`[[]]`, `{"x":42}`).
///
/// What this walk does not judge is `RawNode` -- `channel_list[].settings`, which takes any kind
/// *here* and is decoded into that channel's own settings struct by
/// [`crate::channels::init_channel_list`]. That stage is where Go's sentence for a fractional
/// `media_group_delay_ms` comes from (`a_fractional_number_in_an_int_channel_field`), and
/// reaching the same verdict a second time from the root is the doubled-seam mistake this crate
/// has already made once on the security file.
///
/// Placement is the migrated document, not the file as written, because that is what Go's
/// decoder is handed: `case 0..=2` merges `.security.yml` in as plain data, runs the ladder, and
/// decodes the result -- which is also where [`validate_against`] already looks. Judging the
/// written bytes instead would refuse a config Go migrates into something valid, and the
/// `api_key` -> `api_keys` fold (`unique_api_keys`) is exactly that shape: it deletes a scalar
/// `api_key` and writes a list, so a legacy document carrying both spellings -- `api_key` a
/// string, `api_keys` a string -- loads. Measured one process per shape at picoclaw `99ea66d6`
/// against `LoadConfig`, and against this crate at the same shapes, same verdict every time:
///
/// ```text
/// v1 model_list[].api_key "sk-1" + api_keys "sk-2"   LOADED   (the fold rewrites the pair)
/// v1 model_list[].api_keys ["sk-2"]                  LOADED
/// v1 model_list[].api_keys 42                        REFUSED  expected []*config.SecureString but got number
/// v2 model_list[].api_keys {"a":1}                   REFUSED  expected []*config.SecureString but got object
/// v2 model_list 42                                   REFUSED  expected []map[string]interface {} but got number
/// ```
///
/// The last line is where the two still part company, and it is wording only: on the migration
/// path Go's first decode is into `[]map[string]interface{}`, so its sentence names the loose
/// type, while this walk already knows the field's real one. No corpus case spells `version: 0`
/// as a value (memory 1597) or carries a bad kind on the legacy path, so nothing pins either
/// form.
///
/// The sentence itself is not pinned: a failing corpus case records `error_op_index` and nothing
/// else (memory 1531), so `wanted` follows Go's `reflect` naming as closely as the dump allows
/// -- `config.Channel` for a struct, `[]config.AgentConfig` for a slice of structs, a bare
/// `string`/`int`/`bool`/`float64` for a scalar -- and one position is known to be off:
/// `channel_list.<name>` is `config.channelsConfigAlias` in Go's sentence, and the dump names the
/// same map `ChannelsConfig` because the alias does not survive to that depth in the dump.
#[must_use]
pub fn misplaced_typed_values(
    document: &Doc,
    schema: &Schema,
) -> Option<(String, String, &'static str)> {
    let mut found = None;
    hunt(document, schema, "", &mut found);
    found
}

/// The traversal [`collect`] makes, narrowed to the positions where the type decides what it can
/// hold. It follows the schema rather than a list of field names, so a new strict field is
/// covered by the dump alone -- the same reason `FlexibleStringSlice` and `SecureStrings` are
/// identified by their named type.
fn hunt(
    raw: &Doc,
    target: &Schema,
    path: &str,
    found: &mut Option<(String, String, &'static str)>,
) {
    if found.is_some() {
        return;
    }
    // Hoisted above the match on purpose: the type is recognised wherever a schema position
    // reaches it, not only as a struct field. The dump holds exactly five `SecureStrings` nodes
    // today (`model_list[].api_keys` plus the four `tools.web.*` ones) and every one of them is
    // a struct field, so a `[]SecureStrings` or a `map[string]SecureStrings` would be walked
    // unjudged if this test lived inside the `Struct` arm -- and "the next regeneration covers
    // it" is only a true statement about fields.
    if is_secure_strings(target) {
        if let Some((wanted, got)) = secure_strings_expectation(raw) {
            *found = Some((path.to_string(), wanted.to_string(), got));
        }
        return;
    }
    if matches!(raw, Doc::Null) {
        return;
    }
    match target {
        Schema::Scalar { name, .. } => {
            if let Some(wanted) = scalar_mismatch(*name, raw) {
                *found = Some((path.to_string(), wanted, json_kind(raw)));
            }
        }
        Schema::Struct { name, .. } => {
            // A struct on the wire as a bare string. `SecureString.UnmarshalJSON` accepts a
            // string and refuses every other kind -- `{"token":true}` is refused, so the type
            // error is not "only a number offends it" -- and the 36 positions of this type are
            // exactly the surface issue #15 was filed against.
            if *name == Some(SECURE_STRING) {
                if !matches!(raw, Doc::String(_)) {
                    *found = Some((path.to_string(), go_type_name(*name), json_kind(raw)));
                }
                return;
            }
            let Some(entries) = raw.as_object() else {
                *found = Some((path.to_string(), go_type_name(*name), json_kind(raw)));
                return;
            };
            for (key, value) in entries {
                let Some(child) = target.field(key) else {
                    continue;
                };
                hunt(value, child, &append_json_path(path, key), found);
                if found.is_some() {
                    return;
                }
            }
        }
        Schema::Slice {
            elem,
            name: Some(SKILLS_REGISTRIES),
            ..
        } => match raw {
            // The sequence arm: `[{...}]`. Judged element by element against the entry type,
            // which is what refuses `[[]]` and `[42]`.
            Doc::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    hunt(item, elem, &format!("{path}[{i}]"), found);
                    if found.is_some() {
                        return;
                    }
                }
            }
            // The mapping arm: `{"name":{...}}`. Not a JSON array at all, and this is the only
            // walk that reaches inside it -- [`collect`] stops here on purpose, because Go's
            // diagnostics pass does not descend a slice position holding an object, which is why
            // an unknown key in the mapping spelling loads and the same key in the sequence
            // spelling is refused.
            Doc::Object(entries) => {
                for (key, value) in entries {
                    hunt(value, elem, &append_json_path(path, key), found);
                    if found.is_some() {
                        return;
                    }
                }
            }
            other => {
                *found = Some((
                    path.to_string(),
                    go_type_name(Some(SKILLS_REGISTRIES)),
                    json_kind(other),
                ))
            }
        },
        Schema::Slice { elem, name, .. } => {
            if *name == Some(FLEXIBLE_STRING_SLICE) {
                // The type's own decoder is a chain of attempts, and only two kinds fall off the
                // end of it: a string, a number (`%.0f`, half-to-even), an array (`%v` per
                // element) and `null` all load, while a **bool** and an **object** are refused.
                // Measured one process per shape at picoclaw `99ea66d6` at
                // `channel_list.telegram.allow_from` and at `tools.web.private_host_whitelist`,
                // which answer identically: `true` -> `expected string but got bool`,
                // `{"a":"b"}` -> `expected string but got object`, and `42`, `1.5`, `"a"`, `[true]`
                // and `[{"a":1}]` all load. The last two are the reason the array is not descended:
                // an element is stringified by `%v` rather than judged.
                if matches!(raw, Doc::Bool(_) | Doc::Object(_)) {
                    *found = Some((path.to_string(), "string".to_string(), json_kind(raw)));
                }
                return;
            }
            let Some(items) = raw.as_array() else {
                *found = Some((path.to_string(), go_type_name(*name), json_kind(raw)));
                return;
            };
            for (i, item) in items.iter().enumerate() {
                hunt(item, elem, &format!("{path}[{i}]"), found);
                if found.is_some() {
                    return;
                }
            }
        }
        Schema::Map { elem, name, .. } => {
            let Some(entries) = raw.as_object() else {
                *found = Some((path.to_string(), go_type_name(*name), json_kind(raw)));
                return;
            };
            for (key, value) in entries {
                hunt(value, elem, &append_json_path(path, key), found);
                if found.is_some() {
                    return;
                }
            }
        }
    }
}

/// What Go's decoder wanted at a scalar position of named type `name` and did not get, or `None`
/// when the value fits.
///
/// Fail-open on any name this has no measurement for: a port that refuses what it cannot place
/// has to be sure it is not placing something Go accepts, and inventing a rule is how it starts.
fn scalar_mismatch(name: Option<&str>, raw: &Doc) -> Option<String> {
    let ok = match name {
        // Bytes handed to the field untouched. Measured at `context_manager_config`: a string,
        // an object and an array all load.
        Some("any") | Some("RawNode") | Some("json.RawMessage") => return None,
        Some("string") => matches!(raw, Doc::String(_)),
        Some("bool") => matches!(raw, Doc::Bool(_)),
        // Go parses the literal as an integer, so `2.0`, `1e2` and `9223372036854775808` are all
        // refusals (`expected int but got number`) while `-5` and `i64::MAX` load. This crate's
        // `Doc` spells all three of the refusals as a `Float`, so one arm covers them; the
        // beyond-`i64` shape is what `fix/parse-past-int64` made parseable in the first place.
        Some("int") | Some("int64") => matches!(raw, Doc::Int(_)),
        Some("float64") => matches!(raw, Doc::Int(_) | Doc::Float(_)),
        // The one named scalar in the tree, and a string type: the four `*_turn_profile_*` cases
        // that load a mode string pin the accepting half, and a number is refused like any other
        // kind a string cannot hold.
        Some("TurnProfileMode") => matches!(raw, Doc::String(_)),
        _ => return None,
    };
    if ok {
        return None;
    }
    Some(match name {
        Some("string") | Some("bool") | Some("int") | Some("int64") | Some("float64") => {
            name.unwrap_or("value").to_string()
        }
        other => go_type_name(other),
    })
}

/// How Go's `reflect` names the type behind a dump node's `name`, as far as the dump reaches
/// (see [`misplaced_typed_values`] for what that buys and what it cannot).
fn go_type_name(name: Option<&str>) -> String {
    let Some(name) = name else {
        return "value".to_string();
    };
    if let Some(elem) = name.strip_prefix("[]") {
        return format!("[]{}", go_type_name(Some(elem)));
    }
    if let Some(elem) = name.strip_prefix("map[string]") {
        return format!("map[string]{}", go_type_name(Some(elem)));
    }
    match name {
        "any" => "interface {}".to_string(),
        "string" | "bool" | "int" | "int64" | "int32" | "uint64" | "float64" | "float32" => {
            name.to_string()
        }
        // Already qualified, or a package-qualified name like `json.RawMessage`.
        other if other.contains('.') => other.to_string(),
        other => format!("config.{other}"),
    }
}

/// One element of the list Go ends up with: a string passes through, a number takes the
/// `%.0f` arm, everything else takes `%v`.
pub(crate) fn flexible_element_text(value: &Doc) -> Doc {
    let text = match value {
        Doc::String(s) => s.clone(),
        // `encoding/json` hands the type a `float64` for *every* number, so an integer is
        // `%.0f` of a float: past 2^53 the value moves, and matching that is the difference
        // between Go's `["12345678901234568"]` and a faithful-looking `["12345678901234567"]`.
        Doc::Int(i) => format!("{:.0}", *i as f64),
        Doc::Float(f) => format!("{f:.0}"),
        other => go_percent_v(other),
    };
    Doc::String(text)
}

/// `fmt.Sprintf("%v", ..)` over a value that came out of `encoding/json`, which is the only
/// shape this is ever asked about: maps print with their keys sorted, slices with their
/// elements space-separated, and a nil as `<nil>`.
fn go_percent_v(value: &Doc) -> String {
    match value {
        Doc::String(s) => s.clone(),
        Doc::Int(i) => i.to_string(),
        Doc::Float(f) => go_percent_v_float(*f),
        Doc::Bool(b) => b.to_string(),
        Doc::Null => "<nil>".to_string(),
        Doc::Array(items) => format!(
            "[{}]",
            items.iter().map(go_percent_v).collect::<Vec<_>>().join(" ")
        ),
        Doc::Object(entries) => {
            // Go sorts the *keys*, not the rendered `key:value` pairs: `{"a":1,"a!":2}` is
            // `map[a:1 a!:2]`, and sorting the pairs would put `a!` first because `!` sorts
            // before `:`.
            let mut ordered: Vec<&(String, Doc)> = entries.iter().collect();
            ordered.sort_by(|a, b| a.0.cmp(&b.0));
            let parts: Vec<String> = ordered
                .iter()
                .map(|(key, value)| format!("{key}:{}", go_percent_v(value)))
                .collect();
            format!("map[{}]", parts.join(" "))
        }
    }
}

/// `fmt`'s `%v` for a `float64`, which is `%g` at the shortest precision.
///
/// Go and Rust agree on the *digits* -- each prints the shortest decimal that reads back
/// as the same `float64` -- and disagree on the *notation*: Rust's `Display` is always
/// positional, while Go leaves positional notation outside a window. So `1e15` arrives as
/// `1000000000000000` here and `1e+15` there, and a config that renders such a float
/// through [`go_percent_v`] writes a string the shipped binary would never produce.
///
/// The window is a property of `strconv`'s decision, not of the digit algorithm, so it is
/// pinned by measurement rather than by recall: `tests/fixtures/go_percent_v.txt` is Go's
/// own `%v` output for 228 values (every boundary this function branches on, plus a seeded
/// random spread), and `go_percent_v_matches_go_across_a_measured_table` replays it. The
/// rule that table pins is `exp < -4 || exp >= 6` on `exp = dp - 1`, where `dp` is the
/// decimal-point position of the shortest digits -- `strconv`'s `eprec = 6` for the
/// shortest form. Guessing that boundary would have been worse than leaving the gap
/// documented, because a wrong rule looks authoritative and fails quietly at the edge.
fn go_percent_v_float(value: f64) -> String {
    // Not reachable from a JSON document -- `encoding/json` has no literal for either and
    // neither does this crate's `Doc` -- but Go prints these words, so the port says the
    // same words rather than Rust's `inf`.
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-Inf"
        } else {
            "+Inf"
        }
        .to_string();
    }
    // Go keeps the sign of a negative zero, which `value == 0.0` alone would flatten.
    let sign = if value.is_sign_negative() { "-" } else { "" };
    let magnitude = value.abs();
    if magnitude == 0.0 {
        return format!("{sign}0");
    }

    // Rust's `Display` is shortest *and* positional, so the significant digits and the
    // position of the point can be read straight off it.
    let text = format!("{magnitude}");
    let (integer, fraction) = text.split_once('.').unwrap_or((text.as_str(), ""));
    let all: Vec<char> = format!("{integer}{fraction}").chars().collect();
    let point = integer.len();
    let first = all.iter().position(|c| *c != '0').unwrap_or(all.len());
    let mut digits = all[first..].to_vec();
    // `strconv` drops trailing zeros at the shortest precision, and it does not move the
    // point when it does: `100` is the digit `1` at `dp = 3`, not the digits `100` at 3.
    while digits.last() == Some(&'0') {
        digits.pop();
    }
    let dp = point as isize - first as isize;
    let exp = dp - 1;
    let digits: String = digits.iter().collect();

    let rendered = if !(-4..6).contains(&exp) {
        // Exponent form: one leading digit, a fraction only when there is one, and an
        // exponent of at least two digits -- Go's width, from `1e+06` to `1e+308`.
        let mantissa = match digits.split_at(1) {
            (head, "") => head.to_string(),
            (head, tail) => format!("{head}.{tail}"),
        };
        let (esign, emag) = if exp < 0 { ('-', -exp) } else { ('+', exp) };
        let emag = emag as usize;
        if emag < 100 {
            format!("{mantissa}e{esign}{emag:02}")
        } else {
            format!("{mantissa}e{esign}{emag}")
        }
    } else if dp <= 0 {
        format!("0.{}{digits}", "0".repeat(-dp as usize))
    } else if dp as usize >= digits.len() {
        format!("{digits}{}", "0".repeat(dp as usize - digits.len()))
    } else {
        let (head, tail) = digits.split_at(dp as usize);
        format!("{head}.{tail}")
    };
    format!("{sign}{rendered}")
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

    /// What the decode of `Channel.allow_from` holds for a file that says `value`, through the
    /// stage that actually runs it. `None` means the key is not in the loaded value at all.
    fn flexible(value: &str) -> Option<Doc> {
        let mut document = doc(&format!(
            r#"{{"version":3,"channel_list":{{"telegram":{{"allow_from":{value}}}}}}}"#
        ));
        crate::channels::init_channel_list(&mut document, &schema())
            .expect("telegram is a known channel type");
        document
            .path(&["channel_list", "telegram", "allow_from"])
            .cloned()
    }

    fn strings(items: &[&str]) -> Doc {
        Doc::Array(
            items
                .iter()
                .map(|s| Doc::String((*s).to_string()))
                .collect(),
        )
    }

    /// The two arms that make a scalar a list at all. A port that only *accepts* a scalar keeps
    /// the file's bytes and fails every corpus case that reaches the field.
    #[test]
    fn a_flexible_slice_wraps_a_bare_string_or_number() {
        assert_eq!(flexible(r#""alice""#), Some(strings(&["alice"])));
        assert_eq!(flexible("123456789"), Some(strings(&["123456789"])));
    }

    /// Elements are formatted one at a time and the arms differ: a number takes `%.0f`, which
    /// rounds half to even (1.5 and 2.5 are both `2`) and keeps the sign of a value that rounds
    /// to zero (-0.4 is `-0`), while anything else takes `%v` -- hence `true`, `<nil>`, and Go's
    /// map and slice syntax. Byte-for-byte the corpus case
    /// `a_flexible_string_slice_formats_its_elements_individually`.
    #[test]
    fn a_flexible_slice_formats_each_element_by_its_own_kind() {
        assert_eq!(
            flexible(r#"[1.5,2.5,-0.4,true,null,{"a":1},"s",["x"]]"#),
            Some(strings(&[
                "2", "2", "-0", "true", "<nil>", "map[a:1]", "s", "[x]"
            ]))
        );
    }

    /// `null` is answered before every other arm and sets the slice to nil, so it is not a
    /// one-element list -- and a nil slice under `omitempty` is not in the loaded value at all.
    /// The empty string beside it is a value and does survive as `[""]`.
    #[test]
    fn a_null_flexible_slice_is_nil_not_a_one_element_list() {
        assert_eq!(flexible("null"), None);
        assert_eq!(flexible(r#""""#), Some(strings(&[""])));
    }

    /// The second site, and the reason the settings walk cannot be the root walk. A channel's
    /// `settings` is a raw node that `InitChannelList` decodes by JSON rules, so the same type
    /// is reached at a different depth through a different schema -- the per-type one, which is
    /// the only place `channels` and `request_caps` exist.
    #[test]
    fn a_flexible_slice_inside_channel_settings_is_coerced_by_the_settings_decode() {
        let mut document = doc(
            r#"{"version":3,"channel_list":{"irc":{"settings":{"channels":"picoclaw","request_caps":9}}}}"#,
        );
        crate::channels::init_channel_list(&mut document, &schema())
            .expect("`irc` is a known channel type");
        let settings = document
            .path(&["channel_list", "irc", "settings"])
            .cloned()
            .expect("`irc` settings must survive the stage");
        assert_eq!(settings.get("channels"), Some(&strings(&["picoclaw"])));
        assert_eq!(settings.get("request_caps"), Some(&strings(&["9"])));
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

    /// The notation rule, replayed against Go's own output.
    ///
    /// `tests/fixtures/go_percent_v.txt` is `<float64 bits in hex> <go's %v>`, one value
    /// per line, produced by a throwaway Go program over the boundary set (`0`, `±0`,
    /// `±Inf`, `NaN`, every value at each side of both switch points, the subnormals,
    /// `MaxFloat64`) plus a seeded random spread so the interior is covered too. It is
    /// checked in as bytes rather than transcribed, because the whole point of the fixture
    /// is that the boundary is not something this file remembers.
    ///
    /// The digits themselves are not in question -- Rust's shortest decimal and Go's agree
    /// on every one of the 228 rows -- so a failure here is a notation failure, not a
    /// formatting-precision one.
    #[test]
    fn go_percent_v_matches_go_across_a_measured_table() {
        let table = include_str!("../tests/fixtures/go_percent_v.txt");
        let mut checked = 0;
        for line in table.lines() {
            let (bits, want) = line
                .split_once(' ')
                .unwrap_or_else(|| panic!("fixture row {line:?} is not `<bits-hex> <go's %v>`"));
            let value = f64::from_bits(
                u64::from_str_radix(bits, 16)
                    .unwrap_or_else(|e| panic!("fixture row {line:?} has no hex bits: {e}")),
            );
            let got = go_percent_v(&Doc::Float(value));
            assert_eq!(got, want, "{value:?} (bits {bits})");
            checked += 1;
        }
        // A fixture that silently stopped being read would pass every loop above by never
        // running, so the row count is asserted as well.
        assert_eq!(checked, 228, "the fixture stopped being what it is");
    }

    /// The two switch points, named rather than left to the table's statistics.
    ///
    /// `999_999` and `1_000_000` sit either side of the upper one and `1e-4`/`1e-5` either
    /// side of the lower, and each pair differs only in notation -- which is exactly the
    /// distinction `Display` cannot make. These are the four rows a fault that reverted to
    /// `format!("{f}")` has to fail; the table test alone would also fail, but on a
    /// generated value whose relevance a reader would have to take on trust.
    #[test]
    fn the_notation_switches_at_go_s_two_boundaries() {
        for (value, want) in [
            (999_999_f64, "999999"),
            (1_000_000_f64, "1e+06"),
            (1e-4, "0.0001"),
            (1e-5, "1e-05"),
            (1e15, "1e+15"),
            (1e20, "1e+20"),
            (-0.0, "-0"),
            (1.5, "1.5"),
        ] {
            assert_eq!(go_percent_v(&Doc::Float(value)), want, "{value:?}");
        }
    }
}
