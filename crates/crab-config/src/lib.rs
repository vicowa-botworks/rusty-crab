//! The config seam: `pkg/config`'s loader, its writer, and the pair of files they
//! leave behind.
//!
//! This is the second stored format the port has to stay byte-compatible with, and it
//! has the same shape as the session store: **the artifact is the directory**. One
//! `SaveConfig` writes the JSON document *and* `.security.yml` beside it; one
//! `LoadConfig` of a config below `CurrentVersion` migrates, calls `MakeBackup` and
//! rewrites the user's file in place. A port that treats load as a read misses three
//! things at once -- the backup, the upgrade on disk, and the directory listing -- and
//! a port that writes one plausible file instead of the pair leaves a machine the Go
//! build cannot read back.
//!
//! Three properties carry the whole risk here, and each has its own module:
//!
//! * **the version ladder** ([`load`]): what the loader does before it parses, and in
//!   which order. Two of its branches are bugs, and this crate reproduces both,
//!   because a Rust loader that "fixes" one would accept configs the shipped binary
//!   rejects and the two would then disagree about the same user's directory forever.
//!   See [`BUG_VERSION_PROBE_BEFORE_LENGTH`] and [`BUG_PROVIDERS_SURVIVES_MIGRATION`].
//! * **strictness** ([`schema`]): every JSON decode reflects the target type and
//!   refuses a key it cannot place, at any depth, naming the path. The security file is
//!   the opposite -- decoded by a YAML library that ignores what it does not know -- and
//!   an entry there *fills in* rather than replacing. Which fields an entry may fill is
//!   its own rule per section, and it is narrower than the entry's shape suggests:
//!   `model_list` reaches exactly one field (`api_keys`), a channel's `settings` reaches
//!   that settings struct, and a key with no yaml-tagged field to land in is dropped.
//!   See [`apply_security`]. **All of that is the current version's answer.** A document
//!   below `CurrentVersion` never reaches `loadSecurityConfig`: `LoadConfig`'s migration
//!   arms merge the two files as plain data in `loadConfigMap`, and the strict validator
//!   then runs over the merged bytes -- so the same `.security.yml` that is ignored at v3
//!   is refused at v2, by config.json's own sentence. Both sides are measured, in the
//!   `load` tests named `an_unknown_security_key_is_refused_for_a_legacy_document_only`
//!   and `a_sequence_is_refused_for_the_current_version_and_ignored_for_a_legacy_one`.
//! * **the pair** ([`yaml`]): `.security.yml` is the yaml-tagged half, which is not the
//!   two sections its struct tags suggest at a glance.
//!
//! ## What is not here
//!
//! `SecureString` is a `String`. Go's type exists so a secret does not print in a log
//! or a `Debug` dump; that is a property of Go's formatting, and the fixture cannot
//! observe it -- the corpus records the loaded config re-marshalled, where a secret is
//! just a string. Recorded in `docs/DIVERGENCES.md` rather than silently skipped.
//!
//! The default config table ([`defaults`]) is data, not behaviour: 30 built-in model
//! entries and the rest of `DefaultConfig()`. It is transcribed from the Go source, and
//! the fixture is what notices when the source moves.

mod channels;
mod defaults;
mod doc;
mod marshal;
mod schema;
mod skills;
mod yaml;

pub use defaults::{assert_table_shape, default_config, BUILTIN_MODEL_COUNT, TOP_LEVEL_KEYS};
pub use doc::{from_json, Doc, Parsed};
pub use marshal::{apply_omit, apply_session_shadow, config_file, loaded_value};
pub use schema::{config_schema, unknown_fields, validate_against, Schema};
pub use yaml::{parse as parse_security, to_name_index, write as write_security, Security};

use std::path::Path;

/// The config schema version this build writes and migrates up to.
///
/// `pkg/config.CurrentVersion`. Moving this without moving the migration ladder is the
/// mistake the fixture catches: the ladder is a chain of `if version == N` steps, so a
/// bumped constant with no new step turns every old config into an "unsupported"
/// refusal.
pub const CURRENT_VERSION: i64 = 3;

/// The file `SaveConfig` writes beside the config, holding the yaml-tagged half.
pub const SECURITY_FILE: &str = ".security.yml";

/// Go's `len(data) <= 10` shortcut: a document this small is treated as "no config
/// yet" and answered with defaults.
const TINY_DOCUMENT_MAX: usize = 10;

/// Why an empty file is an error while `{}` is defaults.
///
/// `LoadConfig` unmarshals the document into `{version}` *first*, and only then tests
/// `len(data) <= 10`. So the probe parses, and an empty file is
/// `unexpected end of JSON input` -- while two bytes later, `{}` parses fine and
/// reaches the shortcut. The order is the whole case: a port that checks the length
/// first (which reads more defensively) turns a real refusal into a silent load of
/// defaults, and the user's broken file is never reported.
pub const BUG_VERSION_PROBE_BEFORE_LENGTH: &str =
    "LoadConfig probes {version} before the len(data) <= 10 shortcut, so \"\" is a syntax \
     error and \"{}\" is defaults";

/// Why a v0 config carrying a `providers` map cannot be loaded at all.
///
/// `migrateV0ToV1` converts `providers` into a `model_list` but never deletes the
/// `providers` key; `loadConfig` then decodes the migrated map against the current
/// `Config` through the unknown-field validator, which has no `providers` field to
/// match it to. The conversion happens and the file is refused anyway, on a key the
/// migration itself left behind.
pub const BUG_PROVIDERS_SURVIVES_MIGRATION: &str =
    "migrateV0ToV1 adds model_list but leaves providers, and the post-migration decode \
     refuses the leftover key";

/// Everything a load or save can go wrong as.
///
/// The message text is deliberately not pinned by the corpus -- Go's diagnostic quotes
/// the absolute path of the file it failed on, which is the one thing that cannot be
/// the same on two machines. What the fixture grades is that the call is refused, and
/// where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The document is not valid JSON.
    Malformed(String),
    /// A key the target type cannot place. The payload is Go's dotted path list, with
    /// `[i]` for a sequence element: `channel_list.telegram.nonsense`.
    UnknownField(String),
    /// `version` above `CurrentVersion`. Go's sentence, kept verbatim because a user
    /// reads it.
    UnsupportedVersion(i64),
    /// The security file is not parseable YAML. Note what this does *not* cover: an
    /// unknown key in that file is ignored, and a type error inside a recognised
    /// section is [`Error::SecurityType`].
    UnparseableSecurity(String),
    /// A recognised security section whose shape is wrong -- `model_list` as a sequence
    /// where Go wants `map[string]*ModelConfig`.
    SecurityType(String),
    /// `version` is present but is not an integer. Go's version probe unmarshals into a
    /// typed struct, so `{"version":"3"}` is a decode error there and never reaches the
    /// migration ladder; reading it as "no version" would run the ladder over a document
    /// the shipped binary refuses.
    VersionType(String),
    /// A behaviour this crate does not implement yet, reached by real input.
    ///
    /// It exists so "not ported" is an answer rather than a guess: the alternative is
    /// that an unported position emits something plausible, and a plausible wrong file
    /// is the failure mode this whole seam is arranged to prevent.
    NotPorted(String),
    /// A channel the registry does not know, or settings its typed struct cannot hold.
    /// `InitChannelList`'s two refusals, with Go's sentence.
    Channel(String),
    Io(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "{m}"),
            Self::UnknownField(paths) => {
                write!(f, "config.json contains unknown field(s): {paths}")
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported config version: {v}"),
            Self::UnparseableSecurity(m) | Self::SecurityType(m) => {
                write!(f, "failed to parse security config: {m}")
            }
            Self::VersionType(m) => write!(f, "{m}"),
            Self::NotPorted(m) => write!(f, "not ported: {m}"),
            Self::Channel(m) => write!(f, "{m}"),
            Self::Io(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

/// A loaded config: the document, plus the one thing the loader decides that is not in
/// the file.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// The document, in Go's declaration order.
    pub document: Doc,
    /// Whether the document's `version` is below `CurrentVersion`, which is what
    /// decides whether a save raises it. Go's `SaveConfig` mutates the struct it is
    /// handed, so the loaded value and the saved file disagree on purpose.
    pub needs_version_bump: bool,
}

impl Config {
    /// The document's `version`, as the loader reads it (absent is 0).
    #[must_use]
    pub fn version(&self) -> i64 {
        self.document
            .get("version")
            .and_then(Doc::as_i64)
            .unwrap_or(0)
    }
}

/// Reads a config the way `pkg/config.LoadConfig` does.
///
/// ## What this loader does not do yet
///
/// The Go loader is a long pipeline and this crate implements the front of it. Four
/// stages are deliberately absent, and a caller must know that rather than assume the
/// load is complete:
///
/// * `env.Parse` and the `PICOCLAW_*` compat shims. The corpus runs with that
///   environment cleared, so they are inert for every recorded case -- but a real
///   process is not, and this loader would silently differ from Go there.
/// * `InitChannelList`: inferring `type` from the map key, refusing an unregistered
///   type, the singleton constraints, and -- the part the corpus actually sees -- decoding
///   each channel's `settings` into the typed struct for that type, so the loaded value
///   carries every field of e.g. `TelegramSettings` rather than the keys the file happened
///   to mention. That is why four of the fifteen replayable config cases are listed in
///   `tests/conformance.rs` as known gaps; the per-type field lists are already in the
///   schema dump as `settings_schemas`.
/// * `expandMultiKeyModels`: a model with two `api_keys` becomes two entries, the
///   second named `name__key_1`, and the copy carries only the fields the Go function
///   lists -- `enabled` among those it drops.
/// * `ValidateModelList` and `ValidateTurnProfile`.
///
/// The security file *is* read, because leaving it out would load a config whose secrets
/// are in the wrong place. `channels`/`channel_list` and `model_list` are merged, and
/// `skills` runs in the two halves Go runs it in: [`skills::normalise_document`] with the
/// document alone, then [`skills::apply`] for the file's two merge passes -- the legacy lift
/// and the registry passes, which is what the `tools.skills` half of the loaded value is
/// pinned against. The split is not cosmetic: the first half happens during Go's JSON
/// unmarshal, so it runs when there is no `.security.yml` at all.
///
/// One section Go applies is still dropped: `web`, which reaches `tools.web` through
/// `Tools`' `yaml:",inline"`. That is a divergence and is recorded in `docs/DIVERGENCES.md`
/// with its real mechanism: the inline branch runs, and `merge_filling` refuses the key
/// because it asks the root schema what is a field. Refusing both sections instead was the
/// earlier behaviour and it was worse: every `.security.yml` the shipped binary has ever
/// written carries them, so refusing made the loader reject the normal case. A key the
/// struct does not name at all is ignored, because `loadSecurityConfig` calls plain
/// `yaml.Unmarshal` and not `UnmarshalStrict`.
///
/// A missing file is not an error: Go logs and returns defaults. That is why the return
/// type is not `Option` -- the caller always gets a config, and the only ways to get an
/// `Err` are a document that cannot be parsed, a key that cannot be placed, or a
/// version this build does not know.
///
/// `home` is what `$HOME` expands to. It is a parameter rather than an `env::var` call
/// because the generator pins it (`/home/oracle`) and the fixture pins the expansion
/// byte for byte; reading the real environment here would make the replay depend on the
/// machine running it, which is the failure `pinConfigEnv` exists to prevent on the Go
/// side.
pub fn load(path: &Path, home: &str) -> Result<Config, Error> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        // os.IsNotExist is not an error: Go warns and hands back DefaultConfig().
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Config {
                document: default_config(home),
                needs_version_bump: false,
            })
        }
        Err(e) => return Err(Error::Io(e.to_string())),
    };
    let text = String::from_utf8_lossy(&data).into_owned();

    // The probe. It parses, which is why an empty file is refused here and never
    // reaches the length shortcut below -- see BUG_VERSION_PROBE_BEFORE_LENGTH.
    let parsed = from_json(&text);
    if let Some(diagnostic) = parsed.error {
        return Err(Error::Malformed(diagnostic));
    }
    let document = parsed.doc;
    // The probe decodes into a typed struct, so a version that is not an integer is a
    // decode failure, not a missing version. `unwrap_or(0)` here would silently file
    // `{"version":"3"}` as a v0 document and run the whole migration ladder over it.
    let version = match document.get("version") {
        None | Some(Doc::Null) => 0,
        Some(Doc::Int(v)) => *v,
        Some(other) => return Err(Error::VersionType(version_type_diagnostic(&text, other))),
    };

    if text.len() <= TINY_DOCUMENT_MAX {
        return Ok(Config {
            document: default_config(home),
            needs_version_bump: false,
        });
    }

    let document = match version {
        0..=2 => migrate(document, version),
        CURRENT_VERSION => document,
        other => return Err(Error::UnsupportedVersion(other)),
    };
    let migrated = version < CURRENT_VERSION;

    // The security file, read before anything is validated. Absent is normal -- a config
    // written before the split has none -- but any *other* read failure is fatal.
    // `if let Ok(..)` here would treat EACCES or invalid UTF-8 as "no secrets file" and
    // carry on with default secrets, which is the one place a silent fallback points the
    // wrong way: it does not load a slightly staler config, it loads one that believes
    // nothing is configured and then writes that belief back on the next save.
    let security_path = path.with_file_name(SECURITY_FILE);
    let security = match std::fs::read_to_string(&security_path) {
        Ok(text) => Some(yaml::parse(&text)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(Error::Io(format!("failed to read security config: {e}"))),
    };

    // The decode. Go decodes into a fresh DefaultConfig() and the unknown-field validator
    // runs over the same bytes first, so strictness and defaults-filling are two passes
    // over the document, not one. Which bytes those are depends on the version: a
    // current-version document is validated as config.json alone, because its security file
    // is decoded separately by `yaml.v3`; a legacy one has already been merged with the
    // security file as plain data by `loadConfigMap`, re-marshalled, and validated as one
    // document -- so a key only the security file introduced is refused there, with
    // config.json's own sentence.
    let mut issues = unknown_fields(&document, &config_schema());
    if migrated {
        if let Some(security) = &security {
            issues.extend(unknown_fields(&migration_view(security), &config_schema()));
            issues.sort();
        }
    }
    if !issues.is_empty() {
        return Err(Error::UnknownField(issues.join(", ")));
    }
    let mut merged = default_config(home);
    // The baseline `tools.skills.registries` before the document is merged over it. Go decodes
    // the file *into* the defaults, so a document whose `registries` is not a mapping leaves
    // the builtins standing, and after `merge_over` the answer is no longer in the document.
    let baseline_registries = merged.path(&["tools", "skills", "registries"]).cloned();
    merge_over(&mut merged, &document, &config_schema());

    // `SkillsRegistriesConfig`'s decoder, which Go runs as part of the JSON unmarshal -- that
    // is, before the security file is opened. It is the document-side half of the skills pass
    // and it does not ask whether a `.security.yml` exists; the two merge passes below do.
    skills::normalise_document(&mut merged, baseline_registries.as_ref());

    if let Some(security) = &security {
        // Not wrapped. `Error::SecurityType` and `Error::UnparseableSecurity` are the two
        // kinds this stage can raise and both name themselves; folding them into `Error::Io`
        // would report a type error as a read failure.
        apply_security(
            &mut merged,
            security,
            migrated,
            baseline_registries.as_ref(),
        )?;
    }

    // `InitChannelList`, which sits here in Go too -- after the security merge, before
    // the session scope. It is the stage that makes a loaded config more than the file:
    // every channel's `settings` is replaced by what its typed struct marshals, so the
    // fields the file left out appear and the keys come back in declaration order.
    channels::init_channel_list(&mut merged, &config_schema())?;

    // The last two stages of LoadConfig, and the reason a loaded config can carry a
    // dm_scope the file never mentioned.
    apply_dm_scope(&mut merged);

    Ok(Config {
        document: merged,
        needs_version_bump: version < CURRENT_VERSION,
    })
}

/// The security file as the migration path sees it: data to be merged into config.json,
/// after the two rewrites `loadConfigMap` performs on the way.
///
/// `model_list` is gone because that merge already consumed it, by name, and leaving a map
/// under the key the schema says is an array would report an error Go does not. `web` and
/// `skills` move under `tools` because `Config.Tools` is `yaml:",inline"`, so those two
/// sections *are* tools fields to the decoder -- and the lift **replaces** any `tools`
/// section the file itself carried, which is why a security file with both a `tools:` and a
/// `web:` section has its `tools:` thrown away.
fn migration_view(security: &yaml::Security) -> Doc {
    let present = |name: &str| {
        security
            .document
            .get(name)
            .is_some_and(|v| !matches!(v, Doc::Null))
    };
    let mut entries: Vec<(String, Doc)> =
        security.document.as_object().cloned().unwrap_or_default();
    entries.retain(|(name, _)| name != "model_list");
    if present("web") || present("skills") {
        entries.retain(|(name, _)| name != "web" && name != "skills" && name != "tools");
        let mut lifted: Vec<(String, Doc)> = Vec::new();
        for name in ["web", "skills"] {
            if present(name) {
                if let Some(value) = security.document.get(name) {
                    let value = if name == "skills" {
                        rewrite_skills(value.clone())
                    } else {
                        value.clone()
                    };
                    lifted.push((name.to_string(), value));
                }
            }
        }
        entries.push(("tools".to_string(), Doc::Object(lifted)));
    }
    Doc::Object(entries)
}

/// The two registry spellings `migration.go:437-454` performs on the lifted `skills` node.
///
/// Both exist because the registry *map* is newer than the file format being migrated: an old
/// security file spells a registry at the top of `skills`, and the migration rewrites it into
/// `skills.registries` before anything looks at the result. Skipping the rewrite stopped being
/// cosmetic the moment this view became a validator input: `skills` is a **struct** node, so a
/// key that is not one of its fields is refused with config.json's own sentence --
/// `config.json contains unknown field(s): tools.skills.clawhub` -- on exactly the installs the
/// migration exists to serve. Go never refuses them, at either version.
///
/// The two halves are not symmetric, and the asymmetry is the behaviour:
///
/// * `clawhub` **replaces** `registries` wholesale (`m["registries"] = map[string]any{"clawhub":
///   m["clawhub"]}`), so a `registries` the file already carried is discarded when `clawhub` is
///   present. A `clawhub` that is present but null is left where it is -- the `delete` is inside
///   the `!= nil` guard.
/// * `github` is **copied, not moved**: `skills.github` stays and `registries.github` is a copy
///   with `auth_token` set from `token` when `token` is there (and `token` itself stays in the
///   copy). That is the second half of why a legacy `skills.github.token` reaches the registry
///   twice on the save side.
/// * a `registries` that is not a mapping is replaced rather than merged into, because Go's type
///   assertion yields nil and the code then builds a fresh map.
///
/// What the rewrite does *not* do is make the node permissive: `skills` stays a struct node, so
/// a key that is neither a field nor one of these two spellings is still refused.
fn rewrite_skills(skills: Doc) -> Doc {
    let Doc::Object(mut entries) = skills else {
        return skills;
    };

    if let Some(pos) = entries.iter().position(|(k, _)| k == "clawhub") {
        if !matches!(entries[pos].1, Doc::Null) {
            let value = entries.remove(pos).1;
            entries.retain(|(k, _)| k != "registries");
            entries.push((
                "registries".to_string(),
                Doc::Object(vec![("clawhub".to_string(), value)]),
            ));
        }
    }

    let github = entries
        .iter()
        .find(|(k, _)| k == "github")
        .map(|(_, value)| value.clone());
    if let Some(Doc::Object(mut github_registry)) = github {
        let token = github_registry
            .iter()
            .find(|(k, _)| k == "token")
            .map(|(_, value)| value.clone());
        if let Some(token) = token {
            match github_registry.iter_mut().find(|(k, _)| k == "auth_token") {
                Some(slot) => slot.1 = token,
                None => github_registry.push(("auth_token".to_string(), token)),
            }
        }
        let mut registries: Vec<(String, Doc)> = entries
            .iter()
            .find(|(k, _)| k == "registries")
            .and_then(|(_, value)| value.as_object().cloned())
            .unwrap_or_default();
        match registries.iter_mut().find(|(k, _)| k == "github") {
            Some(slot) => slot.1 = Doc::Object(github_registry),
            None => registries.push(("github".to_string(), Doc::Object(github_registry))),
        }
        entries.retain(|(k, _)| k != "registries");
        entries.push(("registries".to_string(), Doc::Object(registries)));
    }

    Doc::Object(entries)
}

/// `SessionConfig.ApplyDmScope` then `DeriveDmScope` (config.go:360 and :380).
///
/// They are a pair, and the order is the point: `dm_scope` expands into `dimensions`,
/// and only if `dm_scope` was empty does `dimensions` collapse back into `dm_scope`. So
/// a file saying `dimensions: [chat]` comes back with `dm_scope: per-channel` added, and
/// a file saying `dm_scope: per-channel` keeps exactly what it said. Neither direction is
/// derivable from the other, and a port that implements only one of the two produces a
/// loaded value that differs from Go's on exactly the cases the other one covers.
fn apply_dm_scope(document: &mut Doc) {
    let Some(session) = document.get_mut_at("session") else {
        return;
    };
    let scope = session
        .get("dm_scope")
        .and_then(Doc::as_str)
        .unwrap_or_default()
        .to_string();
    let dimensions: Vec<String> = session
        .get("dimensions")
        .and_then(Doc::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    if scope.is_empty() && dimensions.is_empty() {
        return;
    }
    if scope.is_empty() {
        // DeriveDmScope: only the three known shapes, in this order. A custom array is
        // left alone -- Go's comment says the UI handles it.
        let derived = match dimensions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["chat", "sender"] => Some("per-channel-peer"),
            ["chat"] => Some("per-channel"),
            ["sender"] => Some("per-peer"),
            _ => None,
        };
        if let Some(d) = derived {
            session.set("dm_scope", Doc::String(d.to_string()));
        }
        return;
    }
    if !dimensions.is_empty() {
        // ApplyDmScope returns early when dimensions is already set.
        return;
    }
    let expanded = match scope.as_str() {
        "per-channel-peer" => Some(vec!["chat", "sender"]),
        "per-channel" => Some(vec!["chat"]),
        "per-peer" => Some(vec!["sender"]),
        // "global" clears dimensions; anything else changes nothing.
        "global" => Some(vec![]),
        _ => None,
    };
    if let Some(items) = expanded {
        session.set(
            "dimensions",
            Doc::Array(
                items
                    .into_iter()
                    .map(|s| Doc::String(s.to_string()))
                    .collect(),
            ),
        );
    }
}

/// The word Go's type-error sentence uses for a JSON value.
/// Go's `wrapJSONError` summary for the version probe (`diagnostics.go:81`, reached from
/// `config.go:1311`). The probe decodes into `struct { Version int }`, so a version that
/// is not an integer is an `UnmarshalTypeError` naming the field, and the wrapper restates
/// it with the position of the value's last byte -- which is where serde puts it too, so
/// the two agree on line and column for every shape measured against Go.
///
/// Go appends a preview block after this line (`   1 | {"version":"3"}` and a caret). It
/// is deliberately not reproduced: it is coloured by `diagnosticsUseColor()`, and the
/// corpus records no error text at all -- a failing case adds `error_op_index` and nothing
/// else -- so this sentence exists for a human reading a failed start, not for a pin.
fn version_type_diagnostic(text: &str, value: &Doc) -> String {
    #[derive(serde::Deserialize)]
    struct Probe {
        #[serde(default)]
        #[allow(dead_code)]
        version: i64,
    }
    let (line, column) = serde_json::from_str::<Probe>(text)
        .err()
        .map(|e| (e.line(), e.column()))
        .unwrap_or((1, 1));
    // A container needs one added. Go's decoder refuses a `version` the moment it reads the
    // value's **opening** byte -- it never descends into the array -- so its column is that
    // byte, and it does not move with the value's length: `{"version":[]}` and
    // `{"version":[[1],{"a":"}"}]}` both read 12. serde reports the byte *before* it, the
    // colon, so the two disagree by exactly one for `[...]` and `{...}` and agree for every
    // scalar, where both land on the literal's last byte. Measured against `LoadConfig` at
    // picoclaw `1a4e1edf` for all four container shapes.
    let column = match value {
        Doc::Array(_) | Doc::Object(_) => column + 1,
        _ => column,
    };
    // Go's `UnmarshalTypeError.Value`: the type name for a string or bool, and the literal
    // text for a number, so `3.5` reads back as `number 3.5` and `1e10` as `number 1e10`.
    let got = match value {
        Doc::Float(_) | Doc::Int(_) => format!("number {}", number_literal(text, line, column)),
        Doc::String(_) => "string".to_string(),
        Doc::Bool(_) => "bool".to_string(),
        Doc::Object(_) => "object".to_string(),
        Doc::Array(_) => "array".to_string(),
        Doc::Null => "null".to_string(),
    };
    format!(
        "config.json type error at line {line}, column {column} for field \"version\": \
         expected int but got {got}"
    )
}

/// The number as the file spells it. A parsed float cannot give `1e10` back, so the
/// literal is taken from the source: the run of number characters ending at the column
/// the decoder stopped on.
fn number_literal(text: &str, line: usize, column: usize) -> String {
    let Some(line_text) = text.lines().nth(line.saturating_sub(1)) else {
        return String::from("0");
    };
    let end = column.min(line_text.chars().count());
    let taken: Vec<char> = line_text.chars().take(end).collect();
    let start = taken
        .iter()
        .rposition(|c| !matches!(c, '0'..='9' | '.' | 'e' | 'E' | '+' | '-'))
        .map_or(0, |i| i + 1);
    taken[start..].iter().collect()
}

/// Fills the security file's sections into a document the JSON loader already settled.
///
/// `migrated` is the version's answer to a question the file cannot ask. A current-version
/// document gets `loadSecurityConfig`, the typed merge described below. A legacy one never
/// does: `LoadConfig`'s migration arms merge the two files as **plain data** in
/// `loadConfigMap`, migrate the result, and hand the re-marshalled bytes to the ordinary
/// decoder -- so for a migrated document only the `model_list` merge below runs (Go's
/// `mergeModelListsWithMap`, whose matching is *not* the same rule -- see the branch in
/// [`apply_security`]) and the rest of
/// this function's work would be inventing a merge that happens somewhere else, differently
/// and earlier. What the data merge does instead is recorded in `docs/DIVERGENCES.md`.
///
/// `loadSecurityConfig` runs `yaml.Unmarshal(data, cfg)` over the whole file, so what
/// applies is decided by the *yaml* tags, not the json ones -- a different set, and the
/// reason this walks [`Schema::yaml_fields`] rather than the document's keys:
///
/// * `channel_list` and `model_list` are the two sections with a projection of their own.
/// * `tools` is `yaml:",inline"`, so the file's `web` and `skills` land inside `tools`.
///   They are not optional extras: every `.security.yml` the shipped binary has written
///   contains both, so a loader that only knew the first two refused every real file.
/// * Anything else in the file has no yaml-tagged field to land in and is dropped. That
///   is Go's behaviour, not a gap: the yaml half has no unknown-field validator, which is
///   the asymmetry [`yaml`] documents -- for a *current-version* document, since a migrated
///   one has its security file validated as config.json bytes. See [`migration_view`].
///
/// Per field, not per entry: the file decodes into a `Config` the JSON pass has already
/// populated, so an entry touches the fields it names and leaves the rest alone. Which
/// fields a section may name is decided by that section's own projection, not by the
/// entry's shape -- `model_list` gets `api_keys` and nothing else, and an entry naming a
/// model the document does not hold is ignored.
fn apply_security(
    merged: &mut Doc,
    security: &yaml::Security,
    migrated: bool,
    baseline_registries: Option<&Doc>,
) -> Result<(), Error> {
    let schema = schema::config_schema();

    // A `model_list` that is not a mapping: the JSON shape copied into a YAML file, or gone
    // entirely. Fatal here, ignored for a migrated document, where `loadConfigMap` merges
    // the section only if it is a map and deletes it either way. Measured on both sides of
    // the same file: v3 refuses with the decoder's sentence, v2 loads the default list.
    // `filter` rather than a nested `if`: the edition here has no let chains, and a nested
    // one is what `collapsible_if` asks to collapse into a let chain.
    if let Some(kind) = security.model_list_kind.filter(|_| !migrated) {
        return Err(Error::SecurityType(format!(
            "cannot unmarshal !!{kind} into map[string]*config.ModelConfig"
        )));
    }

    // A `model_list` that is a mapping. A section that is not one was refused above, or
    // parsed as an empty map for `model_list:` with no value; the migrated path ignores one.
    if let Some(Doc::Object(entries)) = security.model_list() {
        if let Some(list) = merged.get_mut_at("model_list").and_then(Doc::as_array_mut) {
            // The file keys entries `name:index`; the document holds a sequence.
            //
            // **Two loaders, two shapes.** The current version runs
            // `SecureModelList.UnmarshalYAML` (config_struct.go:326), which walks the models
            // the JSON loader produced and asks the security map for each one's `name:index`
            // key, falling back to the bare name per position. A migrated document runs
            // `mergeModelListsWithMap` (migration.go:497) instead, which builds a key set --
            // `name:index` for every position, and the bare name **only for the first
            // position carrying it** -- and iterates the security map. The two agree on every
            // shape except one, and it is measurable rather than theoretical: two models both
            // named `m1` with the file keyed `m1:` give v3 `["[NOT_HERE]", "[NOT_HERE]"]` and
            // a migrated config `["[NOT_HERE]", "<nil>"]` -- the bare name resolves to the
            // first position only. Measured at picoclaw `1a4e1edf`, one process per scenario,
            // with `model` present on every entry so the required-field stage is not what is
            // answering. So the loop below is chosen by `migrated`, and the three rules that
            // both loaders share are stated once, after the branch.
            //
            // * **An entry naming no model is ignored, not appended.** Both loaders agree. The loop runs over the
            //   models, not over the map, so a leftover `m9:0` against a config that lists
            //   only `m1` contributes nothing. Appending it instead invents a model with an
            //   empty name: the next `save` writes it into `config.json`, names it `:0` in
            //   the security file, and the round trip cannot even reproduce the entry it
            //   wrote. `mergeModelListsWithMap` drops it the same way on the migration path,
            //   and deletes it from the map first so the generic data merge cannot turn it
            //   into a top-level key.
            // * **Only `api_keys` is taken.** `m.APIKeys = sec.APIKeys` is a field
            //   assignment, so `m1:0: {provider: other}` leaves the provider alone -- merging
            //   the whole entry would let the secrets file set a model's provider or rpm.
            // * **The assignment is unconditional when the entry matches**, so a matching
            //   entry with no `api_keys` clears the model's keys rather than leaving them
            //   alone.
            if migrated {
                let mut positions: Vec<(String, usize)> = Vec::new();
                let mut counts: Vec<(String, usize)> = Vec::new();
                for (position, item) in list.iter().enumerate() {
                    let name = item
                        .get("model_name")
                        .and_then(Doc::as_str)
                        .unwrap_or_default();
                    let index = match counts.iter_mut().find(|(n, _)| n == name) {
                        Some(slot) => {
                            slot.1 += 1;
                            slot.1 - 1
                        }
                        None => {
                            counts.push((name.to_string(), 1));
                            0
                        }
                    };
                    positions.push((format!("{name}:{index}"), position));
                    if !positions.iter().any(|(key, _)| key == name) {
                        positions.push((name.to_string(), position));
                    }
                }
                for (spelled, entry) in entries {
                    let Some(position) = positions
                        .iter()
                        .find(|(key, _)| key == spelled)
                        .map(|(_, position)| *position)
                    else {
                        // Go logs `model_name not found in main config: <key>` and moves on.
                        continue;
                    };
                    // Only a mapping entry assigns anything: `if vv, ok := v.(map[string]any)`.
                    let Doc::Object(fields) = entry else { continue };
                    match fields.iter().find(|(key, _)| key == "api_keys") {
                        Some((_, value)) => list[position].set("api_keys", value.clone()),
                        // `mVal["api_keys"] = vv["api_keys"]` assigns nil for a missing key.
                        None => {
                            list[position].remove("api_keys");
                        }
                    }
                }
                return Ok(());
            }

            let keys = yaml::to_name_index(list);
            for (position, key) in keys.iter().enumerate() {
                let name = list[position]
                    .get("model_name")
                    .and_then(Doc::as_str)
                    .unwrap_or_default();
                let entry = entries
                    .iter()
                    .find(|(spelled, _)| spelled == key)
                    .or_else(|| entries.iter().find(|(spelled, _)| spelled == name))
                    .map(|(_, value)| value);
                match entry.and_then(|value| value.get("api_keys")) {
                    Some(found) => list[position].set("api_keys", found.clone()),
                    // Go assigns a nil slice, which marshals to nothing. Removing the key is
                    // that; an empty array would be a different value that happens to print
                    // the same.
                    None if entry.is_some() => {
                        list[position].remove("api_keys");
                    }
                    None => {}
                }
            }
        }
    }

    if migrated {
        return Ok(());
    }

    for field in schema.yaml_fields() {
        if field.json == "model_list" {
            continue;
        }
        if field.inline {
            // `tools`: the file's children are top level, the document's are nested.
            let Some(inner_schema) = schema.field(field.json) else {
                continue;
            };
            let Some(target) = merged.get_mut_at(field.json) else {
                continue;
            };
            for child in inner_schema.yaml_fields() {
                if child.json == "skills" {
                    // Two passes of its own, neither of them a merge: see [`skills`].
                    continue;
                }
                if let Some(value) = security.document.get(child.json) {
                    if let Some(slot) = target.get_mut_at(child.json) {
                        merge_filling(slot, value);
                    }
                }
            }
            continue;
        }
        let Some(value) = security.document.get(field.json) else {
            continue;
        };
        // The channel section merges per entry rather than wholesale, and it answers to
        // either spelling in the file while the document has only one.
        if field.json == "channel_list" {
            let source = security
                .document
                .get("channel_list")
                .or_else(|| security.document.get("channels"));
            if let (Some(source), Some(target)) = (source, merged.get_mut_at("channel_list")) {
                merge_filling(target, source);
            }
            continue;
        }
        if let Some(target) = merged.get_mut_at(field.json) {
            merge_filling(target, value);
        }
    }

    skills::apply(merged, security, baseline_registries);

    Ok(())
}

/// Like [`merge_over`], but a key the schema does not know is dropped instead of added.
///
/// That is the whole difference between the two passes: the JSON document is validated
/// before it is merged, so an unknown key there is a refusal; the security file is not
/// validated, so an unknown key there is nothing at all.
fn merge_filling(base: &mut Doc, overlay: &Doc) {
    let (Some(base_entries), Some(overlay_entries)) = (base.as_object_mut(), overlay.as_object())
    else {
        // Not an object on both sides, so there is nothing to fill: the security value
        // is the whole new value for this position, exactly as Go's yaml decode assigns
        // the decoded node rather than merging into what was there.
        *base = overlay.clone();
        return;
    };
    let schema = schema::config_schema();
    let overlay_entries = overlay_entries.clone();
    for (k, v) in &overlay_entries {
        if schema.field(k).is_none() && !matches!(k.as_str(), "settings" | "api_keys") {
            // Not a field of the target type. Go's yaml decode has no place for it and
            // moves on; the JSON path would have refused the same key.
            continue;
        }
        match base_entries.iter_mut().find(|(bk, _)| bk == k) {
            Some(slot) => merge_filling(&mut slot.1, v),
            None => base_entries.push((k.clone(), v.clone())),
        }
    }
}

/// Writes a config the way `pkg/config.SaveConfig` does: both halves, security first.
///
/// Four things in the Go function are behaviour rather than plumbing:
///
/// * **The version is bumped in the value before either file is written**, so saving a
///   migrated config upgrades it in place. `needs_version_bump` is what told the caller
///   this was going to happen.
/// * **`.security.yml` is written first.** If it fails, `config.json` still holds the
///   previous content and the pair is inconsistent in the recoverable direction. Writing
///   the JSON first fails the other way: a new config pointing at secrets that were never
///   stored.
/// * **Both files are 0600 and written atomically** (`fileutil.WriteFileAtomic`: temp in
///   the same directory, then rename). A secrets file that is briefly world-readable, or
///   briefly truncated to zero bytes, is a secrets file that has leaked or been destroyed.
/// * **Virtual models are filtered out** of the written list. That flag is unexported and
///   never appears in the JSON, so a document this crate loaded cannot carry it -- see the
///   note on [`Config`].
///
/// Returns the bytes of each file written, in the order written, which is what
/// [`save_is_stable`] consumes.
pub fn save(path: &Path, cfg: &mut Config, _home: &str) -> Result<Vec<String>, Error> {
    if cfg
        .document
        .get("version")
        .and_then(Doc::as_i64)
        .unwrap_or(0)
        < CURRENT_VERSION
    {
        cfg.document.set("version", Doc::Int(CURRENT_VERSION));
    }

    let schema = schema::config_schema();
    let security_path = path.with_file_name(SECURITY_FILE);
    let security = yaml::write(&cfg.document, &schema)?;
    write_atomic(&security_path, &security)?;

    let document = marshal::config_file(&cfg.document, &schema)?;
    write_atomic(path, &document)?;

    Ok(vec![security, document])
}

/// `fileutil.WriteFileAtomic`: write beside the target, then rename over it.
///
/// The mode is set on the temp file *before* the rename, so there is no window in which
/// the new content exists under a permissive mode -- and no window in which the target
/// exists but is short.
fn write_atomic(path: &Path, contents: &str) -> Result<(), Error> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| std::path::PathBuf::from("."), std::path::PathBuf::from);
    let tmp = parent.join(format!(
        ".{}.tmp{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config"),
        std::process::id()
    ));
    std::fs::write(&tmp, contents).map_err(|e| Error::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Io(e.to_string()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| Error::Io(e.to_string()))?;
    Ok(())
}

/// Whether two saves of the same file produced identical bytes.
///
/// Mirrors the generator's `saveIsStable`: vacuously true when nothing was saved twice,
/// and the caller must read `asked` before believing `stable`.
#[must_use]
pub fn save_is_stable(writes: &[String]) -> (bool, bool) {
    if writes.len() < 2 {
        return (true, false);
    }
    for w in &writes[1..] {
        if w != &writes[0] {
            return (false, true);
        }
    }
    (true, true)
}

/// Runs the migration ladder for a document below `CurrentVersion`.
///
/// The steps are `if version == N`, not a loop over a list, and the order is the
/// source's: a v0 file runs all three, a v2 file only the last. A ladder that ran every
/// step regardless of the file's version would rename `channels` twice and be harmless,
/// but would also apply v0's `api_key` rewrite to a v3 document that legitimately
/// carries the old spelling inside a nested `settings` map.
fn migrate(mut document: Doc, version: i64) -> Doc {
    if version == 0 {
        migrate_v0_to_v1(&mut document);
    }
    if version <= 1 {
        migrate_v1_to_v2(&mut document);
    }
    if version <= 2 {
        migrate_v2_to_v3(&mut document);
    }
    document
}

/// v0 to v1 (`migration.go:176`).
///
/// The `providers` branch is *not* here, and that is the bug: the Go step converts
/// `providers` into a `model_list` and leaves the original key in place, so the decode
/// that follows refuses the file. Reproducing the bug means not doing the tidy thing
/// here -- see [`BUG_PROVIDERS_SURVIVES_MIGRATION`]. Skipping the conversion cannot make
/// the outcome differ, because the refusal is on the surviving `providers` key either way.
fn migrate_v0_to_v1(document: &mut Doc) {
    migrate_legacy_agent_defaults_model(document);
    unique_api_keys(document);
    document.set("version", Doc::Int(1));
}

/// v1 to v2 (`migration.go:266`).
///
/// * A channel's `mention_only` moves to `group_trigger.mention_only` **and the old key
///   is deleted**. Leaving it behind is not harmless: `mention_only` is not a field of
///   `Channel`, so the validator refuses the migrated document that Go accepts.
/// * `api_key` folds into `api_keys`, and only when the result is non-empty -- Go writes
///   inside `if len(ss) > 0`, so an entry with neither key keeps neither key.
/// * `enabled` is inferred, and only ever *to* `true`: an entry that already says so is
///   skipped, one with keys becomes enabled, and the reserved `local-model` entry is
///   enabled. Nothing sets it to `false`, so a migration never disables a model.
///
/// `channels` is a **map** keyed by channel name at every version below 3. Reading it as
/// the sequence that v3 introduces is the shape error that makes this step look like a
/// no-op on real files.
fn migrate_v1_to_v2(document: &mut Doc) {
    if let Some(channels) = document.get_mut_at("channels").and_then(Doc::as_object_mut) {
        for (_, channel) in channels.iter_mut() {
            let Some(entries) = channel.as_object_mut() else {
                continue;
            };
            let position = entries.iter().position(|(k, _)| k == "mention_only");
            let Some(position) = position else { continue };
            let mention_only = entries.remove(position).1;
            let mut trigger = entries
                .iter()
                .find(|(k, _)| k == "group_trigger")
                .map(|(_, v)| v.clone())
                .unwrap_or(Doc::Object(Vec::new()));
            match &mut trigger {
                Doc::Object(items) => upsert(items, "mention_only", mention_only),
                other => *other = Doc::Object(vec![("mention_only".into(), mention_only)]),
            }
            upsert(entries, "group_trigger", trigger);
        }
    }

    unique_api_keys(document);

    let Some(list) = document
        .get_mut_at("model_list")
        .and_then(Doc::as_array_mut)
    else {
        document.set("version", Doc::Int(2));
        return;
    };
    for entry in list.iter_mut() {
        if !entry.is_object() {
            continue;
        }
        if entry.get("enabled").is_some() {
            continue;
        }
        let has_keys = entry
            .get("api_keys")
            .and_then(Doc::as_array)
            .is_some_and(|items| !items.is_empty());
        if has_keys {
            entry.set("enabled", Doc::Bool(true));
            continue;
        }
        if entry.get("model_name").and_then(Doc::as_str) == Some("local-model") {
            entry.set("enabled", Doc::Bool(true));
        }
    }
    document.set("version", Doc::Int(2));
}

/// v2 to v3 (`migration.go:343`).
///
/// `channels` does not simply rename. Each entry gains `type` from its map key, and every
/// key that is not one of `BaseFieldNames` is **moved** into a `settings` object -- which
/// is the whole reason the two migrated fixture cases used to fail here: leaving
/// `bot_token` and `allowed_user_ids` at the channel level makes the validator refuse a
/// document the shipped binary loads. The list of keys that stay is read from the dump
/// (`Schema::base_fields`), extracted from the same Go map this migration consults, so it
/// cannot drift from it.
///
/// `bindings` is deleted outright: it has no field to land in any more, and leaving it
/// would make the validator refuse the migrated document.
fn migrate_v2_to_v3(document: &mut Doc) {
    migrate_legacy_agent_defaults_model(document);
    document.remove("bindings");

    let Some(channels) = document.remove("channels") else {
        document.set("version", Doc::Int(CURRENT_VERSION));
        return;
    };
    let base: Vec<&str> = schema::config_schema()
        .field("channel_list")
        .and_then(Schema::elem)
        .map(|elem| elem.base_fields().to_vec())
        .unwrap_or_default();
    let mut out: Vec<(String, Doc)> = Vec::new();
    for (name, channel) in channels.as_object().cloned().unwrap_or_default() {
        let mut channel = channel;
        let entries = match channel.as_object_mut() {
            Some(entries) => entries,
            // A non-object entry is left exactly as it is, as Go's type assertion does.
            None => {
                out.push((name, channel));
                continue;
            }
        };
        upsert(entries, "type", Doc::String(name.clone()));
        if entries.iter().any(|(k, _)| k == "settings") {
            out.push((name, channel));
            continue;
        }
        // Onebot's flat prefix list becomes group_trigger.prefixes, and does not overwrite
        // prefixes the entry already declares.
        if let Some(position) = entries
            .iter()
            .position(|(k, _)| k == "group_trigger_prefix")
        {
            let prefixes = entries.remove(position).1;
            let mut trigger = entries
                .iter()
                .find(|(k, _)| k == "group_trigger")
                .map(|(_, v)| v.clone())
                .unwrap_or(Doc::Object(Vec::new()));
            let insert = match &mut trigger {
                Doc::Object(items) => {
                    let missing = !items.iter().any(|(k, _)| k == "prefixes");
                    if missing {
                        items.push(("prefixes".to_string(), prefixes.clone()));
                    }
                    missing
                }
                _ => false,
            };
            let _ = insert;
            upsert(entries, "group_trigger", trigger);
        }
        let mut settings: Vec<(String, Doc)> = Vec::new();
        let mut keep: Vec<(String, Doc)> = Vec::new();
        for (key, value) in entries.drain(..) {
            if base.contains(&key.as_str()) {
                keep.push((key, value));
            } else {
                settings.push((key, value));
            }
        }
        for (key, value) in keep {
            entries.push((key, value));
        }
        if !settings.is_empty() {
            entries.push(("settings".to_string(), Doc::Object(settings)));
        }
        out.push((name, channel));
    }
    document.set("channel_list", Doc::Object(out));
    document.set("version", Doc::Int(CURRENT_VERSION));
}

/// `migrateLegacyAgentDefaultsModel` (migration.go:64): a legacy `agents.defaults.model`
/// string becomes `model_name`, and the old key goes. It runs in the v0 step and again in
/// the v2 step, so a document that skips versions still meets it.
fn migrate_legacy_agent_defaults_model(document: &mut Doc) {
    let Some(defaults) = document
        .get_mut_at("agents")
        .and_then(|agents| agents.as_object_mut())
        .and_then(|entries| entries.iter_mut().find(|(k, _)| k == "defaults"))
        .map(|(_, v)| v)
    else {
        return;
    };
    let Some(entries) = defaults.as_object_mut() else {
        return;
    };
    let Some(position) = entries.iter().position(|(k, _)| k == "model") else {
        return;
    };
    let model = entries.remove(position).1;
    if !entries.iter().any(|(k, _)| k == "model_name") {
        entries.push(("model_name".to_string(), model));
    }
}

/// The `api_key` -> `api_keys` fold shared by the v0 and v1 steps (`toUniqueStrings`).
///
/// Both spellings are merged and de-duplicated, and the pair is written **only when the
/// result is non-empty** -- so `{"api_key":""}` comes back unchanged rather than as an
/// empty `api_keys`. Go builds the set in a map and reads it back in map order, which
/// makes a result of two or more keys unordered in Go itself; first-seen order is used
/// here, and a corpus case with two distinct keys would be pinning a coin flip.
fn unique_api_keys(document: &mut Doc) {
    let Some(list) = document
        .get_mut_at("model_list")
        .and_then(Doc::as_array_mut)
    else {
        return;
    };
    for entry in list.iter_mut() {
        let Some(entries) = entry.as_object_mut() else {
            continue;
        };
        let single = entries
            .iter()
            .find(|(k, _)| k == "api_key")
            .and_then(|(_, v)| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let existing: Vec<Doc> = entries
            .iter()
            .find(|(k, _)| k == "api_keys")
            .and_then(|(_, v)| v.as_array().cloned())
            .unwrap_or_default();
        let mut merged: Vec<Doc> = Vec::new();
        if let Some(key) = single {
            merged.push(Doc::String(key));
        }
        for item in existing {
            let keep = item.as_str().is_some_and(|s| !s.is_empty());
            if keep && !merged.contains(&item) {
                merged.push(item);
            }
        }
        if merged.is_empty() {
            continue;
        }
        if let Some(position) = entries.iter().position(|(k, _)| k == "api_key") {
            entries.remove(position);
        }
        upsert(entries, "api_keys", Doc::Array(merged));
    }
}

/// Sets `key` to `value` in a mapping, keeping the position it already had.
fn upsert(entries: &mut Vec<(String, Doc)>, key: &str, value: Doc) {
    match entries.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value,
        None => entries.push((key.to_string(), value)),
    }
}

/// Fills `base` with everything `overlay` says, leaving everything it does not mention
/// at the default.
///
/// This is Go's decode-into-a-populated-struct: a field absent from the document keeps
/// its default, a field present replaces it, and a nested object recurses. The
/// wholesale part at a scalar or array is what the security file does too, and it is the
/// part a "smart" merge would get wrong -- see the corpus case
/// `security_entry_replaces_the_json_model`.
/// Fills in what the document does not say, following Go's decode into a populated
/// `DefaultConfig()`.
///
/// The schema decides whether a position merges or replaces, and the two answers sit
/// one level apart:
///
/// * A **struct** merges field by field, which is why a file that says only
///   `{"agents":{"defaults":{"model_name":"m"}}}` keeps every other default.
/// * A **map** replaces the entry. `encoding/json` decodes an object into a map by
///   allocating a fresh element (`reflect.New(t.Elem())`) and assigning it, so an
///   existing entry is never handed to the decoder. That is what makes a user's
///   `channel_list.telegram` *the whole channel*: the default telegram entry's
///   `typing: {enabled: true}` and `media_group_delay_ms: 500` do not survive it, and a
///   port that deep-merges writes a channel the user never configured -- with their
///   typing indicator on and their own `settings` keys quietly merged into the ones the
///   struct does not have.
///
/// A slice replaces too, for the same reason: the decoder assigns rather than appends.
fn merge_over(base: &mut Doc, overlay: &Doc, schema: &Schema) {
    let both_objects = base.as_object_mut().is_some() && overlay.as_object().is_some();
    if both_objects {
        if matches!(schema, Schema::Struct { .. }) {
            let overlay_entries = overlay.as_object().expect("checked").clone();
            let base_entries = base.as_object_mut().expect("checked");
            for (k, v) in overlay_entries {
                let child = schema.field(&k);
                match base_entries.iter_mut().find(|(bk, _)| *bk == k) {
                    Some(slot) => match child {
                        Some(child) => merge_over(&mut slot.1, &v, child),
                        None => slot.1 = v,
                    },
                    None => base_entries.push((k, v)),
                }
            }
            return;
        }
        // `tools.skills.registries` is a slice that is not a JSON array. Its
        // `MarshalJSON` writes a name-keyed map and its `UnmarshalJSON` merges each
        // entry into the one the defaults already carry -- it clones the stored entry
        // and decodes over the clone -- so a document that names one registry leaves the
        // others alone *and* leaves the named entry's unstated fields at their defaults.
        // That is the opposite of both arms below: a plain map replaces its entry whole,
        // and anything else replaces the value.
        let registry_elem = match schema {
            Schema::Slice { elem, .. }
                if matches!(
                    **elem,
                    Schema::Struct {
                        name: Some("SkillRegistryConfig"),
                        ..
                    }
                ) =>
            {
                Some(&**elem)
            }
            _ => None,
        };
        if let Some(elem) = registry_elem {
            let overlay_entries = overlay.as_object().expect("checked").clone();
            let base_entries = base.as_object_mut().expect("checked");
            for (k, v) in overlay_entries {
                match base_entries.iter_mut().find(|(bk, _)| *bk == k) {
                    Some(slot) => merge_over(&mut slot.1, &v, elem),
                    None => base_entries.push((k, v)),
                }
            }
            return;
        }
        // A map's entries are allocated fresh, so only the *keys* the document omits
        // come from the defaults.
        if matches!(schema, Schema::Map { .. }) {
            let overlay_entries = overlay.as_object().expect("checked").clone();
            let base_entries = base.as_object_mut().expect("checked");
            for (k, v) in overlay_entries {
                match base_entries.iter_mut().find(|(bk, _)| *bk == k) {
                    Some(slot) => slot.1 = v,
                    None => base_entries.push((k, v)),
                }
            }
            return;
        }
    }
    *base = overlay.clone();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.json");
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(body.as_bytes()).expect("write");
        (dir, path)
    }

    #[test]
    fn a_missing_file_is_defaults_not_an_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cfg = load(&dir.path().join("absent.json"), "/home/oracle").expect("missing loads");
        assert_eq!(cfg.document, default_config("/home/oracle"));
        assert!(
            !cfg.needs_version_bump,
            "defaults are already at CurrentVersion"
        );
    }

    #[test]
    fn a_tiny_document_is_defaults() {
        let (_dir, path) = write_temp("{}");
        let cfg = load(&path, "/home/oracle").expect("{} loads");
        assert_eq!(cfg.document, default_config("/home/oracle"));
    }

    /// The `load` wiring, pinned here rather than left to the corpus: the coercion runs on the
    /// merged document before `InitChannelList`, so a scalar in the file is already a list by
    /// the time anything reads the loaded value. Without the call in `load` this is the only
    /// test that notices, and the corpus cases that would have caught it live above this
    /// branch.
    #[test]
    fn a_bare_allow_from_loads_as_a_list() {
        let (_dir, path) = write_temp(
            r#"{"version":3,"session":{"dm_scope":"per-channel"},"channel_list":{"telegram":{"allow_from":"alice"}}}"#,
        );
        let cfg = load(&path, "/home/oracle").expect("load");
        assert_eq!(
            cfg.document
                .path(&["channel_list", "telegram", "allow_from"]),
            Some(&Doc::Array(vec![Doc::String("alice".to_string())]))
        );
    }

    /// The other half of the Slice arm. `group_trigger.prefixes` is a plain `[]string`, and
    /// the `FlexibleStringSlice` coercion is an *override* over the stored value, not a
    /// replacement of it. Matching the coercion alone projected every non-flexible slice to
    /// `Null`, so a user's trigger prefixes disappeared from the loaded value with no error
    /// at all -- and `prefixes` appears in no corpus case, so the replay stays green.
    #[test]
    fn a_plain_slice_in_channel_settings_still_projects() {
        let (_dir, path) = write_temp(
            r#"{"version":3,"session":{"dm_scope":"per-channel"},"channel_list":{"telegram":{"group_trigger":{"prefixes":["!","?"],"mention_only":true}}}}"#,
        );
        let cfg = load(&path, "/home/oracle").expect("load");
        // Both keys, in `GroupTriggerConfig`'s declaration order rather than the file's.
        assert_eq!(
            cfg.document
                .path(&["channel_list", "telegram", "group_trigger"])
                .map(Doc::to_compact_json),
            Some(r#"{"mention_only":true,"prefixes":["!","?"]}"#.to_string())
        );
    }

    /// A bare bool or object at a `FlexibleStringSlice` falls through every arm of Go's
    /// decoder, which refuses it naming the type. The override restored that by falling back
    /// to the stored document, whose value then lands in the mismatch arm; before it, the
    /// field projected to `Null`, `omitzero` dropped it, and the load *succeeded* with the
    /// field absent -- a silently different config, the case the `Struct` arm exists for one
    /// arm over.
    #[test]
    fn a_bool_or_object_at_a_flexible_slice_is_refused() {
        for value in ["true", r#"{"a":"b"}"#] {
            let document = format!(
                r#"{{"version":3,"session":{{"dm_scope":"per-channel"}},"channel_list":{{"telegram":{{"allow_from":{value}}}}}}}"#
            );
            let (_dir, path) = write_temp(&document);
            let err = load(&path, "/home/oracle")
                .expect_err("a bool or object at a FlexibleStringSlice is refused, not erased");
            assert!(
                err.to_string().contains("FlexibleStringSlice"),
                "{value}: got {err}"
            );
        }
    }

    #[test]
    fn a_version_that_is_not_an_integer_is_refused_by_name() {
        // `{"version":"3"}` is the case `unwrap_or(0)` got wrong: filed as v0, the whole        // migration ladder ran over the document and `needs_version_bump` was set, so a
        // config Go refuses came out looking migrated.
        //
        // The sentence is Go's, measured from `LoadConfig` rather than composed: the probe
        // decodes into a typed struct and `wrapJSONError` restates the type error with a
        // position that depends on the value's kind: for a **scalar** the last byte of the
        // literal, so the column moves with its length; for a **container** the opening byte,
        // because the decoder refuses on seeing `[` or `{` and never descends -- which is why
        // the two array shapes below differ elevenfold in length and read the same column 12.
        // Every shape here is measured from `LoadConfig`, not composed.
        for (document, want) in [
            (
                r#"{"version":"3"}"#,
                "config.json type error at line 1, column 14 for field \"version\": \
                 expected int but got string",
            ),
            (
                r#"{"version":true}"#,
                "config.json type error at line 1, column 15 for field \"version\": \
                 expected int but got bool",
            ),
            (
                r#"{"version":3.5}"#,
                "config.json type error at line 1, column 14 for field \"version\": \
                 expected int but got number 3.5",
            ),
            (
                r#"{"version":[1]}"#,
                "config.json type error at line 1, column 12 for field \"version\": \
                 expected int but got array",
            ),
            (
                r#"{"version":{}}"#,
                "config.json type error at line 1, column 12 for field \"version\": \
                 expected int but got object",
            ),
            (
                r#"{"version":[]}"#,
                "config.json type error at line 1, column 12 for field \"version\": \
                 expected int but got array",
            ),
            (
                r#"{"version":[[1],{"a":"}"}]}"#,
                "config.json type error at line 1, column 12 for field \"version\": \
                 expected int but got array",
            ),
        ] {
            let (_dir, path) = write_temp(document);
            let err = load(&path, "/home/oracle").expect_err("a non-integer version is refused");
            assert!(matches!(err, Error::VersionType(_)), "got {err}");
            assert_eq!(err.to_string(), want, "{document}");
        }
    }

    #[test]
    fn a_negative_version_is_refused_rather_than_migrated() {
        // The migration helpers are `if version <= N`, which makes it look as though any
        // version below CurrentVersion migrates. It does not: `LoadConfig` dispatches on
        // exact values -- `case 0`, `case 1`, `case 2`, `case CurrentVersion`, `default:`
        // (config.go:1492-1511) -- so -1 never reaches the ladder and is refused. Measured
        // rather than inferred, because the two readings disagree and only one is Go.
        // Pinned here rather than in the corpus: the fixture has no negative-version case
        // and adding one is Go-side work.
        let (_dir, path) = write_temp(r#"{"version":-1,"providers":{"openai":{"api_key":"k"}}}"#);
        let err = load(&path, "/home/oracle").expect_err("a negative version must be refused");
        assert!(matches!(err, Error::UnsupportedVersion(-1)), "got {err}");
        assert_eq!(err.to_string(), "unsupported config version: -1");
    }

    #[test]
    fn an_empty_document_is_refused() {
        // The other half of BUG_VERSION_PROBE_BEFORE_LENGTH: 0 bytes is a syntax error
        // and 2 bytes is defaults. A port that gets the order wrong passes this only by
        // failing the case above.
        let (_dir, path) = write_temp("");
        let err = load(&path, "/home/oracle").expect_err("empty must be refused");
        assert!(matches!(err, Error::Malformed(_)), "got {err}");
    }

    #[test]
    fn a_version_above_this_build_is_refused() {
        let (_dir, path) = write_temp(r#"{"version":99}"#);
        let err = load(&path, "/home/oracle").expect_err("99 must be refused");
        assert_eq!(err, Error::UnsupportedVersion(99));
    }

    #[test]
    fn an_unknown_top_level_key_is_refused_by_name() {
        let (_dir, path) = write_temp(r#"{"version":3,"bogus":1}"#);
        let err = load(&path, "/home/oracle").expect_err("bogus must be refused");
        assert_eq!(err, Error::UnknownField("bogus".to_string()));
    }

    #[test]
    fn a_v0_api_key_becomes_a_one_entry_list() {
        let (_dir, path) = write_temp(
            r#"{"model_list":[{"model_name":"m1","provider":"openrouter","model":"llama-3","api_key":"sk-1"}]}"#,
        );
        let cfg = load(&path, "/home/oracle").expect("v0 migrates");
        let keys = cfg
            .document
            .path(&["model_list"])
            .and_then(Doc::as_array)
            .expect("model_list")[0]
            .get("api_keys")
            .and_then(Doc::as_array)
            .expect("api_keys")
            .clone();
        assert_eq!(keys, vec![Doc::String("sk-1".into())]);
        assert!(
            cfg.needs_version_bump,
            "a migrated config is raised on save"
        );
    }

    #[test]
    fn a_v0_providers_map_is_refused_on_the_key_the_migration_left() {
        // The bug, pinned on the Rust side too. If this ever loads, the port has
        // silently diverged from the binary it replaces.
        let (_dir, path) = write_temp(
            r#"{"providers":{"openrouter":{"api_key":"sk-1","api_base":"https://x","models":["llama-3"]}}}"#,
        );
        let err = load(&path, "/home/oracle").expect_err("providers must be refused");
        assert_eq!(err, Error::UnknownField("providers".to_string()));
    }

    #[test]
    fn v2_channels_become_channel_list() {
        let (_dir, path) = write_temp(r#"{"version":2,"channels":{"discord":{"enabled":true}}}"#);
        let cfg = load(&path, "/home/oracle").expect("v2 migrates");
        assert!(cfg.document.get("channel_list").is_some(), "renamed");
        assert!(
            cfg.document.get("channels").is_none(),
            "the old key is gone"
        );
    }

    #[test]
    fn a_current_version_loads_its_own_values_over_the_defaults() {
        let (_dir, path) = write_temp(r#"{"version":3,"gateway":{"port":19000}}"#);
        let cfg = load(&path, "/home/oracle").expect("loads");
        assert_eq!(
            cfg.document
                .path(&["gateway", "port"])
                .and_then(Doc::as_i64),
            Some(19000)
        );
        // The sibling the file did not mention is still the default, not zero.
        assert_eq!(
            cfg.document
                .path(&["gateway", "host"])
                .and_then(Doc::as_str),
            Some("localhost")
        );
    }

    #[test]
    fn merge_replaces_an_array_wholesale() {
        // The property the security-file case turns on: an entry that arrives with one
        // unknown key does not keep the api_keys it did not mention.
        let mut base = from_json(r#"{"list":[{"api_keys":["sk-1"],"name":"m"}]}"#).into_doc();
        let overlay = from_json(r#"{"list":[{"zzz":1}]}"#).into_doc();
        merge_over(&mut base, &overlay, &config_schema());
        assert_eq!(
            base.path(&["list"]).and_then(Doc::as_array).expect("list")[0].to_compact_json(),
            r#"{"zzz":1}"#
        );
    }

    #[test]
    fn stability_is_vacuous_below_two_writes() {
        assert_eq!(save_is_stable(&[]), (true, false));
        assert_eq!(save_is_stable(&["x".into()]), (true, false));
        assert_eq!(save_is_stable(&["x".into(), "x".into()]), (true, true));
        assert_eq!(save_is_stable(&["x".into(), "y".into()]), (false, true));
        assert_eq!(
            save_is_stable(&["x".into(), "x".into(), "z".into()]),
            (false, true)
        );
    }

    #[test]
    fn the_constants_are_go_s_not_rust_taste() {
        assert_eq!(TINY_DOCUMENT_MAX, 10);
        assert_eq!(CURRENT_VERSION, 3);
        assert_eq!(SECURITY_FILE, ".security.yml");
    }

    /// Seeds a directory with both halves of a split config and returns the config path.
    ///
    /// Every case here needs the pair: a `.security.yml` with no `config.json` beside it
    /// takes the `DefaultConfig()` shortcut at the top of `LoadConfig` and never reads the
    /// security file at all.
    fn write_pair(config: &str, security: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.json");
        std::fs::write(&path, config).expect("write config.json");
        std::fs::write(path.with_file_name(SECURITY_FILE), security).expect("write security");
        (dir, path)
    }

    /// The models a load produced, as `model_name` strings.
    fn models(document: &Doc) -> Vec<String> {
        document
            .get("model_list")
            .and_then(Doc::as_array)
            .map(|list| {
                list.iter()
                    .map(|entry| {
                        entry
                            .get("model_name")
                            .and_then(Doc::as_str)
                            .unwrap_or_default()
                            .to_string()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// One field of one model entry, by position.
    fn model_field<'a>(document: &'a Doc, position: usize, field: &str) -> Option<&'a Doc> {
        document
            .get("model_list")?
            .as_array()?
            .get(position)?
            .get(field)
    }

    /// A v3 document with one model, `m1`, holding no keys.
    const ONE_MODEL: &str =
        r#"{"version":3,"model_list":[{"model_name":"m1","provider":"openai"}]}"#;

    #[test]
    fn the_security_file_merges_into_the_model_it_is_named_for() {
        // The direct witness that `apply_security` merges at all. Nothing in the corpus can
        // be it: every `save` case is red on other bytes, and a refusal case refuses in the
        // parse stage, with the merge deleted or not. Deleting the `apply_security` call in
        // `load` fails this test and nothing else.
        //
        // It reads the document rather than the marshalled loaded value on purpose. The
        // marshalled form hides `api_keys` -- `SecureStrings.MarshalJSON` emits nothing --
        // which is Go's rule and the reason the corpus's security cases grade a `save`. The
        // document is where the merge lands, so that rule cannot make this assertion vacuous
        // when the marshalling stage is ported.
        let (_dir, path) = write_pair(
            ONE_MODEL,
            "model_list:\n    m1:0:\n      api_keys: [sk-from-security]\n",
        );
        let cfg = load(&path, "/home/oracle").expect("the pair loads");
        assert_eq!(
            model_field(&cfg.document, 0, "api_keys"),
            Some(&Doc::Array(vec![Doc::String(
                "sk-from-security".to_string()
            )])),
            "the entry fills the field it names"
        );
    }

    #[test]
    fn a_matching_entry_without_keys_clears_them() {
        // `m.APIKeys = sec.APIKeys` is unconditional once the entry matches, so an entry
        // that names no keys assigns nil -- it does not leave the model's keys alone.
        let config =
            r#"{"version":3,"model_list":[{"model_name":"m1","api_keys":["sk-original"]}]}"#;
        let (_dir, path) = write_pair(config, "model_list:\n    m1:0: {}\n");
        let cfg = load(&path, "/home/oracle").expect("the pair loads");
        assert_eq!(
            model_field(&cfg.document, 0, "api_keys"),
            None,
            "cleared, not left alone and not emptied"
        );
    }

    #[test]
    fn a_matching_entry_cannot_set_a_field_it_is_not_named_for() {
        // The security file is a secrets file. `SecureModelList.UnmarshalYAML` assigns
        // `api_keys` and nothing else, so `provider` here is inert -- merging the whole entry
        // would let a secrets file repoint a model at another provider.
        let (_dir, path) = write_pair(
            ONE_MODEL,
            "model_list:\n    m1:0:\n      provider: anthropic\n      api_keys: [sk-1]\n",
        );
        let cfg = load(&path, "/home/oracle").expect("the pair loads");
        assert_eq!(
            model_field(&cfg.document, 0, "provider"),
            Some(&Doc::String("openai".to_string())),
            "the document's own provider survives"
        );
    }

    /// The same rule on the legacy path, which is the half the v3 test above leaves unwitnessed.
    /// A legacy document is merged with the security file **as data** before the strict pass
    /// (`config.go:1474` `mergeMap`), and it is tempting to conclude that a data merge copies
    /// every key the config entry lacks. It does not: measured against `LoadConfig` at v2 with
    /// `provider: other`, `model: othermodel`, `rpm: 77` and `api_keys` in the same entry, the
    /// loaded model keeps `provider`, `model` and `rpm` from the document and gains only the
    /// keys -- byte-identical to v3. The merge is generic, but the security file's own typed
    /// decode has already narrowed the entry to `api_keys` by the time it is data.
    #[test]
    fn a_legacy_document_narrows_the_security_entry_to_its_keys_too() {
        // What narrows the entry here is **not** a typed decode: `loadConfigMap` reads the
        // security file into a `map[string]any`, so nothing has consulted `ModelConfig` by the
        // time the entry is data. The narrowing is the single assignment
        // `mVal["api_keys"] = vv["api_keys"]` at migration.go:524, inside the loop that walks
        // the security map -- the migrated path takes `api_keys` and nothing else because that
        // is the only field it names. (An earlier round of this PR's write-up credited the
        // file's "own typed decode", which is the v3 mechanism; the commit message of
        // 31043aec carries the same slip and is left as history rather than rewritten.)
        let legacy = r#"{"version":2,"model_list":[{"model_name":"m1","provider":"openai"}]}"#;
        let (_dir, path) = write_pair(
            legacy,
            "model_list:\n    m1:0:\n      provider: anthropic\n      api_keys: [sk-1]\n",
        );
        let cfg = load(&path, "/home/oracle").expect("the pair loads");
        assert_eq!(
            model_field(&cfg.document, 0, "provider"),
            Some(&Doc::String("openai".to_string())),
            "the data merge does not widen what a secrets file may set"
        );
    }

    #[test]
    fn an_entry_naming_no_model_is_ignored_rather_than_appended() {
        // The phantom this port used to invent: an entry keyed for a model the document does
        // not hold, appended as a model with an empty name. It then survives the process --
        // `save` writes it into `config.json` and names it `:0` in the security file, which
        // the round trip cannot read back as the entry it wrote.
        let (_dir, path) = write_pair(
            ONE_MODEL,
            "model_list:\n    m9:0:\n      api_keys: [sk-phantom]\n",
        );
        let mut cfg = load(&path, "/home/oracle").expect("the pair loads");
        assert_eq!(
            models(&cfg.document),
            vec!["m1".to_string()],
            "the security entry names nothing, so it adds nothing"
        );
        save(&path, &mut cfg, "/home/oracle").expect("save");
        let written = std::fs::read_to_string(&path).expect("config.json");
        assert!(
            !written.contains("sk-phantom") && !written.contains("api_keys"),
            "and the phantom cannot come back through the writer: {written}"
        );
        let security =
            std::fs::read_to_string(path.with_file_name(SECURITY_FILE)).expect("security file");
        assert!(
            security.contains("\n  m1:0:")
                && !security.contains("\n  :0:")
                && !security.contains("m9"),
            "one entry, named for the model that exists: {security}"
        );
    }

    #[test]
    fn a_sequence_is_refused_for_the_current_version_and_ignored_for_a_legacy_one() {
        // The JSON shape copied into the YAML file. Both sides of this were measured against
        // `LoadConfig`: v3 reports the decoder's type error, v2 loads the default list,
        // because `loadConfigMap` merges the section only when it is a map and deletes it
        // either way. A port that refuses it always loads a file Go accepts; one that always
        // ignores it accepts a file Go refuses.
        let security = "model_list:\n    - model_name: m1\n      api_keys: [sk-1]\n";
        let (_dir, path) = write_pair(ONE_MODEL, security);
        let err = load(&path, "/home/oracle").expect_err("v3 refuses the sequence");
        assert!(
            matches!(err, Error::SecurityType(_)),
            "the current version reports a type error: {err}"
        );
        assert!(
            err.to_string().contains("map[string]*config.ModelConfig"),
            "naming the type it wanted: {err}"
        );

        let legacy = r#"{"version":2,"model_list":[{"model_name":"m1","provider":"openai"}]}"#;
        let (_dir, path) = write_pair(legacy, security);
        let cfg = load(&path, "/home/oracle").expect("v2 loads the same file");
        assert!(
            !models(&cfg.document).contains(&"m1".to_string())
                || model_field(&cfg.document, 0, "api_keys").is_none(),
            "the sequence is ignored, so no key from it lands anywhere: {:?}",
            models(&cfg.document)
        );
        assert!(
            cfg.needs_version_bump,
            "and it is still the migration path that loaded it"
        );
    }

    #[test]
    fn an_unknown_security_key_is_refused_for_a_legacy_document_only() {
        // The other edge of the same split. A current-version security file is decoded by
        // `yaml.v3` into `Config`, and a key with nowhere to land is dropped without a word.
        // A legacy one is merged into config.json as data first, and the strict validator
        // then runs over the merged bytes -- so the key is refused, with config.json's own
        // sentence naming it. Measured: v3 loads, v2 reports
        // `config.json contains unknown field(s): nonsense`.
        let (_dir, path) = write_pair(ONE_MODEL, "nonsense:\n    a: 1\n");
        load(&path, "/home/oracle").expect("the current version ignores it");

        let legacy = r#"{"version":2,"model_list":[{"model_name":"m1","provider":"openai"}]}"#;
        let (_dir, path) = write_pair(legacy, "nonsense:\n    a: 1\n");
        let err = load(&path, "/home/oracle").expect_err("v2 refuses the same file");
        assert!(
            matches!(&err, Error::UnknownField(paths) if paths == "nonsense"),
            "the legacy path refuses it by name: {err}"
        );
    }

    #[test]
    fn web_and_skills_are_reached_and_dropped_until_the_merge_carries_its_schema() {
        // `Tools` is `yaml:",inline"`, so the file's top-level `web:` and `skills:` are
        // `tools` fields and Go applies them. This port reaches them -- `apply_security`
        // walks the inline branch and hands each child to `merge_filling` -- and then drops
        // them, because `merge_filling` still asks the *root* schema whether a key is a
        // field, and `web` is a field of `Tools`, not of `Config`.
        //
        // So this test pins the divergence, not the goal: it fails the day the gate is
        // threaded with the target's schema, and the day it does, `docs/DIVERGENCES.md`
        // loses the entry and these three assertions turn into the merge they describe.
        // Recorded here rather than only in the doc because the doc claimed a mechanism
        // (`apply_security` merges only the two named sections) that the code no longer has.
        let (_dir, path) = write_pair(
            ONE_MODEL,
            "web:\n  brave:\n    api_keys: [bk-from-security]\nskills:\n  github:\n    auth_token: gh-from-security\n",
        );
        let cfg = load(&path, "/home/oracle").expect("the pair loads");
        let tools = cfg.document.get("tools").expect("tools is in the defaults");
        assert_eq!(
            tools
                .get("web")
                .and_then(|w| w.get("brave"))
                .and_then(|b| b.get("api_keys")),
            None,
            "the security key does not land -- docs/DIVERGENCES.md"
        );
        assert_eq!(
            tools
                .get("skills")
                .and_then(|s| s.get("github"))
                .and_then(|g| g.get("auth_token")),
            None,
            "nor the registry token -- docs/DIVERGENCES.md"
        );
    }

    #[test]
    fn the_legacy_view_lifts_web_and_skills_into_tools() {
        // `Config.Tools` is `yaml:",inline"`, so `web` and `skills` are tools fields and the
        // lift keeps them legal under the strict validator. The lift also *replaces* the
        // file's own `tools` section -- `m2["tools"] = m3`, where `m3` holds only the two
        // lifted sections -- which is why a security file carrying both a `tools:` and a
        // `web:` section has its `tools:` thrown away.
        let legacy = r#"{"version":2,"model_list":[{"model_name":"m1","provider":"openai"}]}"#;
        let (_dir, path) = write_pair(
            legacy,
            "tools:\n  bogus: 1\nweb:\n  brave:\n    api_keys: [bk]\nskills:\n  github:\n    token: gh\n",
        );
        load(&path, "/home/oracle").expect("the lifted sections are legal");

        // The pre-`registries` spelling, which the lift alone does not make legal. Go rewrites
        // `skills.clawhub` into `skills.registries.clawhub` before anything validates the view,
        // and `registries` is a **slice** node -- so the object under it is never field-checked,
        // while the same object under the `skills` struct node is. Without the rewrite this
        // config is refused as `tools.skills.clawhub`, a refusal Go does not make at either
        // version, on the install the migration exists to serve.
        let (_dir, path) = write_pair(legacy, "skills:\n  clawhub:\n    token: ch\n");
        load(&path, "/home/oracle").expect("the clawhub spelling is rewritten, not refused");

        // Go's own written `.security.yml` is the same shape, and it is the case that matters
        // operationally: a file this crate would have to read back after saving it.
        let (_dir, path) = write_pair(
            legacy,
            "skills:\n  registries:\n    clawhub:\n      auth_token: ch\n",
        );
        load(&path, "/home/oracle").expect("the current spelling loads, as it always did");

        // And the rewrite is not a licence: `skills` is still a struct node, so a key that is
        // neither one of its fields nor one of the two spellings is still named.
        let (_dir, path) = write_pair(legacy, "skills:\n  bogus:\n    token: x\n");
        let err = load(&path, "/home/oracle").expect_err("skills.bogus has no field to hold it");
        assert!(
            matches!(&err, Error::UnknownField(paths) if paths == "tools.skills.bogus"),
            "the rewrite rewrites, it does not relax: {err}"
        );

        // Without the lift the same `tools` content is refused, which is what makes the
        // above a fact about the lift rather than about `bogus` being accepted.
        let (_dir, path) = write_pair(legacy, "tools:\n  bogus: 1\n");
        let err = load(&path, "/home/oracle").expect_err("tools.bogus has no field to hold it");
        assert!(
            matches!(&err, Error::UnknownField(paths) if paths == "tools.bogus"),
            "named by path, the way the JSON validator names it: {err}"
        );
    }

    /// Writes `config.json` and **no** `.security.yml` -- the state most installs are in, and
    /// the one `write_pair` cannot express because it always writes both files.
    fn write_config_only(config: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.json");
        std::fs::write(&path, config).expect("write config.json");
        assert!(
            !dir.path().join(SECURITY_FILE).exists(),
            "the point of this helper is that the security file is absent"
        );
        (dir, path)
    }

    /// The loaded value's `tools.skills.registries`, in the same compact JSON the corpus records.
    fn loaded_registries(path: &std::path::Path) -> serde_json::Value {
        let cfg = load(path, "/home/oracle").expect("the pair must load");
        let value = loaded_value(&cfg.document, &config_schema());
        let parsed: serde_json::Value =
            serde_json::from_str(&value).expect("the loaded value is JSON");
        parsed["tools"]["skills"]["registries"].clone()
    }

    #[test]
    fn the_document_is_normalised_with_no_security_file_on_disk() {
        // Go normalises `tools.skills.registries` **during** the JSON unmarshal, before the
        // security file is opened, so the pass cannot be gated on that file existing. The
        // three shapes are the ones the decoder changes rather than passes through, and each
        // is a different mistake: `flattened` is the nested `param` map lifted to its keys,
        // `renamed` is the `name` key the marshaler writes itself being dropped, `nulled` is a
        // null credential becoming no key rather than a key holding null.
        let (_dir, path) = write_config_only(
            r#"{"version":3,"tools":{"skills":{"registries":{
                "flattened":{"enabled":true,"param":{"a":1}},
                "renamed":{"name":"named","enabled":true},
                "nulled":{"enabled":true,"auth_token":null}}}}}"#,
        );
        let registries = loaded_registries(&path);
        assert_eq!(
            registries["flattened"],
            serde_json::json!({"a": 1, "base_url": "", "enabled": true}),
            "the nested `param` is lifted and the wrapper gone: {registries}"
        );
        assert_eq!(
            registries["renamed"],
            serde_json::json!({"base_url": "", "enabled": true}),
            "`name` is one of the keys the marshaler writes itself, so it is not a param: \
             {registries}"
        );
        assert_eq!(
            registries["nulled"],
            serde_json::json!({"base_url": "", "enabled": true}),
            "a null credential is no key at all, not `auth_token: null`: {registries}"
        );
    }

    #[test]
    fn a_null_registries_header_in_the_file_wipes_to_the_builtins_at_zero_values() {
        // `registries:` with nothing after the colon is a `!!null` node, and yaml short-circuits
        // it into a nil slice: the document's own registry is gone and what remains is the
        // baseline's *names* at zero values. Measured against `LoadConfig` at picoclaw
        // `01635da3`: `{"clawhub":{"base_url":"","enabled":false},"github":{...}}`. The names
        // come from the baseline, so this is the pass that cannot be answered without it --
        // neither file says `clawhub` any more.
        let (_dir, path) = write_pair(
            r#"{"version":3,"tools":{"skills":{"registries":{"custom":{"enabled":true}}}}}"#,
            "skills:\n  registries:\n",
        );
        assert_eq!(
            loaded_registries(&path),
            serde_json::json!({
                "clawhub": {"base_url": "", "enabled": false},
                "github": {"base_url": "", "enabled": false},
            }),
            "the null header replaces the set rather than adding nothing to it"
        );
    }

    #[test]
    fn the_legacy_view_rewrites_both_registry_spellings_and_keeps_their_asymmetry() {
        // The rewrite is only observable through the view, because the view is what the
        // strict validator sees; the data merge that carries these values into a migrated
        // document is a separate, recorded divergence. So this test asks the view directly.
        let view = |security: &str| {
            migration_view(&yaml::parse(security).expect("the security file parses"))
        };
        let registry = |view: &Doc, name: &str| {
            view.get("tools")
                .and_then(|tools| tools.get("skills"))
                .and_then(|skills| skills.get("registries"))
                .and_then(|registries| registries.get(name))
                .cloned()
        };

        // `clawhub` MOVES: `m["registries"] = map[string]any{"clawhub": m["clawhub"]}` and
        // `delete(m, "clawhub")`. Asserting the value arrived is what makes this a fact about
        // the rewrite -- a pass that merely deleted the key would load too.
        let moved = view("skills:\n  clawhub:\n    token: ch\n");
        let moved_entry = registry(&moved, "clawhub");
        assert_eq!(
            moved_entry
                .as_ref()
                .and_then(|entry| entry.get("token"))
                .and_then(Doc::as_str),
            Some("ch"),
            "the entry is rewritten into `registries`, not dropped: {moved:?}"
        );
        assert!(
            moved
                .get("tools")
                .and_then(|tools| tools.get("skills"))
                .and_then(|skills| skills.get("clawhub"))
                .is_none(),
            "`skills.clawhub` is deleted, so nothing is left to refuse"
        );

        // The replacement is wholesale: with both spellings in one file, Go's assignment
        // discards the `registries` the file already carried (measured: `other` is gone from
        // the loaded value, `clawhub` is present).
        let replaced = view(
            "skills:\n  clawhub:\n    token: ch\n  registries:\n    other:\n      base_url: u\n",
        );
        assert!(
            registry(&replaced, "other").is_none(),
            "`clawhub` replaces `registries`, it does not join it: {replaced:?}"
        );
        assert!(
            registry(&replaced, "clawhub").is_some(),
            "and the replacement holds the moved entry: {replaced:?}"
        );

        // `github` is COPIED, not moved, and the copy carries `auth_token` set from `token`
        // while `token` itself stays -- which is the second half of why a legacy
        // `skills.github.token` reaches the registry twice on the save side (masked
        // `auth_token` plus plaintext `token`, both measured in Go's loaded value).
        let copied = view("skills:\n  github:\n    token: gh\n");
        let github = registry(&copied, "github").expect("`registries.github` is created");
        assert_eq!(
            github.get("auth_token").and_then(Doc::as_str),
            Some("gh"),
            "the copy carries `auth_token` from `token`: {github:?}"
        );
        assert_eq!(
            github.get("token").and_then(Doc::as_str),
            Some("gh"),
            "and keeps `token`, which is why the value arrives twice: {github:?}"
        );
        assert!(
            copied
                .get("tools")
                .and_then(|tools| tools.get("skills"))
                .and_then(|skills| skills.get("github"))
                .is_some(),
            "`skills.github` itself is left in place -- a copy, not a move"
        );

        // No `token`, no `auth_token`: the assignment is inside `if token, ok := …`.
        let untouched = view("skills:\n  github:\n    base_url: u\n");
        let github = registry(&untouched, "github").expect("the copy is made regardless");
        assert!(
            github.get("auth_token").is_none(),
            "a `github` entry with no `token` gains no credential: {github:?}"
        );
        assert_eq!(
            github.get("base_url").and_then(Doc::as_str),
            Some("u"),
            "and the copy carries the entry's own keys: {github:?}"
        );

        // Both spellings in the order Go applies them: `clawhub` replaces first, then
        // `github` is added to the map that replacement built.
        let both = view("skills:\n  clawhub:\n    token: ch\n  github:\n    token: gh\n");
        assert!(
            registry(&both, "clawhub").is_some() && registry(&both, "github").is_some(),
            "the second rewrite joins the map the first one built: {both:?}"
        );

        // The one shape the rewrite does NOT rescue, measured at picoclaw `1a4e1edf`: a
        // `clawhub:` with no value is nil, so the `!= nil` guard skips it and the `delete`
        // inside the guard never runs -- the key stays, and Go refuses the file with
        // exactly this sentence. A rewrite that deleted unconditionally would load.
        let (_dir, path) = write_pair(
            r#"{"version":2,"model_list":[{"model_name":"m1","model":"x","provider":"openai"}]}"#,
            "skills:\n  clawhub:\n",
        );
        let err = load(&path, "/home/oracle").expect_err("a null clawhub is left where it is");
        assert!(
            matches!(&err, Error::UnknownField(paths) if paths == "tools.skills.clawhub"),
            "Go refuses it as an unknown field, and so do we: {err}"
        );
    }

    #[test]
    fn an_empty_registries_mapping_in_the_file_is_not_a_wipe() {
        // The other half of the same node-kind distinction, and the one that broke a fixed
        // point through Go's own saved pair when the two were read as one shape: the file Go
        // writes says `registries: {}`, and treating that as a wipe turns Go's own output into
        // a config Go never produced. An empty mapping decodes to a map that adds nothing, so
        // the builtins keep their **defaults** and the document's entry survives.
        let (_dir, path) = write_pair(
            r#"{"version":3,"tools":{"skills":{"registries":{"custom":{"enabled":true}}}}}"#,
            "skills:\n  registries: {}\n",
        );
        assert_eq!(
            loaded_registries(&path),
            serde_json::json!({
                "clawhub": {"base_url": "https://clawhub.ai", "enabled": true},
                "custom": {"base_url": "", "enabled": true},
                "github": {"base_url": "https://github.com", "enabled": true},
            }),
            "`registries: {{}}` adds nothing; `registries:` replaces everything"
        );
    }

    #[test]
    fn a_non_mapping_registries_node_leaves_the_builtins_standing() {
        // A document whose `registries` is not a mapping is ignored rather than applied, so the
        // baseline survives at its **defaults** -- the same answer as `null` at this depth, and
        // the opposite of `null` in the file. This is the arm the ledger used to call
        // unanswerable for want of the builtin names: they are in the embedded `defaults.json`
        // that `default_config` returns, which is the very baseline `load` merges into.
        for (shape, document) in [
            (
                "an array",
                r#"{"version":3,"tools":{"skills":{"registries":[{"enabled":true,"name":"github"}]}}}"#,
            ),
            (
                "null",
                r#"{"version":3,"tools":{"skills":{"registries":null}}}"#,
            ),
        ] {
            let (_dir, path) = write_config_only(document);
            assert_eq!(
                loaded_registries(&path),
                serde_json::json!({
                    "clawhub": {"base_url": "https://clawhub.ai", "enabled": true},
                    "github": {"base_url": "https://github.com", "enabled": true},
                }),
                "{shape} at `registries` is ignored, not echoed over the builtins"
            );
        }
    }

    #[test]
    fn a_duplicate_model_name_takes_the_security_entry_at_the_first_position_only_when_migrated() {
        // The one place the two loaders' matching shapes disagree, measured at picoclaw
        // `1a4e1edf` with `model` on every entry so the required-field stage is not what
        // answers: two models both named `m1`, the file keyed by the bare name.
        //
        // | version | Go's `api_keys` per position |
        // | --- | --- |
        // | 3 | set, set |
        // | 2 | set, **absent** |
        //
        // v3 asks per position and each position falls back to the bare name; the migrated path
        // builds `indexedKeys`, where the bare name is inserted only for the first position
        // that carries it (`if _, ok := indexedKeys[nameStr]; !ok`), and iterates the file.
        // Keying the second position explicitly agrees on both versions, which is the control
        // that keeps this a fact about the bare-name fallback rather than about duplicates.
        let duplicate = r#"{"version":%VERSION%,"model_list":[
            {"model_name":"m1","model":"x1","provider":"a"},
            {"model_name":"m1","model":"x2","provider":"b"}]}"#;
        let keys_at = |document: &Doc, position: usize| -> bool {
            document
                .get("model_list")
                .and_then(Doc::as_array)
                .and_then(|list| list.get(position))
                .is_some_and(|entry| entry.get("api_keys").is_some())
        };

        for version in ["2", "3"] {
            let (_dir, path) = write_pair(
                &duplicate.replace("%VERSION%", version),
                "model_list:\n  m1:\n    api_keys: [sk-1]\n",
            );
            let cfg = load(&path, "/home/oracle").expect("the pair loads");
            assert!(
                keys_at(&cfg.document, 0),
                "v{version}: the first `m1` always takes the entry"
            );
            assert_eq!(
                keys_at(&cfg.document, 1),
                version == "3",
                "v{version}: only the current version's per-position fallback reaches the                  second `m1`"
            );
        }

        // The explicit spelling resolves to the same position on both versions, so the
        // disagreement above is the bare-name fallback and not duplicate handling in general.
        for version in ["2", "3"] {
            let (_dir, path) = write_pair(
                &duplicate.replace("%VERSION%", version),
                "model_list:\n  m1:1:\n    api_keys: [sk-1]\n",
            );
            let cfg = load(&path, "/home/oracle").expect("the pair loads");
            assert!(
                !keys_at(&cfg.document, 0) && keys_at(&cfg.document, 1),
                "v{version}: `m1:1` is the second position at both versions"
            );
        }
    }
}
