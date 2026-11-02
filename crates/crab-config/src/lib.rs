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
mod multikey;
mod schema;
mod skills;
mod yaml;

pub use defaults::{assert_table_shape, default_config, BUILTIN_MODEL_COUNT, TOP_LEVEL_KEYS};
pub use doc::{from_json, Doc, Parsed};
pub use marshal::{apply_omit, apply_session_shadow, config_file, loaded_value};
pub use schema::{config_schema, unknown_fields, validate_against, Schema};
pub use yaml::{parse as parse_security, to_name_index, write as write_security, Security};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
    /// A value whose shape the type Go decodes it into cannot hold.
    ///
    /// Go raises this from its own typed decoder, and its sentence names a line, a column and
    /// a quoted excerpt of the file:
    ///
    /// ```text
    /// config.json type error at line 1, column 2: expected []*config.SecureString but got number
    /// ```
    ///
    /// This crate keeps no byte offsets, so the payload is Go's `expected ... but got ...` tail
    /// with the dotted path it refused appended. No case pins that wording: a refusing corpus
    /// case records `error_op_index` and nothing else, so the shape of the value is graded and
    /// the sentence is not. Saying so here is what keeps a later reader from quoting this as
    /// Go's text -- the measurements behind it are in `schema.rs`, beside the type.
    TypeMismatch(String),
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
            Self::TypeMismatch(m) => write!(f, "config.json type error: {m}"),
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
    /// Positions in `model_list` that `expandMultiKeyModels` created, the port's version
    /// of Go's per-entry `isVirtual` flag. `SaveConfig` drops exactly these, so the file
    /// keeps one entry per model while the loaded value carries one per key.
    ///
    /// It lives here rather than in the document because a marker key would be a field
    /// the schema does not have, and the loader's own validator refuses those.
    pub(crate) virtual_models: Vec<usize>,
    /// The real `auth_token` behind each `tools.skills.registries` entry, which the
    /// document holds masked because that is what `MarshalJSON` emits. Only `save` reads
    /// it: the security file is the YAML rendering, where `SecureString` answers with the
    /// value rather than the placeholder. See [`skills`].
    pub(crate) secure_tokens: Vec<(String, String)>,
}

impl Config {
    /// A config holding `document` and no loader side-state -- what Go's `DefaultConfig()`
    /// returns before any file has been read.
    ///
    /// The constructor exists so that the two side-state fields can stay `pub(crate)`. They
    /// are the loader's notes to the save path, not part of a config's value: a caller that
    /// builds a `Config` by naming every field has to be told which of them are load-bearing
    /// (`virtual_models` decides what gets written to `config.json`, `secure_tokens` decides
    /// what lands in `.security.yml`), and a test that leaves both empty by writing
    /// `Vec::new()` twice is a test that silently cannot exercise either.
    #[must_use]
    pub fn from_document(document: Doc) -> Self {
        Self {
            document,
            needs_version_bump: false,
            virtual_models: Vec::new(),
            secure_tokens: Vec::new(),
        }
    }

    /// Which `model_list` entries the loader invented; see the field's own documentation.
    #[must_use]
    pub fn virtual_models(&self) -> &[usize] {
        &self.virtual_models
    }

    /// The registry names the loader holds a real token for, in the order it met them.
    #[must_use]
    pub fn secure_tokens(&self) -> &[(String, String)] {
        &self.secure_tokens
    }

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
/// The whole fixture replays byte for byte, which is a stronger claim than "the stages
/// are ported" and a weaker one than "the loader is complete". What is missing below is
/// missing because **no recorded case reaches it**, not because it was measured and found
/// equal -- so a green replay says nothing about any of it:
///
/// * `env.Parse` and the `PICOCLAW_*` compat shims. The corpus runs with the environment
///   cleared, so they are inert for every recorded case -- but a real process is not, and
///   this loader would silently differ from Go there. Recorded in
///   `docs/DIVERGENCES.md` with the three variables it reads.
/// * `ValidateModelList` and `ValidateTurnProfile`. Both refuse a config rather than
///   change one, and the corpus records no refusal for either, so a port that omits them
///   accepts files the shipped binary rejects.
/// * `validateSingletonChannels` and `validateChannelStreamingConfig`, the two validators
///   at the end of `InitChannelList`. The singleton registry is Go-side data the schema
///   dump does not carry, which is why closing this needs a Go-side decision and not only
///   Rust work. Also recorded in `docs/DIVERGENCES.md`.
///
/// Everything the fixture does reach is here: the version dispatch and the ladder, the
/// migration's own security pre-merge ([`load_config_map`]), the decode and its unknown
/// field refusal, the security file including both skills passes,
/// `channels::init_channel_list`, `multikey::expand`, the session scope, and the
/// persistence a migration owes the disk ([`make_backup`] and the deferred [`save`]).
///
/// The security file *is* read, because leaving it out would load a config whose secrets
/// are in the wrong place. `channels`/`channel_list` and `model_list` are merged, and
/// `skills` runs in the two halves Go runs it in: [`skills::normalise_document`] with the
/// document alone, then [`skills::apply`] for the file's two merge passes -- the legacy lift
/// and the registry passes, which is what the `tools.skills` half of the loaded value is
/// pinned against. The split is not cosmetic: the first half happens during Go's JSON
/// unmarshal, so it runs when there is no `.security.yml` at all.
///
/// No section Go applies is dropped any more. `web` reaches `tools.web` through `Tools`'
/// `yaml:",inline"`, and for that the inline branch has to be handed the schema of the node
/// it is merging into: `web` is a field of `Tools`, one level down, so a walk that does not
/// see it walks straight past the section. That was the recorded divergence, and
/// `the_web_section_of_the_security_file_reaches_tools` is the positive pin -- see that test
/// for which fault kills which assertion. Refusing both sections instead was the
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
                virtual_models: Vec::new(),
                secure_tokens: Vec::new(),
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
            virtual_models: Vec::new(),
            secure_tokens: Vec::new(),
        });
    }

    // The security file is read here, before the ladder, because the migration arms ask
    // for it first -- see [`load_config_map`]. It is read once and used twice: as raw
    // material for the ladder, and again below as the ordinary security pass.
    let security_path = path.with_file_name(SECURITY_FILE);
    let security_text = match std::fs::read_to_string(&security_path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(Error::Io(format!("failed to read security config: {e}"))),
    };

    let document = match version {
        0..=2 => {
            // `case 0..=2` does not migrate config.json. It calls `loadConfigMap(path)`,
            // which reads config.json *and* `.security.yml`, merges them, and hands the
            // result to the ladder. The difference is not cosmetic: the security file's
            // `channel_list` entries arrive as ordinary JSON, so `ChannelsConfig`
            // decodes them as **new** channels and each one replaces its default --
            // `group_trigger`, `typing` and `placeholder` and all. Loading the same
            // security file at the current version merges into the defaults instead,
            // because that path goes through `Channel.UnmarshalYAML`. It is the one place
            // in this crate where the same two files produce two different configs
            // depending on a version number, and `migrate_backs_up_both_files` is the
            // case that says so.
            let input = match &security_text {
                Some(text) => load_config_map(&document, &yaml::parse(text)?.document)?,
                None => document,
            };
            migrate(input, version)
        }
        CURRENT_VERSION => document,
        other => return Err(Error::UnsupportedVersion(other)),
    };
    let migrated = version < CURRENT_VERSION;

    // The decode. Go decodes into a fresh DefaultConfig() and the unknown-field validator
    // runs over the same bytes first, so strictness and defaults-filling are two passes
    // over the document, not one. Which bytes those are depends on the version: a
    // current-version document is validated as config.json alone, because its security file
    // is decoded separately by `yaml.v3`; a legacy one has already been merged with the
    // security file as plain data by [`load_config_map`], re-marshalled, and validated as
    // one document -- so a key only the security file introduced is refused there, with
    // config.json's own sentence. That is also why the security file is never folded into
    // the validated bytes a second time: the merge above already put its keys in `document`.
    validate_against(&document, &config_schema())
        .map_err(|issues| Error::UnknownField(issues.join(", ")))?;
    // Go's decode is typed, so a shape it cannot place fails the load with its own sentence,
    // and it checks *every* field. This walk checks the one named type where being permissive
    // is silently wrong: `SecureStrings`, which does not have the tolerance the port assumed
    // every named string slice has (issue #15). The rest of Go's type errors stay unported and
    // tracked rather than assumed away -- a `model_list` holding a bare number is refused by
    // the shipped binary and still loads here, which is stated in the issue filed with this
    // change, not hidden by it.
    if let Some((path, wanted, got)) = schema::misplaced_secure_strings(&document, &config_schema())
    {
        return Err(Error::TypeMismatch(format!(
            "expected {wanted} but got {got} at {path}"
        )));
    }
    // That is also why the security file is never folded into the validated bytes a second
    // time: the merge above already put its keys in `document`. Validating a projection of
    // the file alongside the document -- the shape used before `load_config_map` existed --
    // reports one unknown key twice, `config.json contains unknown field(s): nonsense,
    // nonsense`, the same doubled-seam failure the security *merge* had.
    let mut merged = default_config(home);
    // The baseline `tools.skills.registries` before the document is merged over it. Go decodes
    // the file *into* the defaults, so a document whose `registries` is not a mapping leaves
    // the builtins standing, and after `merge_over` the answer is no longer in the document.
    let baseline_registries = merged.path(&["tools", "skills", "registries"]).cloned();
    merge_over(&mut merged, &document, &config_schema());

    // `SkillsRegistriesConfig`'s decoder, which Go runs as part of the JSON unmarshal -- that
    // is, before the security file is opened. It is the document-side half of the skills pass
    // and it does not ask whether a `.security.yml` exists; the merge below does.
    let mut secure_tokens = skills::normalise_document(&mut merged, baseline_registries.as_ref());

    // The typed security pass, with the version gate Go puts on it: `LoadConfig` calls
    // `loadSecurityConfig` in `case CurrentVersion` and nowhere else, because the `case
    // 0..=2` arms have already taken the security file in through [`load_config_map`] as
    // plain data, before the ladder. Running both for a migrated document applies one file
    // twice where Go applies it once -- and the second trip is through the stricter decoder,
    // `yaml.v3` over typed structs instead of a plain map merge, which is the difference
    // between merging a `channel_list` entry into its default and replacing that default.
    // `filter` rather than a nested `if`: this edition has no let chains, and a nested one
    // is what `collapsible_if` asks to collapse into a let chain.
    if let Some(text) = security_text.as_ref().filter(|_| !migrated) {
        // Not wrapped. `Error::SecurityType` and `Error::UnparseableSecurity` are the two
        // kinds this stage can raise and both name themselves; folding them into `Error::Io`
        // would report a type error as a read failure.
        let security = yaml::parse(text)?;
        secure_tokens = apply_security(&mut merged, &security, baseline_registries.as_ref())?;
        // Assigning rather than extending is what the call-site gate buys: the typed pass
        // rebuilds the same `registries` the document-side pass just rebuilt, so for a
        // current-version document its list *supersedes* the one above -- the file may have
        // replaced an entry whose credential was just collected, or wiped the section to the
        // builtins, and keeping the stale pair would write a credential Go no longer holds.
        // A migrated document must keep the document-side list, because that is where
        // `load_config_map` lifted the legacy `skills.github.token` out of the file; this
        // block never runs for one, so it cannot clobber it.
    }

    // `InitChannelList`, which sits here in Go too -- after the security merge, before
    // the session scope. It is the stage that makes a loaded config more than the file:
    // every channel's `settings` is replaced by what its typed struct marshals, so the
    // fields the file left out appear and the keys come back in declaration order.
    channels::init_channel_list(&mut merged, &config_schema())?;

    // `expandMultiKeyModels`, in Go's position: after the channel list, before the
    // session scope. It is the only stage that changes the *number* of model entries, so
    // it has to run after the security file has put the keys in and before anything reads
    // the list's length.
    let virtual_models = multikey::expand(&mut merged, &config_schema());

    // The last two stages of LoadConfig, and the reason a loaded config can carry a
    // dm_scope the file never mentioned.
    apply_dm_scope(&mut merged);

    let migrated = version < CURRENT_VERSION;
    let mut config = Config {
        document: merged,
        needs_version_bump: migrated,
        virtual_models,
        secure_tokens,
    };

    // A migration is not only in memory. Each `case 0..=2` arm of `LoadConfig` runs
    // `MakeBackup(path)` and then `defer SaveConfig(path, cfg)`, so loading a v0 file on
    // a real machine leaves four files behind: the two backups and the two rewritten
    // configs. The defer is what makes the written file the *fully* loaded one -- it runs
    // after the security merge, `InitChannelList` and the model expansion, not just after
    // the ladder -- which is why this sits at the end of `load` rather than at the
    // version switch.
    //
    // It also mutates the config the caller gets: `SaveConfig` raises `version` through
    // the same pointer, so a migrated load reports `version: 3` in the loaded value even
    // though the file said 0. Skipping the write is not a silent difference either -- the
    // next start would migrate the same file again.
    if migrated {
        let path = path.to_path_buf();
        // `MakeBackup` is a plain call in Go, so a directory that cannot hold a backup does
        // fail the load. The save is the one whose result is thrown away.
        make_backup(&path)?;
        // `defer SaveConfig(path, cfg)` discards its error, and that is a behaviour, not an
        // oversight: Go starts the agent on the migrated config in memory while the file on
        // disk stays at the old version. Propagating here would turn a read-only config
        // directory into "no config at all", which is a strictly worse failure than the one
        // the shipped binary has -- and the caller cannot retry, because `load` has already
        // returned the error instead of the config.
        //
        // Timing, for whoever ports the stages listed in this function's doc: Go's `defer`
        // runs at the *return* of `LoadConfig`, so it persists whatever the loader did after
        // the migration switch -- `env.Parse` and the `Validate*` calls included. This writes
        // at the migration point, which produces the same bytes only while nothing follows
        // it. When those stages land, move this beside `Ok(config)` or the file on disk will
        // disagree with the value the caller receives.
        let _ = save(&path, &mut config, home);
    }

    Ok(config)
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
///   one has its security file merged in as data by [`load_config_map`] and validated as
///   config.json bytes.
///
/// Per field, not per entry: the file decodes into a `Config` the JSON pass has already
/// populated, so an entry touches the fields it names and leaves the rest alone. Which
/// fields a section may name is decided by that section's own projection, not by the
/// entry's shape -- `model_list` gets `api_keys` and nothing else, and an entry naming a
/// model the document does not hold is ignored.
///
/// This is `loadSecurityConfig`, and it runs for a **current-version** document only.
/// `LoadConfig` reaches it in `case CurrentVersion` and nowhere else: the `case 0..=2`
/// arms have already taken the security file in through [`load_config_map`], as plain
/// data, before the ladder. Calling both for a migrated document applies one file twice
/// where Go applies it once -- and through the wrong decoder the second time, `yaml.v3`
/// over typed structs instead of a map merge, which is the difference between merging a
/// `channel_list` entry into its default and replacing that default outright.
fn apply_security(
    merged: &mut Doc,
    security: &yaml::Security,
    baseline_registries: Option<&Doc>,
) -> Result<Vec<(String, String)>, Error> {
    let schema = schema::config_schema();

    // A `model_list` that is not a mapping: the JSON shape copied into a YAML file, or
    // gone entirely. `SecureModelList.UnmarshalYAML` refuses either, and this is the only
    // path that reaches it -- the migrated path merges the section only if it is a map and
    // deletes it either way, so a non-mapping is ignored there rather than refused.
    // Measured on both sides of the same file: v3 refuses with the decoder's sentence, v2
    // loads the default list.
    if let Some(kind) = security.model_list_kind {
        return Err(Error::SecurityType(format!(
            "cannot unmarshal !!{kind} into map[string]*config.ModelConfig"
        )));
    }

    // A `model_list` that is a mapping. A section that is not one was refused above, or
    // parsed as an empty map for `model_list:` with no value.
    if let Some(Doc::Object(entries)) = security.model_list() {
        // **The decode judges every entry, matched or not.** "An entry naming no model is
        // ignored" is exactly right about the loop below and exactly wrong about the decode:
        // `SecureModelList.UnmarshalYAML` (`config_struct.go:324`) calls `value.Decode(&mm)` on
        // the whole map and returns that error *before* the model loop runs. So this pass has
        // no dependence on what the document lists, and it runs whether or not the merged
        // document even has a `model_list` array to write into.
        //
        // Measured against a document listing only `m1`, one process per shape, at
        // `/tmp/opencode/picoclaw-probes/secstr-null/probe.go`:
        //
        // ```text
        // m9:0: {api_keys: 42}      REFUSED  cannot unmarshal !!int `42` into config.SecureStrings
        // m9:   {api_keys: sk-sec}  REFUSED  cannot unmarshal !!str `sk-sec` into config.SecureStrings
        // m9:0: 42                  REFUSED  cannot unmarshal !!int `42` into config.ModelConfig
        // m9:0: [42]                REFUSED  cannot unmarshal !!seq into config.ModelConfig
        // m9:0:                     LOADED   (a nil *ModelConfig, which the loop then skips)
        // m9:0: {api_keys: [42]}    LOADED   (elements stay permissive for an unmatched entry too)
        // m9:0: {provider: 42}      LOADED   (yaml.v3 decodes a scalar into a string field)
        // ```
        //
        // The migration path does not behave this way: the same file at v2 loads with
        // `model_name not found in main config: m9:0`, because `mergeModelListsWithMap` reads
        // the map per model instead of decoding it whole. This belongs to the current-version
        // rule and to nothing else.
        for (_, value) in entries {
            match value {
                Doc::Null => {}
                Doc::Object(_) => {
                    if let Some(found) = value.get("api_keys") {
                        if !crate::schema::secure_strings_yaml_accepts(found) {
                            return Err(Error::SecurityType(format!(
                                "cannot unmarshal {} into {}",
                                node_kind(found),
                                crate::schema::SECURE_STRINGS_GO_TYPE
                            )));
                        }
                    }
                }
                // The entry is not a map at all, so the decode fails one level up: Go names the
                // model type, not the field.
                other => {
                    return Err(Error::SecurityType(format!(
                        "cannot unmarshal {} into config.ModelConfig",
                        node_kind(other)
                    )));
                }
            }
        }

        if let Some(list) = merged.get_mut_at("model_list").and_then(Doc::as_array_mut) {
            // The file keys entries `name:index`; the document holds a sequence.
            //
            // `SecureModelList.UnmarshalYAML` (config_struct.go:326) walks the models the
            // JSON loader produced and asks the security map for each one's `name:index`
            // key, falling back to the bare name per position. The migration path runs
            // `mergeModelListsWithMap` instead -- see [`merge_model_list_into_array`] --
            // and the two agree on every shape except one: two models both named `m1` with
            // the file keyed `m1:` give v3 `["[NOT_HERE]", "[NOT_HERE]"]` and a migrated
            // config `["[NOT_HERE]", "<nil>"]`, because the migration builds a key set in
            // which the bare name resolves to the *first* position carrying it only.
            // Measured at picoclaw `1a4e1edf`, one process per scenario, with `model`
            // present on every entry so the required-field stage is not what is answering.
            //
            // Three rules both loaders share, and both ports state here and there:
            //
            // * **An entry naming no model is ignored, not appended.** The loop runs over
            //   the models, not over the map, so a leftover `m9:0` against a config that
            //   lists only `m1` contributes nothing. Appending it instead invents a model
            //   with an empty name: the next `save` writes it into `config.json`, names it
            //   `:0` in the security file, and the round trip cannot even reproduce the
            //   entry it wrote.
            // * **Only `api_keys` is taken.** `m.APIKeys = sec.APIKeys` is a field
            //   assignment, so `m1:0: {provider: other}` leaves the provider alone --
            //   merging the whole entry would let the secrets file set a model's provider
            //   or rpm.
            // * **The assignment is unconditional when the entry matches**, so a matching
            //   entry with no `api_keys` clears the model's keys rather than leaving them
            //   alone.
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
                    Some(found) => {
                        // Its shape was already judged by the decode pass above, which is also
                        // Go's order here: `SecureModelList.UnmarshalYAML` decodes the whole map
                        // into `map[string]*ModelConfig` before this loop assigns anything. The
                        // generic shape gate never sees this node -- this pass owns `model_list`,
                        // because the file is a map here and the document a sequence -- and
                        // sequence elements stay permissive, so `api_keys: [42]` in a security
                        // entry loads, measured.
                        list[position].set("api_keys", found.clone());
                    }
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
                // `child.name`, not `child.json`: the file is keyed by the names `yaml.v3`
                // writes and the document by the JSON tags. See the note on the top-level
                // lookup below for why that distinction is not pedantry.
                if let Some(value) = security.document.get(child.name) {
                    if let Some(slot) = target.get_mut_at(child.json) {
                        merge_filling(slot, value, inner_schema.field(child.json))?;
                    }
                }
            }
            continue;
        }
        // The channel section merges per entry rather than wholesale, and it answers to
        // either spelling in the file while the document has only one -- so it is handled
        // before the lookup, which asks for the one name the yaml encoder writes.
        if field.json == "channel_list" {
            let source = security
                .document
                .get("channel_list")
                .or_else(|| security.document.get("channels"));
            if let (Some(source), Some(target)) = (source, merged.get_mut_at("channel_list")) {
                apply_security_channels(target, source)?;
            }
            continue;
        }
        // The file is keyed by the names `yaml.v3` writes; the document by the JSON tags.
        // Ninety-odd fields in the dump spell the two differently, because a Go field with
        // no `yaml:` tag gets the lowercased field name -- `web.searxng.base_url` is
        // `baseurl` in the file, `agents.defaults.model_name` is `modelname`. Asking the
        // file for the JSON spelling therefore ignores what the shipped binary reads and
        // applies what it would ignore, in both directions, silently.
        let Some(value) = security.document.get(field.name) else {
            continue;
        };
        if let Some(target) = merged.get_mut_at(field.json) {
            // The schema is threaded for the document's sake, not the corpus's: dropping it
            // here passes every case in the fixture, because both files are rendered from the
            // typed struct and the schema, so an invented key never reaches either. It is
            // kept because Go's struct genuinely does not have the key, and a document that
            // carries things Go's does not is a document that will diverge the first time
            // anything renders it raw. `security_unknown_key_reaches_neither_written_file`
            // is the byte-level half of the same rule.
            merge_filling(target, value, schema.field(field.json))?;
        }
    }

    skills::apply(merged, security, baseline_registries)
}

/// What `loadConfigMap` (migration.go:429) builds: config.json and `.security.yml`
/// merged as plain data, before any typed decoding and before the migration ladder.
///
/// Two rewrites happen on the way, both because the security file is written by the YAML
/// encoder and read back here as if it were the config:
///
/// * `web` and `skills` are fields of the **tools** section, but the security file writes
///   them at the top level. They are lifted into a `tools` key, and the legacy `skills`
///   spelling is rewritten into `registries` on the way -- `clawhub` becomes a registry,
///   and a `github` map is copied into `registries.github` with `token` *duplicated* as
///   `auth_token` rather than moved. That duplicate is why the loaded value shows a
///   legacy token twice, once masked and once in plaintext; see [`skills`].
/// * `model_list` cannot be merged as data at all: the config holds an array, the
///   security file a `name:index` map. The array wins and the map is consumed into it,
///   contributing each model's `api_keys` and nothing else, then deleted -- merging the
///   two as maps would replace the array with a map and lose every model.
///
/// Everything else merges with the security file winning, which is what makes a
/// migration see a different document than the file on disk.
fn load_config_map(config: &Doc, security: &Doc) -> Result<Doc, Error> {
    let mut m1 = config.clone();
    let mut m2 = security.clone();

    if let Doc::Object(entries) = &mut m2 {
        // Go asks `m2[key] != nil` twice over: once to decide whether the lift runs at all
        // (`migration.go:425`), and again **per key** inside it (`:429`, `:433`). So a
        // null-valued section does not join the lift even when its sibling triggers it -- it
        // stays in the merged document, where the strict validator names it. Testing only
        // presence in the loop is the permissive half of that, and it loads a file
        // `LoadConfig` refuses: measured, `web:` (null) beside a `skills:` mapping is refused
        // by Go as `unknown field(s): web` and by the reverse shape as `unknown field(s):
        // skills`. A hand-edited `.security.yml` with a bare `skills:` line is this shape.
        let present = |key: &str| {
            entries
                .iter()
                .any(|(k, v)| k == key && !matches!(v, Doc::Null))
        };
        if present("web") || present("skills") {
            let mut tools: Vec<(String, Doc)> = Vec::new();
            for key in ["web", "skills"] {
                if let Some(position) = entries
                    .iter()
                    .position(|(k, v)| k == key && !matches!(v, Doc::Null))
                {
                    let (_, value) = entries.remove(position);
                    let mut value = value;
                    if key == "skills" {
                        legacy_skills_as_registries(&mut value);
                    }
                    tools.push((key.to_string(), value));
                }
            }
            // `m2["tools"] = m3` assigns, so a `tools` section in the security file is
            // replaced by the two lifted keys rather than extended by them.
            match entries.iter_mut().find(|(k, _)| k == "tools") {
                Some(slot) => slot.1 = Doc::Object(tools),
                None => entries.push(("tools".to_string(), Doc::Object(tools))),
            }
        }
    }

    merge_model_list_into_array(&mut m1, &mut m2)?;
    if let Doc::Object(entries) = &mut m2 {
        entries.retain(|(k, _)| k != "model_list");
    }

    Ok(merge_maps(&m1, &m2))
}

/// The two registry spellings `migration.go:437-454` performs on the lifted `skills` node.
///
/// Both exist because the registry *map* is newer than the file format being migrated: an old
/// security file spells a registry at the top of `skills`, and the migration rewrites it into
/// `skills.registries` before anything looks at the result. Skipping the rewrite stopped being
/// cosmetic the moment `load_config_map`'s output became the bytes the strict validator reads:
/// `skills` is a **struct** node, so a key that is not one of its fields is refused with
/// config.json's own sentence -- `config.json contains unknown field(s): tools.skills.clawhub`
/// -- on exactly the installs the migration exists to serve. Go never refuses them, at either
/// version.
///
/// The two halves are not symmetric, and the asymmetry is the behaviour:
///
/// * `clawhub` **replaces** `registries` wholesale (`m["registries"] = map[string]any{"clawhub":
///   m["clawhub"]}`), so a `registries` the file already carried is discarded when `clawhub` is
///   present. A `clawhub` that is present but null is left where it is, because the `delete`
///   sits inside Go's `!= nil` guard -- the one shape the rewrite does not rescue.
/// * `github` is **copied, not moved**: `skills.github` stays and `registries.github` is a copy
///   with `auth_token` set from `token` when `token` is there (and `token` itself stays in the
///   copy). That is the second half of why a legacy `skills.github.token` reaches the registry
///   twice on the save side.
/// * a `registries` that is not a mapping is replaced rather than merged into, because Go's type
///   assertion yields nil and the code then builds a fresh map.
///
/// What the rewrite does *not* do is make the node permissive: `skills` stays a struct node, so
/// a key that is neither one of its fields nor one of these two spellings is still refused.
fn legacy_skills_as_registries(skills: &mut Doc) {
    let Doc::Object(entries) = skills else { return };
    // Go's guard is `if m["clawhub"] != nil`, and it is load-bearing in both directions.
    // A `clawhub:` with nothing after it is nil, so the guard skips the rewrite *and* the
    // `delete` inside it: the key stays in the lifted `tools.skills`, and the strict
    // validator then refuses the document for `tools.skills.clawhub`. Deleting
    // unconditionally -- the tempting reading -- makes that file load, which is a config Go
    // never produces.
    if let Some((_, clawhub)) = entries
        .iter()
        .find(|(key, value)| key == "clawhub" && !matches!(value, Doc::Null))
        .cloned()
    {
        upsert(
            entries,
            "registries",
            Doc::Object(vec![("clawhub".to_string(), clawhub)]),
        );
        entries.retain(|(k, _)| k != "clawhub");
    }
    let github = entries
        .iter()
        .find(|(k, _)| k == "github")
        .and_then(|(_, v)| v.as_object())
        .cloned();
    if let Some(github) = github {
        let mut registry = github;
        if let Some((_, token)) = registry.iter().find(|(k, _)| k == "token").cloned() {
            // A copy, not a move: `token` stays, which is why a legacy token reaches the
            // loaded value twice -- masked under `auth_token` and in plaintext under
            // `token`. Renaming it here would be the tempting fix and would diverge.
            upsert(&mut registry, "auth_token", token);
        }
        let mut registries = entries
            .iter()
            .find(|(k, _)| k == "registries")
            .and_then(|(_, v)| v.as_object())
            .cloned()
            .unwrap_or_default();
        upsert(&mut registries, "github", Doc::Object(registry));
        upsert(entries, "registries", Doc::Object(registries));
    }
}

/// Folds the security file's `name:index` model map into the config's model array.
///
/// Only `api_keys` crosses over, and only onto a model whose indexed key -- or, for the
/// first model of a name, its bare name -- the file names. An entry naming no model is
/// logged and dropped. A model with no `model_name` is a hard failure, because the map
/// key cannot be derived without it.
///
/// The map is then removed from the security side entirely. Leaving it there would let
/// the data merge replace the array with a map, and every model but the keys would go.
fn merge_model_list_into_array(m1: &mut Doc, m2: &mut Doc) -> Result<(), Error> {
    let models = match m1.get_mut_at("model_list") {
        Some(Doc::Array(items)) => items.clone(),
        _ => return Ok(()),
    };
    let security_models = match m2.get_mut_at("model_list") {
        Some(Doc::Object(entries)) => entries.clone(),
        _ => return Ok(()),
    };

    let mut indexed: Vec<(String, usize)> = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (position, model) in models.iter().enumerate() {
        let name = match model.get("model_name").and_then(Doc::as_str) {
            Some(name) => name.to_string(),
            None => {
                return Err(Error::Malformed(
                    "model_name is required in model_list".to_string(),
                ))
            }
        };
        let count = counts.get(&name).copied().unwrap_or(0);
        indexed.push((format!("{name}:{count}"), position));
        if count == 0 {
            indexed.push((name.clone(), position));
        }
        counts.insert(name, count + 1);
    }

    let mut models = models;
    for (key, entry) in &security_models {
        let Some((_, position)) = indexed.iter().find(|(k, _)| k == key) else {
            continue;
        };
        // Only a mapping entry assigns anything (`if vv, ok := v.(map[string]any)`), and
        // what it assigns is `vv["api_keys"]` -- a missing key yields nil, so a matching
        // entry that names no `api_keys` **clears** the model's keys instead of leaving
        // them alone. Skipping there is the tempting reading and it diverges: the model
        // keeps keys Go has just erased.
        let Doc::Object(fields) = entry else {
            continue;
        };
        match fields.iter().find(|(key, _)| key == "api_keys") {
            Some((_, keys)) => {
                if let Some(slot) = models[*position].get_mut_at("api_keys") {
                    *slot = keys.clone();
                } else {
                    models[*position].set("api_keys", keys.clone());
                }
            }
            // Go assigns nil, which the decoder turns back into a nil slice and
            // `omitempty` then drops -- so the loaded value carries no key at all. An
            // explicit null would be a different value that happens to print similarly.
            None => {
                models[*position].remove("api_keys");
            }
        }
    }

    if let Some(slot) = m1.get_mut_at("model_list") {
        *slot = Doc::Array(models);
    }
    if let Some(Doc::Object(entries)) = m2.get_mut_at("model_list") {
        entries.clear();
    }
    Ok(())
}

/// Go's `mergeMap`: nested maps merge recursively, and anything else the source holds
/// replaces what the destination holds.
fn merge_maps(destination: &Doc, source: &Doc) -> Doc {
    let (Doc::Object(base), Doc::Object(overlay)) = (destination, source) else {
        return source.clone();
    };
    let mut out = base.clone();
    for (key, value) in overlay {
        match out.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = merge_maps(&slot.1, value),
            None => out.push((key.clone(), value.clone())),
        }
    }
    Doc::Object(out)
}

/// Merges the security file's `channel_list` section into the loaded one, per entry.
///
/// `ChannelsConfig.UnmarshalYAML` (:411) walks the file's entries and calls
/// `Channel.UnmarshalYAML` on each, which decodes into a copy of what is already there --
/// so the entry's keys merge rather than replace. One key is different, and it is the one
/// that decides what a saved config looks like:
///
/// `settings` lands in a `RawNode`, whose `UnmarshalYAML` (:115) deep-merges into
/// **whatever that channel slot already holds**. The seed is therefore the channel as it
/// stands after the config document, and that is where the two files part company: a
/// channel the *config file* names is a fresh map element (`encoding/json` allocates one
/// per key), so its slot holds the file's node and the security entry merges into the
/// file's zeros; a channel only the defaults name keeps its default node, so the same
/// entry merges into the defaults. `security_settings_apply_to_a_channel_the_config_names`
/// records the first (`media_group_delay_ms: 1234` on a channel whose other settings are
/// zero), `security_channel_list_entry_merges_into_the_default` the second (`port: 9999`
/// beside a default `host` the security file never mentioned). Seeding from the file's
/// settings alone -- what this function did first -- gets the second one wrong and shows
/// `host: ""`, and no case written against `discord` can see it, because discord's default
/// settings are an empty map.
///
/// Then `Channel.UnmarshalYAML` does `if len(b.Settings) > 0 { b.extend = nil }`: any
/// settings node at all, *even an empty* `{}`, throws away the decoded typed struct.
/// `InitChannelList` later rebuilds it from the raw node into a **fresh** zero struct
/// (`newChannelSettings`), so what comes back is the merged node and nothing else. That is
/// why a config that has been saved once comes back with `group_trigger: {}` and
/// `typing: {}` where a fresh one has `mention_only: true` and `enabled: true`: Go writes
/// `settings: {}` for every channel into every `.security.yml`, and the next load reads
/// that empty node as "no settings", not as "keep the defaults".
fn apply_security_channels(target: &mut Doc, source: &Doc) -> Result<(), Error> {
    let (Some(entries), Some(channels)) = (source.as_object(), target.as_object_mut()) else {
        return Ok(());
    };
    for (name, value) in entries.clone() {
        let position = match channels.iter().position(|(k, _)| k == &name) {
            Some(position) => position,
            // `newBC := &Channel{}` then `node.Decode`: a zero channel, so no default
            // ever enters it and its settings are exactly the node's.
            None => {
                channels.push((name.clone(), Doc::Object(Vec::new())));
                channels.len() - 1
            }
        };
        let channel = &mut channels[position].1;
        if let Some(settings) = value.get("settings") {
            let mut merged = channel
                .get("settings")
                .cloned()
                .unwrap_or(Doc::Object(Vec::new()));
            // No schema here, deliberately. `Channel` keeps `settings` as a `RawNode`, so
            // the security file's node is merged as data and only later decoded -- through
            // JSON, into the typed struct, by `InitChannelList`. A key the settings type
            // does not have is therefore *kept* by this walk and dropped at marshal time,
            // which is what the corpus records; gating it here would drop it from the
            // document and change what a later save writes. It also means this call cannot
            // refuse a shape: the check in `merge_filling` only runs where there is a schema.
            merge_filling(&mut merged, settings, None)?;
            channel.set("settings", merged);
        }
        // Everything else in the entry is dropped, and not by a schema check: every base
        // field of `Channel` is tagged `yaml:"-"` (config_channel.go:224-231), so the yaml
        // decoder never reads `enabled`, `type`, `allow_from` or the rest. A security file
        // can say exactly one thing about a channel, which is its settings.
        //
        // That is what makes an entry under an unknown name a refusal rather than a new
        // telegram channel: `type` in the entry is ignored, `InitChannelList` infers the
        // type from the map key because the struct's is empty (config_channel.go:738), and
        // `isValidChannelType` rejects `mychan`. A port that copies the entry's other keys
        // accepts a file the shipped binary refuses -- and silently turns a secrets file
        // into a way to enable a channel, which is not what it is for.
    }
    Ok(())
}

/// The security file's walk: like [`merge_over`], but a key the **target's own** yaml
/// surface cannot place is dropped rather than added.
///
/// That is the whole difference between the two passes: the JSON document is validated
/// before it is merged, so an unknown key there is a refusal; the security file is not
/// validated, so an unknown key there is nothing at all. Shape is the exception, and the
/// other way round: `loadSecurityConfig` runs `yaml.Unmarshal(data, cfg)` over the whole
/// file, so a node that does not fit its field fails the load -- see [`yaml_accepts`].
///
/// `fields` is the schema of the node being merged *into*, and it has to be threaded from
/// the caller. Asking the top-level `Config` schema instead -- which is what this function
/// did at every depth until a save case caught it -- is right for nothing below the root:
/// `brave` is a field of `WebSearchConfig`, `media_group_delay_ms` of `TelegramSettings`,
/// and neither is a field of `Config`, so both were dropped and the security file's values
/// never reached the typed decode. The failure is quiet in the worst way: the channel came
/// back with the zero its own entry had already forced, which is exactly what a port that
/// ignored the security file entirely records.
///
/// `fields` is the yaml surface of the node being merged into, or `None` where there is no
/// yaml decoder in play at all -- a channel's `settings`, which is stored as a raw node and
/// decoded later through JSON. `None` means every key is readable, and that is a claim about
/// Go, not an absence of one: an unknown key inside `settings` survives the merge and is
/// dropped at marshal time, which is what the corpus records.
///
/// Visibility comes from `yaml_fields`, never from the JSON list. `tools.web.brave` has
/// three JSON fields and one yaml field, and a secrets file can set exactly the one.
fn merge_filling(base: &mut Doc, overlay: &Doc, fields: Option<&Schema>) -> Result<(), Error> {
    // Go never merges this file into anything: `loadSecurityConfig` runs
    // `yaml.Unmarshal(data, cfg)` over the whole document into the typed config first, and
    // `yaml.v3` refuses a node whose shape does not fit the field it lands on. So a
    // position with a schema has to be shape-checked here, before the merge walk decides
    // the value is fine to place.
    if let Some(schema) = fields {
        if !yaml_accepts(overlay, schema) {
            return Err(Error::SecurityType(format!(
                "cannot unmarshal {} into {}",
                node_kind(overlay),
                schema_type(schema)
            )));
        }
    }
    let (Some(base_entries), Some(overlay_entries)) = (base.as_object_mut(), overlay.as_object())
    else {
        // Not an object on both sides, so there is nothing to fill: the security value
        // is the whole new value for this position, exactly as Go's yaml decode assigns
        // the decoded node rather than merging into what was there.
        *base = overlay.clone();
        return Ok(());
    };
    let overlay_entries = overlay_entries.clone();
    for (k, v) in &overlay_entries {
        // The overlay carries the names `yaml.v3` wrote; the base is the JSON document. So
        // the file's key is translated before anything asks the schema about it -- otherwise
        // the gate below passes on `baseurl` and the merge then hunts for a JSON field called
        // `baseurl`, finds none, and appends a key no rendering of the config can produce.
        let field = fields.and_then(|schema| schema.yaml_fields().iter().find(|f| f.name == *k));
        if fields.is_some() && field.is_none() {
            // Not a field the yaml decoder can place. Go's decode has no place for it and
            // moves on; the JSON path would have refused the same key.
            continue;
        }
        let key = field.map_or(k.as_str(), |f| f.json);
        let child = fields.and_then(|schema| schema.field(key));
        match base_entries.iter_mut().find(|(bk, _)| bk.as_str() == key) {
            Some(slot) => merge_filling(&mut slot.1, v, child)?,
            // The key is not in the document yet, which changes nothing about the shape
            // check: Go's decode refuses the node against the field's type whether or not
            // there was anything to merge into, so an absent `api_keys` holding a mapping is
            // still refused, and the sentence is yaml's own: `cannot unmarshal !!map into
            // config.SecureStrings`, naming the field's type -- not the json one, which names
            // `[]*config.SecureString`. Going through the
            // merge rather than pushing directly is what makes that true here -- `Doc::Null`
            // takes the whole overlay, exactly as the push did.
            None => {
                let mut slot = Doc::Null;
                merge_filling(&mut slot, v, child)?;
                base_entries.push((key.to_string(), slot));
            }
        }
    }
    Ok(())
}

/// Does `yaml.v3` have anywhere to put this node?
///
/// Only the two shapes the corpus measures are refused, and the rule is deliberately
/// narrower than "does the type fit": a `null` is Go's zero value and is never a complaint
/// (`security_skills_null_loads_unchanged`), and a scalar into an `int` is a third refusal
/// no case pins, so it is left alone rather than guessed at. What is pinned is a non-mapping
/// where a struct belongs (`security_scalar_where_a_struct_belongs`) and a mapping where a
/// slice belongs (`security_map_where_a_sequence_belongs`) -- both refused by the shipped
/// binary, both previously overwritten here.
fn yaml_accepts(node: &Doc, schema: &Schema) -> bool {
    if matches!(node, Doc::Null) {
        return true;
    }
    // Defensive, and unreachable today: probed by panicking on this branch and running the
    // whole suite (72 unit, 73 conformance, 3 golden), which never reached it. It stays
    // because the exemption is a property of the Go type, not of the corpus -- a position
    // whose type has its own `(Unm|M)arshalYAML` decides its own shape, and the generic walk
    // has no business judging it (`SecureString` takes a bare scalar, `SecureModelList` and
    // `SkillsRegistriesConfig` each project to something the field list does not describe).
    // The first one this walk does reach through a schema has to arrive with a case, not
    // with this branch already graded green.
    if crate::schema::is_secure_strings(schema) {
        // The dump flags `SecureStrings` with a marshaler, and the exemption below is right
        // that a type with its own `(Unm|M)arshalYAML` decides its own shape -- but this type
        // has only a *marshaler*, plus one on its element. Measured: `api_keys: 42` in a
        // security entry is refused with `cannot unmarshal !!int `42` into
        // config.SecureStrings`, while `api_keys: [42]` loads. So the field is a plain sequence
        // and the elements are the permissive part, which is the one case the exemption below
        // would otherwise get backwards for every position of this type.
        return crate::schema::secure_strings_yaml_accepts(node);
    }
    let custom = match schema {
        Schema::Struct { marshaler, .. } | Schema::Map { marshaler, .. } => *marshaler,
        Schema::Slice { marshaler, .. } => *marshaler,
        Schema::Scalar { .. } => true,
    };
    if custom {
        return true;
    }
    match schema {
        Schema::Struct { .. } | Schema::Map { .. } => matches!(node, Doc::Object(_)),
        Schema::Slice { .. } => matches!(node, Doc::Array(_)),
        Schema::Scalar { .. } => true,
    }
}

/// The node's shape, in the words `yaml.v3` uses in its `TypeError`.
fn node_kind(node: &Doc) -> &'static str {
    match node {
        Doc::Null => "!!null",
        Doc::Bool(_) => "!!bool",
        Doc::Int(_) => "!!int",
        Doc::Float(_) => "!!float",
        Doc::String(_) => "!!str",
        Doc::Array(_) => "!!seq",
        Doc::Object(_) => "!!map",
    }
}

/// The Go type a position decodes into, or the shape it wanted when the dump names none.
fn schema_type(schema: &Schema) -> String {
    // One measured exception. The dump names the type `SecureStrings`, but every Go sentence
    // that refuses it says `config.SecureStrings` -- at `model_list[].api_keys` and at the four
    // `tools.web.*` positions alike, which the `model_list` pass and this generic one reach by
    // different routes. Without the qualification the same field is named two different ways
    // depending on which refusal met it. The dump's other names carry the same unprefixed
    // drift and are left alone: they are unmeasured, no corpus case grades a sentence (a
    // refusing case records `error_op_index` and nothing else), and the general type-check gap
    // that would produce most of those sentences is issue #25.
    if crate::schema::is_secure_strings(schema) {
        return crate::schema::SECURE_STRINGS_GO_TYPE.to_string();
    }
    let name = match schema {
        Schema::Struct { name, .. } | Schema::Map { name, .. } | Schema::Slice { name, .. } => {
            *name
        }
        Schema::Scalar { name, .. } => *name,
    };
    match name {
        Some(name) => name.to_string(),
        None => match schema {
            Schema::Struct { .. } | Schema::Map { .. } => "a mapping".to_string(),
            Schema::Slice { .. } => "a sequence".to_string(),
            Schema::Scalar { .. } => "a scalar".to_string(),
        },
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

    // `SaveConfig` swaps in the non-virtual model list *first*, then writes the security
    // file, then marshals the document, and restores the original on a defer. So the
    // entries the loader invented are absent from **both** files while the `fallbacks`
    // that point at them are kept in the config. Getting the order wrong is subtle and
    // expensive: writing the security file from the unfiltered list records
    // `m1__key_1:0: {api_keys: [sk-2]}`, and the next load then finds a model the user
    // never wrote and merges a secret under it.
    let filtered = hide_virtual_models(cfg);
    let masked = unmask_registry_tokens(cfg);

    let security_path = path.with_file_name(SECURITY_FILE);
    // Everything that can fail is inside the block below, and both undo steps run after it
    // whichever way it ends. Go restores the model list on a `defer`, so its caller is left
    // holding a whole config even when the save fails; the `?`s this used to carry returned
    // early with the caller's real models still removed, and the next `save` on that config
    // would write a `model_list` missing every virtual entry's primary.
    //
    // The mask is the worse half of the same mistake. The document is the JSON rendering, so
    // a registry left holding its real token after a failed save renders that secret into
    // anything that reads the loaded value afterwards -- which is why the mask goes back on
    // the failure path too, and why it goes back *before* `config.json` is marshalled on the
    // success path, exactly where Go puts it.
    //
    // The corpus cannot reach any of this: no recorded case fails a write, so a fixture run
    // grades the success path only. `ENOSPC`, `EACCES` or `EROFS` on `.security.yml` is the
    // route, and a retry after a failed write is the normal flow, not an exotic one.
    let mut pending = Some(masked);
    let outcome = (|| -> Result<(String, String), Error> {
        let schema = schema::config_schema();
        let security = yaml::write(&cfg.document, &schema)?;
        write_atomic(&security_path, &security)?;
        if let Some(tokens) = pending.take() {
            remask_registry_tokens(cfg, tokens);
        }
        Ok((security, marshal::config_file(&cfg.document, &schema)?))
    })();
    if let Some(tokens) = pending.take() {
        remask_registry_tokens(cfg, tokens);
    }
    restore_model_list(cfg, filtered);
    let (security, document) = outcome?;
    write_atomic(path, &document)?;

    Ok(vec![security, document])
}

/// Swaps the real `auth_token` into every registry the loader recorded a token for, and
/// hands back what was there, so the caller can put the placeholders back.
///
/// The document is the JSON rendering, where `SkillRegistryConfig.MarshalJSON` writes the
/// literal `[NOT_HERE]` for that key -- which is exactly what the loaded value must show. The
/// security file is the *other* rendering: `yaml.Marshal` asks `SecureString` itself and gets
/// the value. Writing the file straight from the document therefore records a placeholder in
/// the one file whose entire purpose is holding the secret, and the next load then reads back
/// a registry whose token is the string `[NOT_HERE]`.
fn unmask_registry_tokens(cfg: &mut Config) -> Vec<(String, String)> {
    let mut previous = Vec::new();
    let Some(registries) = cfg
        .document
        .get_mut_at("tools")
        .and_then(|tools| tools.get_mut_at("skills"))
        .and_then(|skills| skills.get_mut_at("registries"))
        .and_then(Doc::as_object_mut)
    else {
        return previous;
    };
    for (name, token) in &cfg.secure_tokens {
        let Some(entry) = registries.iter_mut().find(|(key, _)| key == name) else {
            continue;
        };
        if let Some(slot) = entry.1.get_mut_at("auth_token") {
            // Always the placeholder -- `to_doc` is the only writer of this key -- so
            // reading it back as text is exact rather than a lossy coercion.
            previous.push((name.clone(), slot.as_str().unwrap_or_default().to_string()));
            *slot = Doc::String(token.clone());
        }
    }
    previous
}

/// The inverse of [`unmask_registry_tokens`], run before `config.json` is marshalled.
fn remask_registry_tokens(cfg: &mut Config, previous: Vec<(String, String)>) {
    let Some(registries) = cfg
        .document
        .get_mut_at("tools")
        .and_then(|tools| tools.get_mut_at("skills"))
        .and_then(|skills| skills.get_mut_at("registries"))
        .and_then(Doc::as_object_mut)
    else {
        return;
    };
    for (name, value) in previous {
        if let Some(entry) = registries.iter_mut().find(|(key, _)| key == &name) {
            if let Some(slot) = entry.1.get_mut_at("auth_token") {
                *slot = Doc::String(value);
            }
        }
    }
}

/// Removes the loader-created `model_list` entries and hands back what was taken, so the
/// caller can put them back. Out-of-range positions are ignored: the flag is positional,
/// and a caller that shrank the list since loading is not a reason to panic.
fn hide_virtual_models(cfg: &mut Config) -> Vec<(usize, Doc)> {
    let mut taken = Vec::new();
    if cfg.virtual_models.is_empty() {
        return taken;
    }
    let Some(list) = cfg
        .document
        .get_mut_at("model_list")
        .and_then(Doc::as_array_mut)
    else {
        return taken;
    };
    let mut sorted = cfg.virtual_models.clone();
    sorted.sort_unstable();
    sorted.dedup();
    for position in sorted.into_iter().rev() {
        if position < list.len() {
            taken.push((position, list.remove(position)));
        }
    }
    taken.reverse();
    taken
}

/// Puts [`hide_virtual_models`] back, in the order they were taken.
fn restore_model_list(cfg: &mut Config, taken: Vec<(usize, Doc)>) {
    if taken.is_empty() {
        return;
    }
    let Some(list) = cfg
        .document
        .get_mut_at("model_list")
        .and_then(Doc::as_array_mut)
    else {
        return;
    };
    for (position, entry) in taken {
        list.insert(position.min(list.len()), entry);
    }
}

/// `MakeBackup` (config.go:1637): copy the config, and the security file beside it, to
/// `<name>.<YYYYMMDD>.bak`.
///
/// Three things about it are load-bearing and none of them are obvious from the name:
///
/// * **A missing config is not an error and makes no backup.** `os.IsNotExist` returns
///   nil before the suffix is even computed, so loading a config that is not there leaves
///   the directory exactly as it was.
/// * **The suffix is a date, not a timestamp**, so a second load on the same day
///   overwrites the first backup rather than adding a second file. Two loads on two days
///   leave two files, which is why the corpus masks the eight digits: the case would
///   otherwise disagree with itself across midnight.
/// * **The security file is backed up under the same suffix**, and only when it exists.
///   Its absence is normal -- a config from before the split has no secrets file -- and
///   refusing for it would break every such config on first migration.
fn make_backup(path: &Path) -> Result<(), Error> {
    if !path.exists() {
        return Ok(());
    }
    let suffix = format!(".{}.bak", today());
    copy_file(path, &PathBuf::from(format!("{}{suffix}", path.display())))?;
    let security = path.with_file_name(SECURITY_FILE);
    if security.exists() {
        copy_file(
            &security,
            &PathBuf::from(format!("{}{suffix}", security.display())),
        )?;
    }
    Ok(())
}

/// Today, as Go's `time.Now().Format(".20060102.bak")` reads it: the local calendar date,
/// no time, no separator.
fn today() -> String {
    // Days since the Unix epoch, then civil-from-days. Done in the crate rather than via
    // a date dependency: the port has no chrono, and this is the only place a calendar
    // date is needed.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    // Go's time.Now() is local; the corpus clears the environment, so TZ is UTC here and
    // in the generator, which is what makes the masked digits comparable at all.
    let days = secs.div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}{month:02}{day:02}")
}

/// Howard Hinnant's `civil_from_days`: the inverse of `days_from_civil`, no tables.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// `fileutil.CopyFile`: the bytes, at mode 0600.
fn copy_file(from: &Path, to: &Path) -> Result<(), Error> {
    let bytes = std::fs::read(from)
        .map_err(|e| Error::Io(format!("failed to create config backup: {e}")))?;
    // Atomic, like every other write this crate does. A plain `write` leaves the backup
    // truncated-and-readable for the length of the copy, and the one file this one exists
    // to protect is the config: a crash here used to replace a good `config.json.<date>.bak`
    // with a partial one, which is worse than not making the backup at all.
    write_atomic(to, bytes).map_err(|e| Error::Io(format!("failed to create config backup: {e}")))
}

/// `fileutil.WriteFileAtomic`: write beside the target, then rename over it.
///
/// The mode is set on the temp file *before* the rename, so there is no window in which
/// the new content exists under a permissive mode -- and no window in which the target
/// exists but is short.
fn write_atomic(path: &Path, contents: impl AsRef<[u8]>) -> Result<(), Error> {
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

    /// Go decodes the whole `.security.yml` into the typed config *before* anything is
    /// merged, so a node that does not fit the field it lands on fails the load. The port
    /// overwrote the node instead, which is the direction that loses data without saying so.
    ///
    /// `security_scalar_where_a_struct_belongs` and `security_map_where_a_sequence_belongs`
    /// record both refusals as Go's bytes; the two accepted siblings are here because a
    /// blanket "not a mapping" refusal is wrong in Go's unfavourable direction -- a `null`
    /// decodes to the zero value without ever asking for a mapping, and a real sequence of
    /// keys is what the writer emits.
    #[test]
    fn a_security_node_that_does_not_fit_its_field_fails_the_load() {
        for (body, refused) in [
            ("web:\n    brave: oops\n", true),
            ("web:\n    brave:\n        api_keys: {a: b}\n", true),
            ("web:\n    brave: null\n", false),
            ("web:\n    brave:\n        api_keys: [bk]\n", false),
        ] {
            let (dir, path) = write_temp(r#"{"version":3}"#);
            std::fs::write(dir.path().join(SECURITY_FILE), body).expect("security file");
            let outcome = load(&path, "/home/oracle");
            if refused {
                assert!(
                    matches!(outcome, Err(Error::SecurityType(_))),
                    "{body:?} should be refused, got {outcome:?}"
                );
            } else {
                assert!(
                    outcome.is_ok(),
                    "{body:?} should load, got {:?}",
                    outcome.err()
                );
            }
        }
    }

    /// Issue #15: `SecureStrings` is a plain sequence of strings, not a `FlexibleStringSlice`.
    ///
    /// Every refused spelling here is one the shipped binary refuses at the same position,
    /// measured one process per shape. The accepted siblings are part of the test because a
    /// blanket "must be an array" would be wrong in Go's unfavourable direction: `null` is
    /// answered before anything else and leaves the slice nil, an empty array is an empty
    /// slice, and a number is refused only where Go's element decode asks for a string.
    ///
    /// The `null` elements are the expensive rows. `SecureStrings.UnmarshalJSON` decodes into
    /// `[]*SecureString`, so a null element becomes a nil pointer that never reaches
    /// `SecureString.UnmarshalJSON`, and the filter at `config_struct.go:168-176` drops it --
    /// `[null]` is zero keys and the next `save` omits the field. Nothing in the fixture sees
    /// this: of its cases that spell `api_keys` as an array, none carries a null element, so a
    /// walk that judged null as a wrong element type would replay green while refusing a config
    /// the shipped binary loads. `[null, 42]` is here for the same reason in the other
    /// direction: Go blames the number, and skipping the nil is what names the same element.
    #[test]
    fn a_shape_secure_strings_cannot_hold_fails_the_load() {
        for (spelling, refused) in [
            (r#""sk-1""#, true),
            ("42", true),
            ("[42]", true),
            (r#"["a",42]"#, true),
            ("{}", true),
            ("true", true),
            (r#"["a","b"]"#, false),
            ("[]", false),
            ("null", false),
            ("[null]", false),
            (r#"[null,"a"]"#, false),
            (r#"["a",null]"#, false),
            ("[null,null]", false),
            ("[null,42]", true),
            ("[42,null]", true),
            ("[[null]]", true),
            ("[null,{}]", true),
            ("[1,null]", true),
        ] {
            let body = format!(
                r#"{{"version":3,"model_list":[{{"model_name":"m1","provider":"p","model":"m","api_keys":{spelling}}}]}}"#
            );
            let (_dir, path) = write_temp(&body);
            let outcome = load(&path, "/home/oracle");
            if refused {
                assert!(
                    matches!(outcome, Err(Error::TypeMismatch(_))),
                    "api_keys: {spelling} should be refused, got {outcome:?}"
                );
            } else {
                assert!(
                    outcome.is_ok(),
                    "api_keys: {spelling} should load, got {:?}",
                    outcome.err()
                );
            }
        }
    }

    /// The same field in `.security.yml` follows yaml's rule, which is *not* the document's:
    /// the field has to be a sequence, but its elements go through `SecureString`'s raw-text
    /// decoder, so a number inside the array loads while a bare number at the field is refused
    /// as `cannot unmarshal !!int `42` into config.SecureStrings`. Both halves are pinned
    /// because one predicate for the two files gets one of them backwards.
    ///
    /// The `m9` rows exist because the document lists only `m1`, so those entries name no model
    /// the assignment loop will ever visit -- and `SecureModelList.UnmarshalYAML` decodes the
    /// whole map and returns its error before that loop runs. "An entry naming no model is
    /// ignored" is a true statement about the assignment and a false one about the load, and
    /// this is the only place the distinction is pinned. The `m9:0:` null row is the other side:
    /// a null decodes to a nil `*ModelConfig` and the loop skips it, so it loads.
    #[test]
    fn a_security_api_keys_that_is_not_a_sequence_fails_the_load() {
        let document = r#"{"version":3,"model_list":[{"model_name":"m1","provider":"p","model":"m","api_keys":["sk-doc"]}]}"#;
        for (body, refused) in [
            ("model_list:\n    m1:0:\n        api_keys: 42\n", true),
            ("model_list:\n    m1:0:\n        api_keys: sk-sec\n", true),
            ("model_list:\n    m1:0:\n        api_keys: {a: b}\n", true),
            ("model_list:\n    m1:0:\n        api_keys: [42]\n", false),
            (
                "model_list:\n    m1:0:\n        api_keys: [sk-sec]\n",
                false,
            ),
            ("model_list:\n    m1:0:\n        api_keys: null\n", false),
            // Entries the document never asked for, judged by the decode all the same.
            ("model_list:\n    m9:0:\n        api_keys: 42\n", true),
            ("model_list:\n    m9:\n        api_keys: sk-sec\n", true),
            (
                "model_list:\n    m1:0:\n        api_keys: [ok]\n    m9:0:\n        api_keys: 42\n",
                true,
            ),
            (
                "model_list:\n    m1:0:\n        api_keys: [ok]\n    m9:0: 42\n",
                true,
            ),
            ("model_list:\n    m9:0:\n", false),
            ("model_list:\n    m9:0:\n        api_keys: [42]\n", false),
            // A null *element* is permissive here as well, for a different reason than in the
            // document: yaml has no filter to drop it, so Go keeps a nil `*SecureString`. Only
            // the verdict is pinned; what a save then writes for a nil element is a Go-side
            // oddity this port does not claim to match, and no corpus case reaches it.
            ("model_list:\n    m1:0:\n        api_keys: [null]\n", false),
            // A scalar into a string field is what yaml.v3 does without complaint, so an
            // unmatched entry with a wrong-typed *string* stays a load.
            ("model_list:\n    m9:0:\n        provider: 42\n", false),
        ] {
            let (_dir, path) = write_temp(document);
            std::fs::write(path.parent().expect("config dir").join(SECURITY_FILE), body)
                .expect("security file");
            let outcome = load(&path, "/home/oracle");
            if refused {
                assert!(
                    matches!(outcome, Err(Error::SecurityType(_))),
                    "{body:?} should be refused, got {outcome:?}"
                );
            } else {
                assert!(
                    outcome.is_ok(),
                    "{body:?} should load, got {:?}",
                    outcome.err()
                );
            }
        }
    }

    /// The same document rule at a *second* position, pinned on purpose.
    ///
    /// The walk finds this type through the schema rather than a list of field names, which is
    /// what lets it gain or lose a position without a single name changing. The dump holds five
    /// `SecureStrings` nodes: `model_list[].api_keys` and the four under `tools.web`. `brave`
    /// stands for those four, and no corpus case reaches any of them -- so without this row the
    /// walk could stop judging four of the five positions and still replay green. Measured at
    /// picoclaw `main`: `42`, a bare string and `[42]` refuse here exactly as they do in
    /// `model_list`, and `[null]` loads there too.
    #[test]
    fn a_web_api_keys_position_is_judged_by_the_same_walk() {
        for (spelling, refused) in [
            ("42", true),
            (r#""sk-web""#, true),
            ("[42]", true),
            (r#"["sk-web"]"#, false),
            ("[null]", false),
            ("null", false),
        ] {
            let body = format!(
                r#"{{"version":3,"model_list":[{{"model_name":"m1","provider":"p","model":"m"}}],"tools":{{"web":{{"enabled":true,"brave":{{"api_keys":{spelling}}}}}}}}}"#
            );
            let (_dir, path) = write_temp(&body);
            let outcome = load(&path, "/home/oracle");
            if refused {
                assert!(
                    matches!(outcome, Err(Error::TypeMismatch(_))),
                    "web.brave api_keys: {spelling} should be refused, got {outcome:?}"
                );
            } else {
                assert!(
                    outcome.is_ok(),
                    "web.brave api_keys: {spelling} should load, got {:?}",
                    outcome.err()
                );
            }
        }
    }

    /// The unmatched-entry decode belongs to the current-version path and not to the migration
    /// one, and the pair is pinned because one rule for both paths is wrong on one of them --
    /// the same trap the legacy `channel_list` pair pins.
    ///
    /// `LoadConfig`'s `case 0..=2` reaches the security file as plain data and folds it with
    /// `mergeModelListsWithMap`, which reads the map per model rather than decoding it whole, so
    /// an entry naming no model is never seen. Measured: the two files that refuse at v3 load at
    /// v2, with Go logging `model_name not found in main config: m9:0` and leaving the
    /// document's keys alone.
    #[test]
    fn the_migration_path_never_decodes_an_unmatched_security_entry() {
        let document = r#"{"version":2,"model_list":[{"model_name":"m1","provider":"p","model":"m","api_keys":["sk-doc"]}]}"#;
        for body in [
            "model_list:\n    m9:0:\n        api_keys: 42\n",
            "model_list:\n    m9:0: 42\n",
            "model_list:\n    m9:0:\n        api_keys: {a: b}\n",
        ] {
            let (_dir, path) = write_temp(document);
            std::fs::write(path.parent().expect("config dir").join(SECURITY_FILE), body)
                .expect("security file");
            let outcome = load(&path, "/home/oracle");
            assert!(
                outcome.is_ok(),
                "v2 {body:?} should load, got {:?}",
                outcome.err()
            );
        }
    }

    fn write_temp(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.json");
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(body.as_bytes()).expect("write");
        (dir, path)
    }

    /// The invariant the security merge's readability gate rests on.
    ///
    /// `YamlField` carries two spellings on purpose -- `json`, the key in the document, and
    /// `name`, the key `yaml.v3` writes -- and `.security.yml` is written and read in the
    /// second one while `config.json` holds the first. The gate therefore has to compare the
    /// file's key against `name` and then merge into `json`, which is what the code does.
    ///
    /// Today the two columns agree for **every field this path can gate**, because each of
    /// them carries an explicit `yaml:"snake_case"` tag; 96 of the dump's 260 yaml fields do
    /// not, and they are all in subtrees the walk never enters with a schema. That is why the
    /// 73 cases cannot see the distinction and why this assertion exists instead: the first
    /// extension that reaches an untagged Go struct through a schema silently changes which
    /// keys are readable, and this fails loudly at the schema instead of grading green on the
    /// wrong column. `ModelConfig` is the known exclusion -- a security entry is read for
    /// `api_keys` alone, on both the current-version path and the migration one -- so it is
    /// named rather than silently skipped.
    #[test]
    fn every_field_the_security_gate_reads_is_spelled_the_same_in_both_files() {
        fn walk(schema: &Schema, path: &str, out: &mut Vec<String>) {
            for field in schema.yaml_fields() {
                if field.json != field.name {
                    out.push(format!(
                        "{path}.{} is written as `{}`",
                        field.json, field.name
                    ));
                }
                if let Some(child) = schema.field(field.json) {
                    walk(child, &format!("{path}.{}", field.json), out);
                    if let Some(elem) = child.elem() {
                        walk(elem, &format!("{path}.{}[]", field.json), out);
                    }
                }
            }
        }

        let schema = config_schema();
        let mut drifted = Vec::new();
        for field in schema.yaml_fields() {
            if field.json == "model_list" {
                continue;
            }
            if field.json != field.name {
                drifted.push(format!(
                    "{}.{} is written as `{}`",
                    "config", field.json, field.name
                ));
            }
            if let Some(child) = schema.field(field.json) {
                walk(child, field.json, &mut drifted);
                if let Some(elem) = child.elem() {
                    walk(elem, &format!("{}[]", field.json), &mut drifted);
                }
            }
        }

        assert!(
            drifted.is_empty(),
            "the security merge gates readability on YamlField.name and merges into YamlField.json, which is only behaviour-neutral while the two agree. These gated fields now disagree, so a `.security.yml` key stops being readable (or becomes readable) depending on which column is asked: {drifted:?}"
        );
    }

    /// The security walk has exactly three sections it can be asked about, and the tail of
    /// its loop -- the lookup that asks the file for a field by its yaml spelling -- is
    /// therefore unreachable today: `model_list` and `channel_list` are each handled before
    /// it, and `tools` is inlined so it never appears as a key of its own.
    ///
    /// Asserted rather than commented because the branch is not wrong, only unwitnessed: a
    /// fourth yaml section in the dump would make it live, and no case would say so. The
    /// corpus pins the boundary from the other side --
    /// `security_agents_section_is_not_readable_from_the_file` records that a section outside
    /// these three is not merely unknown to the decoder but `yaml:"-"` and unreadable, so a
    /// port that walked the JSON field list would apply `agents` and diverge on every field
    /// inside it.
    #[test]
    fn the_security_walk_has_exactly_the_three_sections_it_handles() {
        let mut names: Vec<&str> = config_schema()
            .yaml_fields()
            .iter()
            .map(|field| field.name)
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec!["channel_list", "model_list", "tools"],
            "a fourth yaml section makes apply_security's tail lookup live, unwitnessed, and \
             in need of a case before it is trusted"
        );
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

    /// Go restores the filtered `model_list` on a `defer`, so a save that fails still hands
    /// the caller back a whole config. The `?`s `save` used to carry returned early with the
    /// caller's real models still removed, and the next save on that same config would then
    /// write a `model_list` missing a primary -- a silent config edit caused by a failed
    /// write, which is the one thing a failed write must never do.
    #[test]
    fn a_failed_save_leaves_the_callers_config_whole() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");
        std::fs::write(
            &path,
            "{\"version\":3,\"model_list\":[{\"model_name\":\"m\",\"provider\":\"p\",\"model\":\"q\",\"api_keys\":[\"a\",\"b\"]}]}",
        )
        .expect("write config.json");
        let mut cfg = load(&path, "/home/oracle").expect("the config must load");
        assert_eq!(
            cfg.document
                .get("model_list")
                .and_then(Doc::as_array)
                .map(Vec::len),
            Some(2),
            "a two-key model should have virtualised into a copy and a primary"
        );

        // A directory that does not exist, rather than one with a mode that forbids writes:
        // CI runs the suite as root, and root walks straight through `0o500`.
        let unwritable = dir.path().join("gone/config.json");
        let failed = save(&unwritable, &mut cfg, "/home/oracle");

        assert!(failed.is_err(), "a missing directory must fail the save");
        assert_eq!(
            cfg.document
                .get("model_list")
                .and_then(Doc::as_array)
                .map(Vec::len),
            Some(2),
            "the failed save left the caller's config with its virtual entries filtered out"
        );
    }

    /// The secret half of the same promise, and the one no `save`-op case can grade.
    ///
    /// `save` swaps each registry's real `auth_token` into the document so the yaml writer
    /// can print it -- the document normally holds the `[NOT_HERE]` placeholder that
    /// `SkillRegistryConfig.MarshalJSON` produces -- and puts the placeholder back before
    /// `config.json` is marshalled. On the failure path that is a *second* restore, and
    /// without it the caller keeps a document that renders its own credential: the loaded
    /// value prints it, and the retry writes it into `config.json`, the file that is not the
    /// secrets file. The model-list half above cannot see this; the two restores are
    /// different calls on different paths.
    #[test]
    fn a_failed_save_does_not_hand_back_a_real_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");
        std::fs::write(
            &path,
            concat!(
                "{\"version\":3,\"tools\":{\"skills\":{\"registries\":{\"github\":",
                "{\"enabled\":true,\"base_url\":\"https://github.com\"}}}}}"
            ),
        )
        .expect("write config.json");
        // The token has to arrive through the security file. A token the *document* carries
        // is already in the document as its real text -- the placeholder is a rendering rule,
        // not a stored one -- so only a file-sourced token is the one `save` swaps in and
        // back out.
        std::fs::write(
            dir.path().join(SECURITY_FILE),
            "skills:\n  registries:\n    github:\n      auth_token: ghp_sec\n",
        )
        .expect("write .security.yml");
        let mut cfg = load(&path, "/home/oracle").expect("the config must load");

        let token = |cfg: &Config| {
            cfg.document
                .get("tools")
                .and_then(|tools| tools.get("skills"))
                .and_then(|skills| skills.get("registries"))
                .and_then(|registries| registries.get("github"))
                .and_then(|github| github.get("auth_token"))
                .and_then(Doc::as_str)
                .map(str::to_string)
        };
        assert_eq!(
            token(&cfg).as_deref(),
            Some("[NOT_HERE]"),
            "the loaded document must hold the placeholder, not the credential"
        );

        let unwritable = dir.path().join("gone/config.json");
        assert!(
            save(&unwritable, &mut cfg, "/home/oracle").is_err(),
            "a missing directory must fail the save"
        );
        assert_eq!(
            token(&cfg).as_deref(),
            Some("[NOT_HERE]"),
            "the failed save handed the caller a document holding its own token"
        );
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
    fn a_matching_entry_without_keys_clears_them_when_migrated_too() {
        // The migrated path reaches the same rule by a different function, and the port had
        // it only on the typed one. `mergeModelListsWithMap` (migration.go:521) assigns
        // `mVal["api_keys"] = vv["api_keys"]`, and a missing key in `vv` yields nil -- so a
        // matching entry that names no keys clears the model's keys there as well. Measured
        // at picoclaw `1a4e1edf`, one process per scenario, against a document whose model
        // starts with `sk-original`:
        //
        // | version | entry | Go's `api_keys` |
        // | --- | --- | --- |
        // | 3 | `m1:0: {}` | cleared |
        // | 3 | `m1: {provider: other}` | cleared |
        // | 2 | `m1:0: {}` | cleared |
        // | 2 | `m1: {provider: other}` | cleared |
        //
        // Skipping a keyless match instead -- the tempting reading of "the file supplies
        // each model's keys" -- leaves `sk-original` standing, which is a config Go does not
        // produce, and it survives on the current version only because the typed pass has
        // its own copy of the rule.
        for version in ["2", "3"] {
            let config = r#"{"version":%VERSION%,"model_list":[
                {"model_name":"m1","model":"x","provider":"openai","api_keys":["sk-original"]}]}"#;
            for spelling in ["m1:0: {}", "m1: {provider: other}"] {
                let (_dir, path) = write_pair(
                    &config.replace("%VERSION%", version),
                    &format!("model_list:\n  {spelling}\n"),
                );
                let cfg = load(&path, "/home/oracle").expect("the pair loads");
                assert_eq!(
                    model_field(&cfg.document, 0, "api_keys"),
                    None,
                    "v{version} with `{spelling}` must clear the keys, not leave them alone"
                );
            }
        }
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
    fn a_null_section_is_left_for_the_validator_even_when_its_sibling_is_lifted() {
        // The per-key half of the lift's guard. Go's outer test is `m2["web"] != nil ||
        // m2["skills"] != nil`, but each branch then asks the same question about *its own*
        // key (`migration.go:429`, `:433`), so a null section is never lifted and the strict
        // validator names it. Measured against Go at `f03fbd20`, one process per shape, on a
        // legacy document that is valid at both versions (`model_name` *and* `model`, because
        // `ModelConfig.Validate` requires both):
        //
        //   web: (null) + skills: mapping  -> unknown field(s): web
        //   web: mapping + skills: (null)  -> unknown field(s): skills
        //   both null                      -> unknown field(s): skills, web
        //   tools: {} alone                -> loads
        //
        // The mixed rows are the whole point: the outer guard is satisfied either way, so a
        // lift that tests only presence loads a document Go refuses.
        let legacy = r#"{"version":2,"model_list":[{"model_name":"m1","model":"openai/gpt-4o"}]}"#;

        let (_dir, path) = write_pair(legacy, "web:\nskills:\n  github:\n    token: gh\n");
        let err = load(&path, "/home/oracle").expect_err("a null `web` is still a key");
        assert!(
            matches!(&err, Error::UnknownField(paths) if paths == "web"),
            "Go refuses `unknown field(s): web`: {err}"
        );

        let (_dir, path) = write_pair(legacy, "web:\n  brave:\n    api_keys: [bk]\nskills:\n");
        let err = load(&path, "/home/oracle").expect_err("a null `skills` is still a key");
        assert!(
            matches!(&err, Error::UnknownField(paths) if paths == "skills"),
            "Go refuses `unknown field(s): skills`: {err}"
        );

        // Both null: the lift does not run at all, and each key is named on its own. Go's
        // order is `skills, web`; the port's is whatever the document holds, so the assert
        // names both without pinning an order Go gets from a map.
        let (_dir, path) = write_pair(legacy, "web:\nskills:\n");
        let err = load(&path, "/home/oracle").expect_err("neither null lifts");
        assert!(
            matches!(&err, Error::UnknownField(paths)
                if paths.contains("web") && paths.contains("skills")),
            "both nulls are named: {err}"
        );

        // Control: with no null in the file the same two sections lift and load, so the three
        // refusals above are about `null` and not about a legacy document carrying them.
        let (_dir, path) = write_pair(
            legacy,
            "web:\n  brave:\n    api_keys: [bk]\nskills:\n  github:\n    token: gh\n",
        );
        load(&path, "/home/oracle").expect("two present sections lift, as they always did");
    }

    #[test]
    fn the_web_section_of_the_security_file_reaches_tools() {
        // `Tools` is `yaml:",inline"`, so the file's top-level `web:` is a `tools` field and Go
        // applies it. This port reached the section and then dropped it, because the inline walk
        // resolved field knowledge at the root: `web` is a field of `Tools`, one level down. The
        // entry recording that in `docs/DIVERGENCES.md` is deleted by this commit and this is the
        // pin that replaced it.
        //
        // What each fault costs, measured one fault per run with the other 102 lib tests green:
        // leaving `web` out of the inline walk fails this test *and*
        // `a_security_node_that_does_not_fit_its_field_fails_the_load`; handing `merge_filling`
        // the *root* schema fails the same two; handing it no child schema fails only the refusal
        // test. So the walk has two witnesses and this is not a unique one -- what this
        // assertion alone owns is that the value **lands with the right shape**, which the
        // refusal test does not claim either way.
        //
        // The `skills` half of the same section is deliberately not asserted here: it never goes
        // through `merge_filling` -- `skills::apply` rebuilds it -- and its own tests, starting at
        // `a_null_registries_header_in_the_file_wipes_to_the_builtins_at_zero_values`, pin what
        // the file's `skills` node does to the registries.
        let (_dir, path) = write_pair(
            ONE_MODEL,
            "web:\n  brave:\n    api_keys: [bk-from-security]\n",
        );
        let cfg = load(&path, "/home/oracle").expect("the pair loads");
        let tools = cfg.document.get("tools").expect("tools is in the defaults");
        let api_keys: Vec<&str> = tools
            .get("web")
            .and_then(|w| w.get("brave"))
            .and_then(|b| b.get("api_keys"))
            .and_then(Doc::as_array)
            .map(|items| items.iter().filter_map(Doc::as_str).collect())
            .unwrap_or_default();
        assert_eq!(
            api_keys,
            vec!["bk-from-security"],
            "the security file's search key lands on `tools.web.brave.api_keys`"
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
        // What each fault costs, measured one fault per run with the other 102 lib tests green:
        // leaving `web` out of the inline walk fails this test *and*
        // `a_security_node_that_does_not_fit_its_field_fails_the_load`; handing `merge_filling`
        // the *root* schema fails the same two; handing it no child schema fails only the refusal
        // test. So the walk has two witnesses and this is not a unique one -- what this
        // assertion alone owns is that the value **lands with the right shape**, which the
        // refusal test does not claim either way.
        //
        // The `skills` half of the same section is deliberately not asserted here: it never goes
        // through `merge_filling` -- `skills::apply` rebuilds it -- and its own tests, starting at
        // `a_null_registries_header_in_the_file_wipes_to_the_builtins_at_zero_values`, pin what
        // the file's `skills` node does to the registries.
        let (_dir, path) = write_pair(
            ONE_MODEL,
            "web:\n  brave:\n    api_keys: [bk-from-security]\n",
        );
        let cfg = load(&path, "/home/oracle").expect("the pair loads");
        let tools = cfg.document.get("tools").expect("tools is in the defaults");
        let api_keys: Vec<&str> = tools
            .get("web")
            .and_then(|w| w.get("brave"))
            .and_then(|b| b.get("api_keys"))
            .and_then(Doc::as_array)
            .map(|items| items.iter().filter_map(Doc::as_str).collect())
            .unwrap_or_default();
        assert_eq!(
            api_keys,
            vec!["bk-from-security"],
            "the security file's search key lands on `tools.web.brave.api_keys`"
        );
    }

    #[test]
    fn the_legacy_data_merge_lifts_web_and_skills_into_tools() {
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
    fn the_legacy_data_merge_rewrites_both_registry_spellings_and_keeps_their_asymmetry() {
        // The rewrite lives in the data merge now, because the data merge is what carries a
        // legacy document's security file into the config: `LoadConfig` reaches
        // `loadSecurityConfig` only at `CurrentVersion`, so `load_config_map` is the one
        // place these two spellings are rewritten for a migrated document. Asking it
        // directly is what makes each assertion a fact about the shipped path rather than
        // about a validator input.
        let view = |security: &str| {
            load_config_map(
                &Doc::Object(Vec::new()),
                &yaml::parse(security)
                    .expect("the security file parses")
                    .document,
            )
            .expect("the data merge succeeds")
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
