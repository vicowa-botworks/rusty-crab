//! The security file's `skills` section, which is two passes and neither one is a merge.
//!
//! `applySecurityConfig` (`pkg/config/security.go`) reaches `skills` twice, and the second
//! time is not a second look at the same thing -- it is a different rule with different
//! inputs:
//!
//! 1. **`yaml.Unmarshal(data, cfg)`**, which sees only what the yaml tags allow. Inside
//!    [`SkillsToolsConfig`] that is exactly two keys: `registries` (a custom
//!    `UnmarshalYAML` that clones the entry of the same name and decodes into it) and
//!    `github` (whose only yaml-visible field is `token`, a `SecureString`). Everything
//!    else in the file's `skills` mapping -- `enabled`, `max_concurrent_searches`, and
//!    every legacy per-registry key -- has `yaml:"-"` or no field at all, so the yaml pass
//!    drops it. `ToolConfig` is embedded with `yaml:"-"`, which is why a security file
//!    cannot turn a tool on.
//! 2. **`applyLegacySkillsSecurityConfig`** (`security.go:96`), which walks the file's
//!    `skills` mapping by hand and treats every key except `registries` as a registry in
//!    its own right. This is the pass that can *create* a registry the config never
//!    mentioned, and it is the reason a legacy `skills.github.token` shows up in the loaded
//!    value **twice**: once as `auth_token`, masked, and once as `token`, in plaintext.
//!
//! The plaintext half is not a bug this port is preserving by accident.
//! `SkillRegistryConfig.MarshalJSON` (`config_struct.go:503`) hand-builds a
//! `map[string]any` and marshals that, so it never consults an omit option and re-emits
//! every `Param` key raw. A port that masked `Param` would leak nothing and would diverge
//! from Go byte for byte, which is why the corpus pins the leak rather than the mask.
//!
//! Both passes land in the same place: `tools.skills.registries`, which the loaded value
//! renders as a name-keyed object because `SkillsRegistriesConfig.MarshalJSON` builds a
//! `map[string]SkillRegistryConfig` -- so the order entries were added in is not
//! observable, only their contents.
//!
//! ## What the corpus cannot see
//!
//! Injecting faults into this module and replaying the config seam leaves faults that no
//! case fails, and they are not all the same kind of thing -- an equivalence, a survivor, and
//! a gap need different responses. Re-derived at this commit rather than carried forward,
//! because the last tally here was wrong in both directions:
//!
//! * **Writing `auth_token` over one that is already set is a survivor, not an equivalence.**
//!   Making the legacy pass write unconditionally (dropping `if current.auth_token.is_empty()`)
//!   leaves the unit tests and the replay green, because every `SecureString` marshals to the
//!   same `[NOT_HERE]` -- but the *effective* credential differs, and the effective credential
//!   is exactly what `save` writes back to `.security.yml`. This seam has already carried one
//!   bug of that shape (`security_registry_token_save_splits_masked_and_real`), so "invisible
//!   in the loaded value" is not a claim of equivalence, only of where the witness has to
//!   live: a `save`-side case. Until one exists this is an uncovered branch, and it should be
//!   read that way rather than as harmless.
//! * **Letting the file's `github.token` win over one already in config.json is not a fault at
//!   all any more.** It has been the shipped behaviour since the file's value was made to
//!   *replace* the document's, and its opposite (fill-only) is killed by
//!   `the_files_github_token_replaces_the_documents`. It stayed on this list after that commit
//!   changed what it described, which is how a counted "equivalent" survived a round.
//! * **Dropping the `registries` skip is a gap, not an equivalent.** Go refuses a file
//!   whose legacy skills value is not a mapping -- `valueNode.Decode` into a
//!   `SkillRegistryConfig` decodes into a `map[string]any`, and a scalar is not one. This
//!   module answers a non-mapping node by ignoring it, so it loads a file the shipped
//!   binary rejects. `security_a_scalar_under_registries_loads_unchanged` pins the
//!   behaviour *with* the skip, which is why the fault still replays green: the port
//!   never reaches the refusal the skip exists to avoid. Recorded in
//!   `docs/DIVERGENCES.md` rather than fixed here, because refusing needs an error type
//!   on this pass and no case yet pins which diagnostic wins.

use crate::doc::Doc;
use crate::yaml::Security;
use crate::Error;

/// What `SkillRegistryConfig.MarshalJSON` writes for any non-empty `SecureString`.
const NOT_HERE: &str = "[NOT_HERE]";

/// A registry as Go holds it: the four named fields plus the open `Param` map.
///
/// `Param` is where every key that is not one of the four lands, and it is also what
/// marshals back out -- there is no `param` key in the JSON. So the round trip is lossy
/// in one direction only: a config file that writes `param: {a: 1}` comes back as `a: 1`.
#[derive(Debug, Clone, Default)]
struct Registry {
    enabled: bool,
    base_url: String,
    auth_token: String,
    params: Vec<(String, Doc)>,
}

impl Registry {
    /// Reads one yaml/JSON node into `self`, the way `SkillRegistryConfig.UnmarshalYAML`
    /// does: `param` first, then every other key, with the later key winning.
    ///
    /// The order is not cosmetic. Go merges the nested `param` map into `params` before
    /// its loop over the decoded map, so a key that appears both nested and at the top
    /// level ends up with the top-level value -- and because that loop walks a Go map,
    /// two *nested* keys have no order at all, which is why the output is sorted at
    /// marshal time rather than here.
    fn read(&mut self, node: &Doc) {
        let Doc::Object(entries) = node else {
            // A scalar or sequence where a mapping belongs. Go's decode into
            // `SkillRegistryConfig` fails outright -- `skills: {github: ghp_direct}` is a
            // config the shipped binary will not load -- while this port declines the node
            // and carries on loading, which is the divergence recorded under "loads a
            // non-mapping skills value Go refuses" in `docs/DIVERGENCES.md`. What matters
            // here is what this arm does *not* do: printing the node and keeping it as a
            // token would manufacture a credential Go refuses to have.
            return;
        };
        if let Some(Doc::Object(nested)) =
            entries.iter().find(|(k, _)| k == "param").map(|(_, v)| v)
        {
            for (k, v) in nested {
                self.set_param(k, v);
            }
        }
        for (k, v) in entries {
            match k.as_str() {
                "enabled" => {
                    if let Doc::Bool(b) = v {
                        self.enabled = *b;
                    }
                }
                "base_url" => {
                    if let Doc::String(s) = v {
                        self.base_url = s.clone();
                    }
                }
                "auth_token" => {
                    // A yaml null is not a value: `yaml.v3` short-circuits `!!null` before it
                    // asks a custom unmarshaler, so `SecureString.UnmarshalYAML` never sees
                    // the node and the field keeps what the decode is writing *into*. `""` is
                    // a value and does clear. The two assignment sites in this pass need the
                    // same guard; `a_null_leaves_a_credential_the_document_already_holds`
                    // pins both, and pins the empty string beside them so the pair cannot
                    // agree by construction.
                    //
                    // The JSON document is the opposite rule, and this function reads both:
                    // `encoding/json` does call `UnmarshalJSON` for `null`, and
                    // `SecureString.fromRaw("")` resolves it to empty. That is invisible
                    // here because the document side always starts from
                    // `Registry::default()`, where keep and clear are the same string.
                    if !matches!(v, Doc::Null) {
                        self.auth_token = scalar_text(v);
                    }
                }
                // Hydrates the SecureString only; never persisted as a param.
                "_auth_token" | "param" | "name" => {}
                _ => self.set_param(k, v),
            }
        }
    }

    fn set_param(&mut self, key: &str, value: &Doc) {
        match self.params.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = value.clone(),
            None => self.params.push((key.to_string(), value.clone())),
        }
    }

    /// The object `SkillRegistryConfig.MarshalJSON` writes: `enabled` and `base_url`
    /// always, `auth_token` when set, then every `Param` key that survives the three
    /// skips -- and the whole thing sorted, because it is one Go map on the way out.
    fn to_doc(&self) -> Doc {
        let mut out: Vec<(String, Doc)> = vec![
            ("base_url".to_string(), Doc::String(self.base_url.clone())),
            ("enabled".to_string(), Doc::Bool(self.enabled)),
        ];
        if !self.auth_token.is_empty() {
            // The hand-written placeholder, and the reason it survives the walk: the
            // document holds an *object* under `registries`, whose schema is a slice that
            // is not a JSON array, so `apply_omit` falls to its passthrough arm and never
            // consults `is_dropped_by_omit`. Normalise this document to an array some day
            // and the `SecureString` arm in `marshal.rs` will eat this key -- the two
            // changes are load-bearing for each other, which is why both say so.
            out.push(("auth_token".to_string(), Doc::String(NOT_HERE.to_string())));
        }
        for (k, v) in &self.params {
            if k.is_empty() || k == "param" || k.starts_with('_') {
                continue;
            }
            if out.iter().any(|(ek, _)| ek == k) {
                // A param cannot displace one of the three keys the marshaler writes
                // itself -- `if _, exists := m[key]; exists { continue }`.
                continue;
            }
            out.push((k.clone(), v.clone()));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Doc::Object(out)
    }
}

/// A `SecureString` read out of the file.
///
/// `SecureString.UnmarshalYAML` is `fromRaw(node.Value)`, and the registry path reaches it
/// through `yaml.Marshal(v)` of whatever the generic decode produced -- so a scalar of any
/// type arrives as its printed text (`true`, not a bool), and a mapping or sequence node
/// has an empty `Value` and reads as unset. What is *not* modelled here is `resolveKey`:
/// an `enc://` or `file://` reference is kept as the opaque text it is, so its emptiness is
/// the reference's emptiness rather than the secret's. The corpus has no key material and
/// clears the environment, so that half is unpinnable and stays so.
///
/// A null is the one shape that never reaches `UnmarshalYAML` at all: yaml.v3 short-circuits
/// `!!null` for a type with a custom unmarshaler and zeroes the target, so `fromRaw` is
/// never called and the `SecureString` stays empty. Printing the node would give `"null"`,
/// which is a credential. `a_null_or_empty_legacy_token_creates_no_credential` pins the
/// registry existing with no `auth_token` key at all; the corpus cases of the same shape
/// (`security_legacy_null_token_creates_no_credential`,
/// `security_legacy_empty_token_creates_no_credential`) exist only at picoclaw `origin/main`,
/// so until the fixture moves the unit test is the whole pin. Numbers are the opposite case:
/// `42` and `1.5` are both printed scalars, so both create one.
fn scalar_text(node: &Doc) -> String {
    match node {
        Doc::String(s) => s.clone(),
        Doc::Bool(true) => "true".to_string(),
        Doc::Bool(false) => "false".to_string(),
        Doc::Int(i) => i.to_string(),
        Doc::Float(f) => crate::doc::go_number(*f),
        Doc::Null => String::new(),
        _ => String::new(),
    }
}

/// Applies both passes to a document the JSON loader already settled.
///
/// Hands back the `auth_token` each surviving registry really holds. The document cannot
/// carry it: `SkillRegistryConfig.MarshalJSON` writes the literal `[NOT_HERE]` for that key,
/// and the port's document *is* the JSON rendering, so the secret has nowhere to live once
/// the pass is done. `saveSecurityConfig` writes the other rendering -- `yaml.Marshal` asks
/// `SecureString` itself, which answers with the value -- so the one file whose entire purpose
/// is holding secrets would otherwise record a placeholder. Go keeps the real value in the
/// struct and masks only at marshal time; with the document standing in for the struct, the
/// mask has to be undone by the save path from this list. Same reason `Config::virtual_models`
/// exists: state the loader knows and the document cannot hold.
///
/// [`normalise_document`] has already run on that path by the time this is called, so the
/// document's `registries` is a mapping and the baseline arm below cannot fire here. It is
/// kept identical rather than split in two because the two entry points differ only in
/// whether the file passes run, and a reader should not have to prove that twice.
pub fn apply(
    merged: &mut Doc,
    security: &Security,
    baseline: Option<&Doc>,
) -> Result<Vec<(String, String)>, Error> {
    rebuild(merged, Some(security), baseline)
}

/// The document-side half on its own: the pass Go runs **during** the JSON unmarshal, before
/// the security file is opened at all.
///
/// This is the whole difference between "the file says nothing about `skills`" and "there is
/// no file". The first is a `Security` with an empty document and the second is no `Security`;
/// both leave the two merge passes with nothing to do, and only the second used to skip this
/// rebuild as well -- so whether `config.json` came back normalised depended on whether an
/// unrelated file happened to exist, and the common install has no `.security.yml` at all.
///
/// `baseline` is the `tools.skills.registries` node from `default_config` **before** the
/// document was merged over it, because Go decodes into the defaults and a document whose
/// `registries` is not a mapping leaves them standing:
///
/// | document `registries` | Go's loaded value |
/// | --- | --- |
/// | a mapping | that mapping, merged over the builtins and normalised |
/// | `null` | `clawhub` + `github` at their **defaults** -- the same answer as an array |
/// | an array | the array ignored, the builtins standing at their **defaults** |
/// | a number | refused outright, see the scalar arm in [`rebuild`] |
/// | absent | untouched -- Go's decoder is never called for a key that is not there |
///
/// Measured at picoclaw `01635da3`, one process per shape, no `.security.yml` on disk:
/// `null`, `[{enabled:true,name:github}]` and an absent key all give
/// `{clawhub:{base_url:"https://clawhub.ai",enabled:true}, github:{...}}`, and a mapping
/// `{"custom":{base_url:"u"}}` keeps both builtins and adds `custom` at zero values.
///
/// **Do not read the `null` row as the file's null header.** A `registries:` with nothing
/// after the colon in `.security.yml` is a different pass and a different answer -- the
/// baseline's *names* at **zero** values, with the document's own registries gone. That one
/// is pinned by `a_null_registries_header_in_the_file_wipes_to_the_builtins_at_zero_values`;
/// this pass never wipes, and the two are the easiest pair on this seam to confuse.
pub fn normalise_document(merged: &mut Doc, baseline: Option<&Doc>) -> Vec<(String, String)> {
    // The `Err` half is unreachable through this entry point: the refusal inside [`rebuild`]
    // needs a `skills` node *in the security file*, and there is no file here.
    //
    // The token list is NOT discarded. This is the pass that masks a document's own
    // `registries.*.auth_token`, so on its own it is the only place the effective credential
    // is still in hand -- which stopped being theoretical the moment the migration path
    // started running it: `load_config_map` merges the security file in as data, so a legacy
    // `skills.github.token` arrives here already lifted into `registries.github.auth_token`,
    // and the typed pass that would otherwise collect it is skipped for a migrated document
    // (`apply_security` returns an empty list under `migrated`). Dropping it wrote the literal
    // `[NOT_HERE]` into the user's `.security.yml` on the next save -- caught by the corpus
    // case `security_legacy_token_on_the_migration_path`.
    rebuild(merged, None, baseline).unwrap_or_default()
}

fn rebuild(
    merged: &mut Doc,
    security: Option<&Security>,
    baseline: Option<&Doc>,
) -> Result<Vec<(String, String)>, Error> {
    // A value that is not a mapping fails the whole load, and `null` is not one of them.
    // Go decodes this section into the typed `SkillsToolsConfig`, so yaml.v3 refuses a
    // scalar, a sequence and a number -- three shapes, three corpus cases, because a port
    // that handles the scalar still accepts the other two. A null it unmarshals into the
    // zero value without complaint, which is why "refuse anything that is not an object" is
    // wrong in the other direction: it rejects `skills: null`, a file the shipped binary
    // loads. Pinned by `security_skills_null_loads_unchanged`. Gated on there being a file
    // at all, because the document-side entry point has no `skills` node to refuse.
    if let Some(file_skills) = security.and_then(|file| file.document.get("skills")) {
        if !matches!(file_skills, Doc::Object(_) | Doc::Null) {
            return Err(Error::SecurityType(format!(
                "cannot unmarshal {} into config.SkillsToolsConfig",
                go_yaml_kind(file_skills)
            )));
        }
    }

    let Some(target) = merged
        .get_mut_at("tools")
        .and_then(|tools| tools.get_mut_at("skills"))
    else {
        return Ok(Vec::new());
    };

    // The gate is the *document*, not the security file. Go runs `SkillsRegistriesConfig`'s
    // decoder whenever `tools.skills.registries` is there to decode, and the file only decides
    // whether the two merge passes below run; returning here when the file has no `skills`
    // section made whether `config.json` is normalised depend on whether an unrelated file
    // happens to exist -- and the common install has no `.security.yml` at all.
    let file_skills = match security.and_then(|s| s.document.get("skills")) {
        Some(node @ Doc::Object(_)) => Some(node),
        // A non-mapping `skills` value is the divergence recorded under "loads a non-mapping
        // skills value Go refuses": no pass below can read it, and the doc-side rebuild still
        // runs, which is the half that has nothing to do with the file.
        _ => None,
    };

    // The registries the document already carries, in the shape Go holds them -- or, when the
    // node is there but is not a mapping, the baseline's, because Go's decoder leaves the
    // defaults standing rather than replacing them with what it could not read.
    //
    // `null` is its own arm and it is not the same answer: `SkillsRegistriesConfig` assigns a
    // fresh slice built from the *names it already had*, so the entries come back at zero
    // values (`{"base_url":"","enabled":false}`) and any registry the document named but the
    // baseline does not is gone. A non-mapping that is not null -- the JSON array shape, a
    // scalar -- is ignored outright, so the baseline's own values stand.
    let document_registries = target.get("registries");
    let mut registries: Vec<(String, Registry)> = match document_registries {
        Some(Doc::Object(entries)) => entries
            .iter()
            .map(|(name, node)| {
                let mut registry = Registry::default();
                registry.read(node);
                (name.clone(), registry)
            })
            .collect(),
        // `null` and the JSON array shape are the same answer, measured: Go's decoder ignores
        // a node it cannot read into the map and the builtins stand at their defaults. A
        // `null` that *wipes* is the security file's, below -- the two are easy to confuse and
        // only one of them replaces.
        Some(Doc::Null) | Some(Doc::Array(_)) => baseline
            .and_then(Doc::as_object)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(name, node)| {
                        let mut registry = Registry::default();
                        registry.read(node);
                        (name.clone(), registry)
                    })
                    .collect()
            })
            .unwrap_or_default(),
        // A number where the mapping belongs is the one shape Go refuses here, measured at
        // picoclaw `01635da3`: `config.json type error at line 1, column 1: expected
        // map[string]jsontext.Value but got number`. That sentence belongs to a loader stage
        // this crate has not ported -- it refuses nothing at this depth -- so the document
        // keeps the shape it was given rather than an answer invented here, and the
        // divergence is recorded in `docs/DIVERGENCES.md` rather than papered over.
        Some(_) => Vec::new(),
        None => Vec::new(),
    };

    // Pass 1 -- `registries`, cloned-by-name then decoded.
    //
    // Both node kinds are walked, because `decodeRegistryNodesFromYAML` walks
    // `value.Content` in pairs and never tests what kind of node it is holding: for a
    // mapping that is `key, value` pairs, and for a sequence it is `item, item` pairs, so
    // `registries: [clawhub, {enabled: false}]` names the registry from element 0 and
    // decodes element 1. Reading only the mapping form silently leaves such a registry at
    // its defaults -- a different config rather than a refused one, which is worse than the
    // refusals this pass does raise.
    // A `registries:` header that is **null** is a wipe, and an empty mapping is not. Measured
    // against `LoadConfig` with a document carrying `custom`:
    //
    // | the file's `registries` | Go's loaded set |
    // | --- | --- |
    // | `registries:` (nothing after the colon, so `!!null`) | the baseline's names at **zero** values, `custom` gone |
    // | `registries: null` | the same |
    // | `registries: {}` | builtins at their **defaults** and `custom` kept -- no wipe at all |
    // | no `registries` key | the document's set standing |
    //
    // The first two are one yaml node kind and the third is another, which is the whole
    // difference: yaml short-circuits `!!null` into a nil slice, and an empty mapping decodes to
    // a map that simply adds nothing. Reading them as one shape is what broke the fixed point
    // through Go's own saved pair, where the file Go writes says `registries: {}`.
    //
    // The names come from the baseline because nothing else has them by then: the document's
    // own entry is gone and the file names nothing.
    let file_registries_node = file_skills.and_then(|skills| skills.get("registries"));
    if matches!(file_registries_node, Some(Doc::Null)) {
        registries = baseline
            .and_then(Doc::as_object)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(name, _)| (name.clone(), Registry::default()))
                    .collect()
            })
            .unwrap_or_default();
    }

    let file_registries = file_skills.map(|f| registry_nodes(f.get("registries")));
    for (name, node) in file_registries.as_deref().unwrap_or(&[]) {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let mut registry = lookup(&registries, name).cloned().unwrap_or_default();
        registry.read(node);
        set(&mut registries, name, registry);
    }

    // The deprecated `github.token`, which the yaml pass sets and the legacy pass reads.
    //
    // The file's value *replaces* the document's whenever the key is present with a value,
    // and that includes replacing it with nothing: pass 1 is `yaml.Unmarshal(data, cfg)`, and
    // yaml decodes a struct field into the existing value, so `SecureString.UnmarshalYAML`
    // assigns whatever the node holds. The difference is only visible when one side is empty
    // -- with both sides non-empty the mask renders `[NOT_HERE]` either way -- and it is
    // pinned here by `the_files_github_token_replaces_the_documents` and
    // `a_null_leaves_a_credential_the_document_already_holds`. The two corpus cases that name
    // the pair exactly, `security_github_file_token_empty_overwrites_the_documents` and
    // `security_github_file_token_absent_keeps_the_documents`, are not in this repo's fixture
    // yet (they are at picoclaw `origin/main`), so the unit tests are the whole pin until the
    // fixture moves. Fill-only would pass both of the obvious cases and fail exactly that
    // pair.
    //
    // A null is the third state, and it belongs with "absent", not with "empty": yaml
    // short-circuits `!!null` before the unmarshaler, so the field keeps the document's value
    // and the plaintext `token` param still records the null the file spelled. Clearing here
    // deleted a credential the shipped binary keeps.
    //
    // The assignment therefore has to land on the document, not just on this local. It used
    // to be read and dropped, on the reasoning that the field is invisible in the loaded
    // value -- which is true, `SecureString` marshals to nothing there, and `config.json`
    // shows `github: {}` whichever token is in force. But `saveSecurityConfig` marshals the
    // same typed field through yaml, where `yaml:"token,omitempty"` is writable, so
    // `.security.yml` reports the *effective* token. Keeping the document's copy there is
    // how the port wrote `token: ghp_doc` under a registry whose real token is `ghp_file`:
    // one file with two answers about the same credential. Pinned by
    // `security_registry_token_save_splits_masked_and_real`.
    let mut github_token = target
        .path(&["github", "token"])
        .map(scalar_text)
        .unwrap_or_default();
    if let Some(token) = file_skills
        .and_then(|f| f.path(&["github", "token"]))
        .filter(|t| !matches!(t, Doc::Null))
    {
        github_token = scalar_text(token);
        match target.get_mut_at("github") {
            // Clearing is a removal rather than an empty string: `omitempty` drops the key
            // on both renderings, and writing `""` would put a key in the document that
            // neither file can show.
            Some(github) if github_token.is_empty() => {
                github.remove("token");
            }
            Some(github) => github.set("token", Doc::String(github_token.clone())),
            None if github_token.is_empty() => {}
            None => target.set(
                "github",
                Doc::Object(vec![(
                    "token".to_string(),
                    Doc::String(github_token.clone()),
                )]),
            ),
        }
    }

    // Pass 2 -- every other key in the file's `skills` mapping is a registry.
    if let Some(Doc::Object(entries)) = file_skills {
        for (key, node) in entries {
            let name = key.trim();
            if name.is_empty() || name == "registries" {
                continue;
            }
            if name == "github" {
                // Nothing to do here: pass 1 above already took this node's `token`, which
                // is the same value Go's `cfg.Tools.Skills.Github.Token` holds by the time
                // the legacy pass reads it. Reading it again here was what let a *bare
                // scalar* under `github` become a token (`skills: {github: ghp_direct}`),
                // manufacturing a credential Go refuses to load at all -- see the
                // non-mapping skills entry in `docs/DIVERGENCES.md`, whose blast radius is
                // "the token is dropped" only because this line no longer prints one.
            }
            let mut legacy = Registry::default();
            legacy.read(node);
            if legacy.auth_token.is_empty() {
                if name == "github" && !github_token.is_empty() {
                    legacy.auth_token = github_token.clone();
                } else {
                    // No token from anywhere, so the registry is not created at all.
                    continue;
                }
            }
            let mut current = lookup(&registries, name).cloned().unwrap_or_default();
            if current.auth_token.is_empty() {
                current.auth_token = legacy.auth_token;
            }
            if current.base_url.is_empty() && !legacy.base_url.is_empty() {
                current.base_url = legacy.base_url;
            }
            for (k, v) in legacy.params {
                if !current.params.iter().any(|(ek, _)| *ek == k) {
                    current.params.push((k, v));
                }
            }
            set(&mut registries, name, current);
        }
    }

    let tokens: Vec<(String, String)> = registries
        .iter()
        .filter(|(_, registry)| !registry.auth_token.is_empty())
        .map(|(name, registry)| (name.clone(), registry.auth_token.clone()))
        .collect();

    if registries.is_empty() {
        // Nothing to write, and nothing to create: a document with no `registries` key at all
        // never reaches Go's decoder. A `registries:` header that was present but unreadable
        // is not this case -- the arms above produced the baseline's entries for it. The token
        // list is empty here for the same reason: it is read off `registries` just above.
        return Ok(tokens);
    }
    let mut out: Vec<(String, Doc)> = registries
        .iter()
        .map(|(name, registry)| (name.clone(), registry.to_doc()))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    // A document with no `registries` key at all is possible -- `{"tools":{}}` -- and Go
    // creates the entry here because the legacy pass `Set`s into a nil slice.
    if let Doc::Object(entries) = target {
        match entries.iter_mut().find(|(k, _)| k == "registries") {
            Some(slot) => slot.1 = Doc::Object(out),
            None => entries.push(("registries".to_string(), Doc::Object(out))),
        }
    }
    Ok(tokens)
}

/// Go's yaml type name for a node, as it appears in an unmarshal error: `!!str`, `!!int`,
/// `!!seq`, `!!bool`, `!!float`. Only reached on the refusal above, so the wording is Go's
/// for whoever reads the message rather than something the corpus grades.
fn go_yaml_kind(value: &Doc) -> &'static str {
    match value {
        Doc::Bool(_) => "!!bool",
        Doc::Int(_) => "!!int",
        Doc::Float(_) => "!!float",
        Doc::Array(_) => "!!seq",
        _ => "!!str",
    }
}

/// The `(name, node)` pairs `decodeRegistryNodesFromYAML` walks.
///
/// Go steps through `value.Content` two at a time without checking what kind of node it is
/// holding, so a sequence works as well as a mapping: element 0 is the name -- its `Value`,
/// which is empty for a container, so a container names nothing -- and element 1 is the
/// registry. A trailing element with no pair is dropped rather than turned into a registry
/// with no fields.
fn registry_nodes(node: Option<&Doc>) -> Vec<(String, &Doc)> {
    match node {
        Some(Doc::Object(entries)) => entries
            .iter()
            .map(|(name, value)| (name.clone(), value))
            .collect(),
        Some(Doc::Array(items)) => items
            .chunks(2)
            .filter_map(|pair| {
                let name = scalar_text(&pair[0]);
                let value = pair.get(1)?;
                Some((name, value))
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn lookup<'a>(list: &'a [(String, Registry)], name: &str) -> Option<&'a Registry> {
    list.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

fn set(list: &mut Vec<(String, Registry)>, name: &str, registry: Registry) {
    match list.iter_mut().find(|(k, _)| k == name) {
        Some(slot) => slot.1 = registry,
        None => list.push((name.to_string(), registry)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The state the loader hands this pass: `tools.skills` exists by the time the security
    /// file is applied, because the defaults materialise it.
    fn document(skills: Vec<(&str, Doc)>) -> Doc {
        Doc::Object(vec![(
            "tools".to_string(),
            Doc::Object(vec![(
                "skills".to_string(),
                Doc::Object(
                    skills
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect(),
                ),
            )]),
        )])
    }

    fn registries_after(security_yaml: &str, skills: Vec<(&str, Doc)>) -> Doc {
        let security = crate::yaml::parse(security_yaml).expect("the snippet must parse");
        let mut doc = document(skills);
        // The verdict is not what this helper is for: the refusals have their own tests on
        // the `Result`. A rejected node leaves the document untouched either way, which is
        // exactly what the callers below assert.
        let _ = apply(&mut doc, &security, None);
        doc.path(&["tools", "skills", "registries"])
            .cloned()
            .unwrap_or(Doc::Null)
    }

    fn registry_of(registries: &Doc, name: &str) -> Doc {
        let Doc::Object(entries) = registries else {
            panic!("`registries` must be an object, got {registries:?}");
        };
        entries
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("`{name}` was not created; got {registries:?}"))
    }

    fn has_token(registry: &Doc) -> bool {
        registry.get("auth_token").is_some()
    }

    /// The document's own `registries` is normalised by Go's decoder whether or not a
    /// `.security.yml` exists -- and the common install has none. Gating the whole pass on the
    /// file left these three shapes echoed back as written: a nested `param` kept under a
    /// `param` key instead of flattened into the marshaler's top level, a `name` that
    /// `MarshalJSON` never writes, and an `auth_token` the document spelled `null`. Putting
    /// the `skills` key back in the security file made the first and third agree again, which
    /// is what makes the *gate* the bug rather than the shapes themselves.
    #[test]
    fn the_documents_registries_are_normalised_without_a_security_file() {
        let registries = registries_after(
            "",
            vec![(
                "registries",
                Doc::Object(vec![
                    (
                        "flattened".to_string(),
                        Doc::Object(vec![
                            ("enabled".to_string(), Doc::Bool(true)),
                            (
                                "param".to_string(),
                                Doc::Object(vec![("a".to_string(), Doc::Int(1))]),
                            ),
                        ]),
                    ),
                    (
                        "renamed".to_string(),
                        Doc::Object(vec![
                            ("name".to_string(), Doc::String("named".to_string())),
                            ("enabled".to_string(), Doc::Bool(true)),
                        ]),
                    ),
                    (
                        "nulled".to_string(),
                        Doc::Object(vec![
                            ("enabled".to_string(), Doc::Bool(true)),
                            ("auth_token".to_string(), Doc::Null),
                        ]),
                    ),
                ]),
            )],
        );
        let flattened = registry_of(&registries, "flattened");
        assert_eq!(flattened.get("a"), Some(&Doc::Int(1)), "{flattened:?}");
        assert!(
            flattened.get("param").is_none(),
            "`param` survived: {flattened:?}"
        );
        assert!(
            registry_of(&registries, "renamed").get("name").is_none(),
            "`name` is not a field Go marshals"
        );
        assert!(
            !has_token(&registry_of(&registries, "nulled")),
            "a null `auth_token` became a key"
        );
    }

    /// yaml.v3 short-circuits `!!null` for a type with a custom unmarshaler, so the
    /// `SecureString` is never handed a value: the registry exists and carries no
    /// credential. Printing the node would give `"null"`, which is one.
    #[test]
    fn a_null_or_empty_legacy_token_creates_no_credential() {
        let registries = registries_after(
            "skills:\n  registries:\n    blank:\n      auth_token:\n    explicit:\n      auth_token: null\n",
            Vec::new(),
        );
        for name in ["blank", "explicit"] {
            let registry = registry_of(&registries, name);
            assert_eq!(registry.get("enabled"), Some(&Doc::Bool(false)));
            assert!(
                !has_token(&registry),
                "`{name}` gained a credential: {registry:?}"
            );
        }
    }

    /// The other side of the same rule: a number is a printed scalar, so it *is* a token.
    /// Both faces, because the float is only attributable to the scalar's kind next to the
    /// integer.
    #[test]
    fn a_numeric_legacy_token_is_a_credential() {
        let registries = registries_after(
            "skills:\n  registries:\n    int:\n      auth_token: 42\n    float:\n      auth_token: 1.5\n",
            Vec::new(),
        );
        for name in ["int", "float"] {
            assert!(
                has_token(&registry_of(&registries, name)),
                "`{name}` lost its credential"
            );
        }
    }

    /// Pass 1 decodes the file *into* the value the document already left there, so the
    /// file's text replaces whatever was there -- including with nothing. The observable
    /// consequence is the registry the legacy pass creates from that token: replaced with
    /// nothing, no registry; key absent, the document's token still qualifies one. Fill-only
    /// would create a registry in both halves.
    #[test]
    fn the_files_github_token_replaces_the_documents() {
        let with_document_token = || {
            vec![(
                "github",
                Doc::Object(vec![(
                    "token".to_string(),
                    Doc::String("ghp_doc".to_string()),
                )]),
            )]
        };

        let emptied = registries_after(
            "skills:\n  github:\n    token: \"\"\n",
            with_document_token(),
        );
        assert!(
            matches!(emptied, Doc::Null),
            "an empty file token left the document's credential and created a registry: {emptied:?}"
        );

        let kept = registries_after(
            "skills:\n  github:\n    base_url: https://github.com\n",
            with_document_token(),
        );
        assert!(
            has_token(&registry_of(&kept, "github")),
            "an absent file token dropped the document's credential: {kept:?}"
        );
    }

    /// The third state, which is neither "absent" nor "empty". yaml.v3 short-circuits `!!null`
    /// before it asks a custom unmarshaler, so a null `github.token` never reaches
    /// `SecureString.UnmarshalYAML` and the field keeps the document's value -- while the
    /// plaintext `token` param still records the null the file spelled, because the registry
    /// is created and the param walk is not type-guarded. Clearing here deleted a credential
    /// the shipped binary keeps, and lost that param with it.
    #[test]
    fn a_null_github_token_keeps_the_documents_and_prints_itself() {
        let with_document_token = || {
            vec![(
                "github",
                Doc::Object(vec![(
                    "token".to_string(),
                    Doc::String("ghp_doc".to_string()),
                )]),
            )]
        };
        for file in [
            "skills:\n  github:\n    token:\n",
            "skills:\n  github:\n    token: null\n",
            "skills:\n  github:\n    token: ~\n",
        ] {
            let registries = registries_after(file, with_document_token());
            let github = registry_of(&registries, "github");
            // The mask is the only face a kept credential has in a loaded value --
            // `SkillRegistryConfig.MarshalJSON` writes the literal for the key whatever the
            // value is -- so the discriminator against clearing is that the key is there.
            assert_eq!(
                github.get("auth_token"),
                Some(&Doc::String("[NOT_HERE]".to_string())),
                "`{file}` cleared a credential Go keeps"
            );
            assert_eq!(
                github.get("token"),
                Some(&Doc::Null),
                "`{file}` lost the plaintext null param that comes with the key"
            );
        }
    }

    /// The same rule at the other assignment site -- the `auth_token` a `registries` entry
    /// names -- with the empty string beside it, because a test that only checks the null
    /// passes when both nulls and empties clear.
    #[test]
    fn a_null_leaves_a_credential_the_document_already_holds() {
        let with_document_token = || {
            vec![(
                "registries",
                Doc::Object(vec![(
                    "github".to_string(),
                    Doc::Object(vec![(
                        "auth_token".to_string(),
                        Doc::String("ghp_doc".to_string()),
                    )]),
                )]),
            )]
        };
        for file in [
            "skills:\n  registries:\n    github:\n      auth_token:\n",
            "skills:\n  registries:\n    github:\n      auth_token: null\n",
        ] {
            let registries = registries_after(file, with_document_token());
            assert_eq!(
                registry_of(&registries, "github").get("auth_token"),
                Some(&Doc::String("[NOT_HERE]".to_string())),
                "`{file}` cleared a credential Go keeps"
            );
        }

        let cleared = registries_after(
            "skills:\n  registries:\n    github:\n      auth_token: \"\"\n",
            with_document_token(),
        );
        assert!(
            !has_token(&registry_of(&cleared, "github")),
            "an empty string must still clear the credential: {cleared:?}"
        );
    }

    /// `decodeRegistryNodesFromYAML` walks `Content` in pairs without testing the node kind,
    /// so a sequence names its registry from element zero rather than being ignored.
    #[test]
    fn a_sequence_of_registries_is_read_as_pairs() {
        let registries = registries_after(
            "skills:\n  registries:\n    - clawhub\n    - enabled: true\n",
            Vec::new(),
        );
        assert_eq!(
            registry_of(&registries, "clawhub").get("enabled"),
            Some(&Doc::Bool(true)),
            "the sequence form was not read: {registries:?}"
        );
    }
}
