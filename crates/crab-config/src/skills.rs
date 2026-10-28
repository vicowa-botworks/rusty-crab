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
//! Injecting faults into this module and replaying the config seam leaves three that no
//! case fails. Two are equivalent and one is a gap in this port, and the three should not
//! be remembered as the same kind of thing:
//!
//! * **Writing `auth_token` over one that is already set** is equivalent, because every
//!   `SecureString` marshals to the same `[NOT_HERE]`. No document can tell "kept the
//!   stored token" from "replaced it with the legacy one"; only the file that `save`
//!   writes back could, and `save` is not ported yet.
//! * **Letting the file's `github.token` win over one already in config.json** is the
//!   same equivalence seen from the other field: both are invisible in the loaded value
//!   (see `marshal`'s SecureString rule) and both qualify the registry identically.
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
/// which is a credential -- `security_legacy_null_token_creates_no_credential` and
/// `security_legacy_empty_token_creates_no_credential` pin the registry existing with no
/// `auth_token` key at all. Numbers are the opposite case: `42` and `1.5` are both printed
/// scalars, so both create one.
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
pub fn apply(merged: &mut Doc, security: &Security) {
    let Some(file_skills) = security.document.get("skills") else {
        return;
    };
    let Some(target) = merged
        .get_mut_at("tools")
        .and_then(|tools| tools.get_mut_at("skills"))
    else {
        return;
    };

    // The registries the document already carries, in the shape Go holds them.
    let mut registries: Vec<(String, Registry)> = target
        .get("registries")
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
        .unwrap_or_default();

    // Pass 1 -- `registries`, cloned-by-name then decoded.
    //
    // Both node kinds are walked, because `decodeRegistryNodesFromYAML` walks
    // `value.Content` in pairs and never tests what kind of node it is holding: for a
    // mapping that is `key, value` pairs, and for a sequence it is `item, item` pairs, so
    // `registries: [clawhub, {enabled: false}]` names the registry from element 0 and
    // decodes element 1. Reading only the mapping form silently leaves such a registry at
    // its defaults -- a different config rather than a refused one, which is worse than the
    // refusals this pass does raise.
    for (name, node) in registry_nodes(file_skills.get("registries")) {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let mut registry = lookup(&registries, name).cloned().unwrap_or_default();
        registry.read(node);
        set(&mut registries, name, registry);
    }

    // The deprecated `github.token`, which the yaml pass sets and the legacy pass reads.
    // It is invisible in the loaded value -- `SecureString` marshals to nothing there --
    // and its only observable effect is the registry it fills in below.
    //
    // The file's value *replaces* the document's whenever the key is present with a value,
    // and that includes replacing it with nothing: pass 1 is `yaml.Unmarshal(data, cfg)`, and
    // yaml decodes a struct field into the existing value, so `SecureString.UnmarshalYAML`
    // assigns whatever the node holds. `security_github_file_token_empty_overwrites_the_documents`
    // is the only case that can see the difference -- with both sides non-empty the mask
    // renders `[NOT_HERE]` either way -- and it shows `token: ""` in the file removing the
    // document's token, while `security_github_file_token_absent_keeps_the_documents` shows
    // an absent key keeping it. Fill-only would pass both of the obvious cases and fail
    // exactly that pair.
    //
    // A null is the third state, and it belongs with "absent", not with "empty": yaml
    // short-circuits `!!null` before the unmarshaler, so the field keeps the document's value
    // and the plaintext `token` param still records the null the file spelled. Clearing here
    // deleted a credential the shipped binary keeps.
    let mut github_token = target
        .path(&["github", "token"])
        .map(scalar_text)
        .unwrap_or_default();
    if let Some(token) = file_skills
        .path(&["github", "token"])
        .filter(|t| !matches!(t, Doc::Null))
    {
        github_token = scalar_text(token);
    }

    // Pass 2 -- every other key in the file's `skills` mapping is a registry.
    if let Doc::Object(entries) = file_skills {
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

    if registries.is_empty() {
        return;
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
        apply(&mut doc, &security);
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
