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
            // A scalar or sequence where a mapping belongs. Go's `Decode(&raw)` into a
            // `map[string]any` fails on a scalar, and the legacy pass refuses a
            // non-mapping node outright; neither is in the corpus, so the port declines
            // the node rather than inventing a shape for it.
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
                "auth_token" => self.auth_token = scalar_text(v),
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
fn scalar_text(node: &Doc) -> String {
    match node {
        Doc::String(s) => s.clone(),
        Doc::Bool(true) => "true".to_string(),
        Doc::Bool(false) => "false".to_string(),
        Doc::Int(i) => i.to_string(),
        Doc::Null => "null".to_string(),
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
    if let Some(Doc::Object(entries)) = file_skills.get("registries") {
        for (name, node) in entries {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let mut registry = lookup(&registries, name).cloned().unwrap_or_default();
            registry.read(node);
            set(&mut registries, name, registry);
        }
    }

    // The deprecated `github.token`, which the yaml pass sets and the legacy pass reads.
    // It is invisible in the loaded value -- `SecureString` marshals to nothing there --
    // and its only observable effect is the registry it fills in below.
    let mut github_token = target
        .path(&["github", "token"])
        .map(scalar_text)
        .unwrap_or_default();
    if let Some(token) = file_skills.path(&["github", "token"]) {
        let token = scalar_text(token);
        if github_token.is_empty() && !token.is_empty() {
            github_token = token;
        }
    }

    // Pass 2 -- every other key in the file's `skills` mapping is a registry.
    if let Doc::Object(entries) = file_skills {
        for (key, node) in entries {
            let name = key.trim();
            if name.is_empty() || name == "registries" {
                continue;
            }
            if name == "github" {
                let legacy = node
                    .get("token")
                    .map(scalar_text)
                    .unwrap_or_else(|| scalar_text(node));
                if github_token.is_empty() && !legacy.is_empty() {
                    github_token = legacy;
                }
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

fn lookup<'a>(list: &'a [(String, Registry)], name: &str) -> Option<&'a Registry> {
    list.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

fn set(list: &mut Vec<(String, Registry)>, name: &str, registry: Registry) {
    match list.iter_mut().find(|(k, _)| k == name) {
        Some(slot) => slot.1 = registry,
        None => list.push((name.to_string(), registry)),
    }
}
