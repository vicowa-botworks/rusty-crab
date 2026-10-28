# Recorded divergences

Every intentional difference between this port and picoclaw's Go behaviour, with
the reason it exists. An empty list means the two are required to agree on
everything.

A divergence is recorded here **before** the code that implements it lands, in the
same pull request. A conformance failure "fixed" by changing a fixture without an
entry here is a bug, not a decision.

## Format

```
### <short name>

- Go: <what picoclaw does>, at <file:line or package>
- Rust: <what this port does instead>
- Why: <the reason Go's behaviour cannot be carried over>
- Blast radius: <who notices — existing installs, provider requests, ...>
- Recorded: <date>, <PR>
```

## Divergences

### Wording of a refused `time.Time`

- Go: marshalling a `time.Time` with a year outside `[0, 9999]`, or in a zone
  whose hour exceeds 23, fails the whole document with
  `json: error calling MarshalJSON for type *time.Time: year outside of range [0,9999]`
  (`time.appendStrictRFC3339`, reached through `json.Marshal`).
- Rust: `go_time::format_rfc3339_nano` returns `MarshalError` carrying Go's
  *inner* message; `MarshalError`'s `Display` renders it as
  `json: unsupported value: <message>`, which is Go's wording for the NaN/Inf
  family rather than for a `MarshalJSON` refusal.
- Why: `MarshalError` is one flat type shared with the unsupported-value family.
  Matching Go exactly here means a second error variant in `crab-gojson` for a
  string nothing parses.
- Blast radius: anyone printing or pattern-matching the error text. The
  observable contract -- no bytes emitted, the whole document fails -- is
  unchanged, and that is the half the conformance corpus can see.
- Recorded: 2026-10-26, #3.

Structural deviations -- a function living in a different crate than its Go
package, a module split that does not match a directory -- are not divergences in
this file as long as observable behaviour is identical. They belong in
`ARCHITECTURE.md`, next to the reason.

### `crates/crab-config` drops the `web` section of `.security.yml`

- Go: `loadSecurityConfig` unmarshals the whole file into `Config`, and `Tools` is tagged
  `yaml:",inline"`, so a top-level `web:` in the security file lands on `tools.web` and
  overrides the JSON config. The section is written by `saveSecurityConfig` whenever a search
  provider has an API key, so it is present in most real files.
- Rust: it is reached and then dropped. `apply_security` does walk the inline branch --
  it takes `tools`' own yaml list from the dump and hands each child to `merge_filling` --
  but `merge_filling` decides whether a key is a field by asking the **root** `Config`
  schema, where `web` is not a field of anything: it is a field of `Tools`, one level down.
  The key is skipped and the section is gone.
- Scope note: `skills` used to be listed here as well. It is applied now, by
  `skills::apply` (the legacy lift plus both registry passes); what is still open on that
  section is its own entry below, and it is about the *builtin registry materialisation*, not
  about the inline walk.
- Why it is still open: the fix is the architecture rule this file already states -- thread
  the target's schema through the walk instead of resolving field knowledge once at the
  root -- and `merge_filling` is also the function the channel `settings` merge goes
  through, whose `settings`/`api_keys` exemptions exist only because of the same root
  lookup. Threading it correctly changes bytes on cases that are green today, so it is its
  own change rather than a line in this one.
- Why not refuse them instead: that was the first behaviour, and it was the wrong direction
  -- refusing makes the loader reject a file the shipped binary loads, and the failure lands
  on every install that has ever saved a search key. Ignoring is the smaller divergence and
  it is visible here rather than in a user's running agent.
- Blast radius: an install that keeps a web-search key or a registry token in
  `.security.yml` gets a config where that key is absent, so a search tool that works under
  Go reports "not configured" under the port. Secrets are not leaked or written anywhere new
  -- they are read and dropped.
- Closes with: `merge_filling` taking the schema of the node it is merging into. The dump
  already carries every field list needed, so no Go-side work is required.
  `web_and_skills_are_reached_and_dropped_until_the_merge_carries_its_schema` fails on the
  day it does, and this entry goes with it.
- Recorded: 2026-10-26, #5; mechanism corrected 2026-10-28, #11.

### `crates/crab-config` does not apply the Telegram streaming env-compat shims

- Go: `applyTelegramStreamingEnvCompat` (`pkg/config/config_channel.go:768`) runs inside
  `InitChannelList` and reads `PICOCLAW_CHANNELS_TELEGRAM_STREAMING_ENABLED`,
  `PICOCLAW_CHANNELS_TELEGRAM_STREAMING_THROTTLE_SECONDS` and
  `PICOCLAW_CHANNELS_TELEGRAM_STREAMING_MIN_GROWTH_CHARS`, writing them into the telegram
  channel's streaming settings.
- Rust: `channels::init_channel_list` has no equivalent, so the environment is inert.
- Why: the conformance corpus runs with the environment cleared (`pinConfigEnv` in
  `cmd/oracle/config.go`), so no recorded case can distinguish the two. Porting it against
  this fixture would mean inventing the expected bytes, which is the thing the corpus
  exists to prevent. Note this is *not* the `env.Parse` no-op — that one genuinely does
  nothing, because no field in `config_channel.go` carries an `env:` tag.
- Blast radius: an install that sets any of the three variables loads a different config
  under the port than under the shipped binary, and the streaming behaviour that follows is
  silently the default rather than the operator's setting. Nothing fails loudly, which is
  why it is written down instead of left for a green replay to imply.
- Closes with: a corpus case that sets the variables in the generator's own environment and
  records the loaded value. Until then the replay staying green says nothing about this.
- Recorded: 2026-10-27, #7.

### `crates/crab-config` skips the two channel validators

- Go: `InitChannelList` refuses two things after building the list —
  `validateSingletonChannels` (`pkg/config/config_channel.go:754`), more than one enabled
  channel of a type that only allows one, and `validateChannelStreamingConfig` (`:761`),
  inconsistent streaming settings.
- Rust: neither runs, so a config Go refuses loads here.
- Why: both need Go-side tables the schema dump does not carry — the singleton registry is
  data in `config_channel.go`, not a struct tag, so the AST extractor cannot see it — and no
  corpus case reaches either refusal. Inventing a registry in Rust would be a list that
  silently disagrees the day Go adds a singleton type, which is the failure mode
  `base_fields` was extracted into the dump to avoid.
- Blast radius: a config with two enabled `telegram` channels loads under the port and is
  refused by the shipped binary. Both are refusals rather than rewrites, so no *passing*
  config looks different — the divergence is only ever a file that should not have loaded.
- Closes with: the singleton registry and the streaming rules carried in the dump (the same
  mechanism `base_fields` uses), plus one corpus case per refusal.
- Recorded: 2026-10-27, #7.

### A null or non-mapping `registries` section cannot be answered without the builtin registries

- Go: `SkillsRegistriesConfig` is a slice, so yaml.v3's `!!null` short-circuit *zeroes* it
  before the custom unmarshaler is reached -- the same short-circuit that makes a null
  `SecureString` keep what it held, arriving at the opposite result because the kind differs.
  The decoder then re-materialises the two builtins at their **zero** values, and the
  document's own registries are gone with the slice. Measured at picoclaw `origin/main` and at
  the fixture's head, identical on both:

  | `.security.yml` `skills:` | Go's `tools.skills.registries` |
  | --- | --- |
  | `registries:` (null) | `clawhub {enabled: false, base_url: ""}`, `github {enabled: false, base_url: ""}` |
  | same, with `custom` in `config.json` | `custom` gone entirely |
  | `registries: null` beside a legacy key | builtins zeroed **and** the legacy registry created |
  | `registries: {}` / `registries: []` | builtins intact (the port agrees) |
  | `config.json` `registries: [{name: github, enabled: true}]`, no security file | the array ignored; `clawhub` + `github` at **defaults** |

- Rust: a null section reads as "nothing to do" (`registry_nodes`' `_ => Vec::new()`), so the
  builtins stay at their defaults and a `custom` survives; a non-object document `registries`
  is echoed as written, which changes the *kind* of the node and deletes a builtin.
- Why it is not fixed in the same commit as the gate: both answers need the two builtin
  registries -- their names and the base URLs `defaults()` gives them -- and the port has
  neither anywhere. `clawhub` appears nowhere in `crates/crab-config/src/` and not in the
  schema dump, because it is data in `config.go:1560`/`:1609`, not a struct tag, so the AST
  extractor cannot see it. Writing the pair by hand is exactly the failure mode `base_fields`
  was extracted into the dump to avoid: a list that silently disagrees the day Go changes a
  default.
- Blast radius: an operator who leaves a `registries:` header and nothing under it gets a
  config where clawhub is still enabled under the port and disabled under the shipped binary.
  The array spelling is rarer and rewrites the node's kind.
- Closes with: the builtin registry list carried in the dump the way the singleton channel
  registry is (one Go-side extraction, then the two arms here are four lines), tracked as
  vicowa-botworks/rusty-crab#13.
- Recorded: 2026-10-28, #8 round 3.

### `crates/crab-config` loads a non-mapping skills value Go refuses

- Go: `applyLegacySkillsSecurityNode` (`pkg/config/security.go:124`) decodes every value in
  the security file's `skills` mapping into a `SkillRegistryConfig`, and that decoder
  decodes into a `map[string]any`. A scalar or sequence there is a decode failure, so
  `skills: {github: ghp_direct}` is a config the shipped binary will not load.
- Rust: `skills::apply` answers a non-mapping node by ignoring it, so the file loads. The
  token really is dropped: an earlier round printed the bare scalar as a token, which made
  the port *manufacture* a credential (`auth_token: "[NOT_HERE]"`) on a config Go refuses --
  a worse divergence than the one recorded here, and fixed in #8 round 2.
- Why: the one corpus case in this area, `security_a_scalar_under_registries_loads_unchanged`,
  pins the file that *does* load -- `registries` is skipped by name before the decode, which
  is the only reason it survives. No case pins a non-`registries` key holding a scalar, so
  refusing now would be writing an error path against bytes nobody recorded, including which
  diagnostic wins when several keys are wrong.
- Blast radius: a hand-edited `.security.yml` with a typo that puts a token where a registry
  mapping belongs loads under the port with the token dropped, and is refused by the shipped
  binary. Nothing is silently rewritten -- the file is simply accepted that should not be --
  but it is the class of divergence that turns a rejected config into a running one.
- Closes with: one corpus case per shape (scalar, sequence) under a legacy skills key, then
  an error type on this pass. The `registries` skip itself stays unpinnable until then: with
  the skip removed this port still replays green, because it never reaches the refusal the
  skip exists to avoid.
- Recorded: 2026-10-27.

### The version probe's error has no preview block

- Go: the version probe (`config.go:1311`, `json.Unmarshal` into
  `struct { Version int }`) hands its error to `wrapJSONError` (`diagnostics.go:64`), which
  for an `UnmarshalTypeError` returns the summary line *and*, when the offset lands on a
  non-blank line, a second block: `   1 | {"version":"3"}` and a caret under the offending
  column, dimmed and colour-bolded when `diagnosticsUseColor()` says the stream is a
  terminal.
- Rust: `version_type_diagnostic` returns the summary line only. The line, the column, the
  field name, the expected type and the value word (`string`, `bool`, `number 3.5`) all
  match; the preview is absent.
- Why: the preview is a rendering decision, not a decoding one -- it depends on whether
  stderr is a TTY, and on `trimDiagnosticLine`'s windowing around the caret. The corpus
  records no error text at all (a failing case adds `error_op_index` and nothing else), so
  there is nothing to pin it against and everything to get wrong.
- Blast radius: anyone printing the error sees one line instead of two-then-two, and anyone
  pattern-matching the *first* line is unaffected. `DiagnosticSummary` in Go strips the
  preview for logs, so the summary the port does reproduce is the half Go treats as the
  message.
- Closes with: a preview renderer in `crab-config` plus a TTY probe, if anything ever needs
  the two-line form. Nothing in the port prints config errors today.
- Recorded: 2026-10-28, #11.

### A migrated document's security file is merged as data, and only its `model_list` half is ported

- Go: `LoadConfig` calls `loadSecurityConfig` only for a document already at
  `CurrentVersion`. A legacy document goes through `loadConfigMap` (migration.go:404),
  which unmarshals `.security.yml` as a plain `map[string]any`, rewrites it
  (`mergeModelListsWithMap` consumes `model_list` by name; `web`/`skills` are lifted into
  `tools`, replacing any `tools` the file itself carried), merges it into config.json with
  the generic `mergeMap`, and hands the re-marshalled result to the ordinary decoder.
- Rust: the version decides the two edges that are observable today -- a key the decoder
  cannot place is ignored at v3 and refused at v2, and a `model_list` that is not a mapping
  is a type error at v3 and deleted at v2 -- and the `model_list` merge itself runs on both
  paths. What is not ported is the generic `mergeMap` over the rest of a legacy document:
  there, a security `channel_list` entry replaces what is in the config rather than filling
  into it, and a scalar the two files both name goes to the security file.
- Why: the merge happens in a stage this crate reaches only for documents below
  `CurrentVersion`, and it is a different function from the typed one -- `mergeMap` on
  untyped data, before `migrateV1ToV2`, with its own ordering. Porting the typed merge and
  calling it done is what produced the two wrong edges above, both of which read the file as
  though one loader owned it.
- Blast radius: an install whose `config.json` is still on version 1 or 2 and which has a
  `.security.yml` with a `channel_list` entry. The port loads the secrets it needs and
  differs from Go on the non-secret keys the same entry carries. A current-version install
  -- every install that has saved once -- is unaffected.
- Why no recorded case can show it: every corpus case that has a `.security.yml` is a v3
  document, because the file is written by a v3 save; and the three `migrate_*` cases have
  no security file at all. `migrate_backs_up_both_files` is the single case with a legacy
  document *and* a security file, and it is deferred on the `save` half -- its load prefix
  is replayed and labelled `security_data_merge` in `tests/conformance.rs`, which is the
  closest the fixture currently comes. Closing this needs a Go-side case: a v2
  `config.json` plus a `.security.yml` whose `channel_list` entry names keys the config also
  sets.
- Recorded: 2026-10-28, #11.
