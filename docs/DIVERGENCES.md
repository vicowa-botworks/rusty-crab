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

### `crates/crab-config` drops the `web` and `skills` sections of `.security.yml`

- Go: `loadSecurityConfig` unmarshals the whole file into `Config`, and `Tools` is tagged
  `yaml:",inline"`, so a top-level `web:` or `skills:` in the security file lands on
  `tools.web` / `tools.skills` and overrides the JSON config. Both sections are written by
  `saveSecurityConfig` whenever a search provider has an API key or a skill registry has an
  auth token, so they are present in most real files.
- Rust: `yaml::parse` accepts them and `apply_security` merges only `channels` and
  `model_list`, so the two sections are read and then discarded.
- Why not refuse them instead: that was the first behaviour, and it was the wrong direction
  -- refusing makes the loader reject a file the shipped binary loads, and the failure lands
  on every install that has ever saved a search key. Ignoring is the smaller divergence and
  it is visible here rather than in a user's running agent.
- Blast radius: an install that keeps a web-search key or a registry token in
  `.security.yml` gets a config where that key is absent, so a search tool that works under
  Go reports "not configured" under the port. Secrets are not leaked or written anywhere new
  -- they are read and dropped.
- Closes with: `apply_security` growing the two sections. The schema dump already carries
  their field lists, so no Go-side work is needed.
- Recorded: 2026-10-26, #5.

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
