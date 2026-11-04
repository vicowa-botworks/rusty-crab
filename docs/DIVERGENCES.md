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

### A scalar at a document's `registries` is refused by Go and loads here

- Go: `tools.skills.registries` is decoded through the `jsontext` map reader, so a scalar is a
  type error naming its own line and column -- measured at picoclaw `1a4e1edf`, whose
  `pkg/config` loader differs from the `01635da3` the review ran at only by `schema_dump.go`
  and a test file:
  `config.json type error at line 1, column 3: expected map[string]jsontext.Value but got
  string`, with the offending line quoted and a caret under the path. A sequence is *not* in
  that family: it is ignored, and the builtin registries stand at their defaults.
- Rust: `skills::rebuild` treats a sequence as "ignored, baseline stands" (pinned by
  `a_non_mapping_registries_node_leaves_the_builtins_standing`, which covers both that and a
  document `null`) and leaves a scalar in the document untouched rather than refusing it,
  because this crate has no stage that raises Go's `jsontext` type error at all -- the
  unknown-field validator reports names, not kinds, and the two sentences differ.
- Why it is left: inventing a refusal here would be inventing its wording too, and the
  measured Go sentence -- `config.json type error at line 1, column 1: expected
  map[string]jsontext.Value but got number`, at picoclaw `01635da3` -- belongs to a loader
  stage this crate has not ported. The blast radius
  is a config that should not load, loading with a scalar where a registry map belongs; the
  registries themselves come back as the baseline's, so nothing silently gains a credential.
- Closes with: the type-error stage, which is the same missing stage as the `SecureString`
  number refusal in vicowa-botworks/rusty-crab#15.
- Recorded: 2026-10-28, #8 round 4. The entry this replaces -- "a null or non-mapping
  `registries` section cannot be answered without the builtin registries" -- was wrong about
  its own cause: the names and defaults are in the embedded `defaults.json`, which is the
  baseline `load` merges into, so both arms were four lines each and they are now landed
  (`normalise_document` for the document side, the null-header wipe for the file's).



### `crates/crab-config` loads a non-mapping value *inside* a legacy skills key

- Go: `applyLegacySkillsSecurityNode` (`pkg/config/security.go:124`) decodes every value in
  the security file's `skills` mapping into a `SkillRegistryConfig`, and that decoder
  decodes into a `map[string]any`. A scalar or sequence there is a decode failure, so
  `skills: {github: ghp_direct}` is a config the shipped binary will not load.
- Rust: `skills::apply` answers a non-mapping node by ignoring it, so the file loads. The
  token really is dropped: an earlier round printed the bare scalar as a token, which made
  the port *manufacture* a credential (`auth_token: "[NOT_HERE]"`) on a config Go refuses --
  a worse divergence than the one recorded here, and fixed in #8 round 2.
- Not this entry: the `skills:` node itself being a non-mapping. That is refused on both
  sides since #10 -- `security_skills_{scalar,sequence,number}_is_refused`, with `null`
  loading because a null never asks for a mapping. This entry is only about a value *under*
  a legacy skills key, which the parent-node refusal does not reach.
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
- Recorded: 2026-10-27, re-scoped and restored 2026-10-28 (#10 round 3) after this head
  deleted it while the behaviour it describes was still live.

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


### `crates/crab-config` names a migration backup by the UTC date

- Go: `MakeBackup` builds the suffix from `time.Now().Format("20060102")`, and `time.Now()`
  is the **local** calendar date. `config.json.20261027.bak` is the day as the user's own
  wall clock reads it.
- Rust: `today()` derives the date from `SystemTime::now()` as UTC. The crate carries no date
  dependency and this is the only calendar date it needs, so it does the civil-from-days
  arithmetic itself.
- Why: the corpus cannot see the difference, in either direction. Config cases run with the
  environment cleared, so `TZ` is UTC in the generator as well as in the replay; and the
  eight date digits of a backup name are masked by the generator's clock rule anyway, because
  a timestamp at or after the generator process started is the code's own. A case here would
  compare `<date>` with `<date>`.
- Blast radius: only a migration writes a backup, so this is a once-per-upgrade file, and only
  for a user whose local date differs from UTC at that moment. West of UTC that is the last
  hours of the local day, and there **two migrations on consecutive local days fall inside one
  UTC day, so the second backup overwrites the first that Go would have kept** -- the one
  direction in which this loses data. East of UTC, in the first hours of the local day, the
  port names the file with the previous day instead, which only leaves more files behind than
  Go does. No config content changes, and the newest backup always exists.
- Closes with: a local-time source in `today()` -- a date dependency, or reading `TZ` and
  `/etc/localtime` -- and even then no corpus case can pin it, because the clock is masked, so
  treat this as permanent rather than deferred.
- Recorded: 2026-10-28, #9.
### A security `model_list` naming one slot two ways is decided by Go's map order

- Go: `mergeModelListsWithMap` iterates `for k, v := range secML` (`migration.go:520`), so
  when a `.security.yml` carries both spellings of the same slot -- `m1:0:` and `m1:`, each
  with its own `api_keys` -- the winner is whichever key the map hands over last. Five
  processes on one input and one binary gave `[b] [b] [a] [b] [b]`.
- Rust: the port walks the document in file order, so it is deterministically `[b]`, the key
  that comes later in the file.
- Why this is recorded rather than fixed: there is no Go behaviour to reproduce. A corpus case
  pinning either answer pins a coin flip, and it reads as a flaky test the first time the
  iterator disagrees.
- Blast radius: nobody running the port, which is the deterministic side. Anyone who tries to
  witness this shape in the corpus, or who diffs a hand-edited security file against Go and
  sees different keys for two files that look identical.
- Closes with: nothing. If Go ever sorts the iteration this becomes an ordinary merge and the
  corpus can pin it.
- Recorded: 2026-10-30, #9 round 4.
