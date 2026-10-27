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
