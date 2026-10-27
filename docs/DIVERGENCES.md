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
