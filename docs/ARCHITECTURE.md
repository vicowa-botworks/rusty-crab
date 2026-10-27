# Architecture

## What is being ported

picoclaw is 120,438 lines of non-test Go (111,968 of it in 425 `pkg/` files)
across 98 internal packages, with a further 121,092 lines of tests. Measured from
the import graph:

| Top-level group | Non-test LOC | Files |
|---|---|---|
| `pkg/channels` | 26,591 | 81 |
| `pkg/agent` | 19,373 | 59 |
| `pkg/tools` | 14,015 | 55 |
| `pkg/providers` | 10,611 | 47 |
| `pkg/config` | 7,286 | 16 |
| `pkg/evolution` | 5,884 | 22 |
| `pkg/seahorse` | 4,864 | 11 |
| everything else (31 more) | 23,344 | 134 |

## The dependency graph is the port order

The package graph is a **DAG** — Go forbids import cycles, so this is
guaranteed, but it is worth stating because it means the port can proceed
strictly bottom-up and never has to stub a not-yet-ported dependency.

Longest chain is 16 edges. Depth here means "longest path to a leaf", so L0
imports nothing internal and is portable first:

| Layer | Packages |
|---|---|
| 0 | `constants` `credential` `events` `fileutil` `health` `logger` `netbind` `pkg` `providers/protocoltypes` `audio` `devices/events` `cmd/picoclaw/internal/cliui` |
| 1 | `bus` `cron` `media` `state` `providers/common` `providers/messageutil` `providers/bedrock` `devices/sources` |
| 2 | `config` `devices` `identity` `providers/anthropic` `providers/anthropic_messages` `providers/openai_compat` `providers/openai_responses_common` |
| 3 | `auth` `commands` `isolation` `pid` `providers/azure` `providers/httpapi` `mcp`* |
| 5 | `providers` |
| 6 | `memory` `routing` `tokenizer` `utils` `audio/tts` |
| 7 | `channels` `session` `skills` `updater` `audio/asr` |
| 8 | 21 `channels/*` adapters, `evolution`, `tools/shared`, `agent/interfaces` |
| 9–11 | `agent/adapters`, `tools/fs`, `tools/hardware`, `tools/integration`, `tools` |
| 12–16 | `seahorse` `heartbeat` → `agent` → `gateway` → `cmd/picoclaw` |

\* layers 4 and 5 mix `cmd/` internals with `mcp`, `migrate` and `providers`; the
full listing is reproducible from `go list -deps` and is not worth keeping by
hand.

### One cycle, at the directory level

`pkg/config` and `pkg/providers` form a cycle *as directories*:

```
pkg/config/config.go            -> pkg/providers/common   (NormalizeToolSchemaTransform)
pkg/providers/factory_provider.go, legacy_provider.go -> pkg/config   (ModelConfig, Config, Version)
```

This compiles because Go's rule is per-package, not per-directory. It matters for
the port because a Rust crate graph **is** acyclic at the module level too, so the
directory split cannot be carried over unchanged. The seam is one function:

`pkg/providers/common/tool_schema_transform.go` imports only `fmt` and `strings`,
and nothing else in `providers/common` uses it. Moving it out of `providers/common`
breaks the cycle with no behaviour change. Until that happens upstream, the Rust
port must place that function on the `config` side of the boundary.

## Crate mapping

The default is one crate per Go package group, so that a reviewer can read a Rust
crate and the Go package side by side, and so a conformance fixture names both
sides unambiguously.

| Rust crate | Go package |
|---|---|
| `crab-tokenizer` | `pkg/tokenizer` |
| `crab-protocoltypes` | `pkg/providers/protocoltypes` |
| `crab-gojson` | Go's `encoding/json` — standard library, not a picoclaw package |

Deviations from one-to-one need a reason written next to them. `crab-gojson` is
one: picoclaw does not own `encoding/json`, but it is a *dependency whose bytes
are load-bearing* — `pkg/tokenizer` measures `len(json.Marshal(x))`, and
`pkg/providers/protocoltypes` puts those bytes on the wire and into session files.
So it is ported as infrastructure and shared, because two copies would drift and
disagree about what the same Go value serialises to. It is pinned by its own
fixture (1558 cases), which is what makes sharing safe: "improving" it fails a test
that names the byte.

The crate sits **below** `crab-tokenizer`, matching Go's graph — `protocoltypes` is
layer 0 and `tokenizer` is layer 6, so a wire type must never depend on the
tokenizer. `crab_tokenizer` re-exports the value type because
`ToolFunctionDefinition::parameters` mentions it in a public signature.

## Rules

**Behaviour is inherited, never re-derived.** A ported function's output is
whatever the Go function returns for the same input. Where the Go code looks
wrong, port the wrongness and file the bug against picoclaw — a Rust port that
silently fixes things is a port that strands users mid-upgrade.

**Format-compatible surfaces stay frozen.** Memory-store JSONL, session files and
config serialization keep field names, ordering and defaults so existing users'
files load unchanged. These are compat surfaces guarded by characterization
tests, not formats free to redesign.

**A Go `int` is 64-bit.** Rust code porting arithmetic must use `i64`/`usize`
explicitly and never rely on platform width.

**Go's `len()` on a string is bytes; `utf8.RuneCountInString` is runes.** The two
appear in the same expression in picoclaw. Every ported tally has to say which one
it is, per term.

**Go's zero values are not Rust's `Default`.** A nil map, an empty slice and an
absent field behave differently in the Go code (`!= nil` guards, `len()`, JSON
`omitempty`), and the difference is usually load-bearing. Model them as `Option`
versus empty deliberately, not by reaching for `#[serde(default)]`.

**Concurrency.** Go's goroutine-per-thing and channel-based handoff map to
`tokio` tasks and `mpsc` — but Go's unbuffered channel rendezvous semantics differ
from a bounded channel, and a Go `select` with a `default` is a poll, not a wait.
Port the buffer sizes, since they are usually the backpressure design.

## Where to start

Two crates are done and are the template: `crab-tokenizer` (arithmetic and
byte/rune tallies) and `crab-protocoltypes` (a serialisation surface). Each has a
Go-side generator, a committed corpus, a replay test, and unit tests that explain
the traps.

They fail differently, which is why both are worth having as precedents. A
tokenizer divergence is a wrong number that is invisible until a context window
overflows. A wire-type divergence is a byte that a provider still accepts and that
only the *next release* notices, when it reads back a session file the old port
wrote. The second kind is the one no test catches without an oracle.

Next, in the order the oracle suite covers them: the memory JSONL store, then
`pkg/config`. Both are stored formats, so both are wire-type-shaped problems.
