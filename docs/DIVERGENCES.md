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

None.

Structural deviations -- a function living in a different crate than its Go
package, a module split that does not match a directory -- are not divergences in
this file as long as observable behaviour is identical. They belong in
`ARCHITECTURE.md`, next to the reason.
