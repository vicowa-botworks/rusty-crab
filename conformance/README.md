# Conformance fixtures

Every file here is generated, and every file here is a claim about what
picoclaw's Go code does. Neither half is optional: the fixtures are the port's
specification, and they are only trustworthy because a Go program wrote them.

## Where they come from

`cmd/oracle` in <https://github.com/sipeed/picoclaw> calls the real Go functions
over a corpus and records what comes back. It contains no expectations of its own
— every `expected` is a return value captured at emit time.

```sh
cd ~/prj/picoclaw
go run -tags goolm,stdjson ./cmd/oracle \
    -out ~/prj/rusty-crab/conformance/fixtures \
    -seed 0x5EED -fuzz 1500
```

Output is deterministic for a given `-seed`, so regenerating produces a diff of
*behaviour*, not of ordering. Always review that diff before committing it.

## What is here

| File | Seam | Cases | `expected` is |
|---|---|---|---|
| `tokenizer_estimate_message_tokens.json` | `pkg/tokenizer.EstimateMessageTokens` | 1550 | token count |
| `tokenizer_estimate_tool_defs_tokens.json` | `pkg/tokenizer.EstimateToolDefsTokens` | 802 | token count |
| `go_json_encode_parameters.json` | `encoding/json.Marshal` | 1558 | the exact output string, or `null` where Go returns an error |
| `protocoltypes_marshal.json` | `pkg/providers/protocoltypes` + `json.Marshal` | 248 | the exact output string |

Each file carries `schema`, `generator`, `source_repo`, `source_commit` and
`seed`. The harness refuses a `schema` it does not recognise and refuses a file
with zero cases, so a format change or an emptied corpus fails loudly instead of
passing.

The third file exists because the first two reach `json.Marshal` only through a
byte *count*: a one-byte encoding difference would surface as an off-by-one token
estimate and say nothing about which byte moved. Pinning the encoder directly
makes a failure name the byte.

## When a fixture fails

A failure means one of exactly two things, and the order matters:

1. **The Rust port drifted.** The common case. Fix the Rust code.
2. **The Go behaviour changed on purpose and these fixtures are stale.** Then
   regenerate from picoclaw, read the diff, and confirm every changed value is
   one someone chose to change.

Decide which before editing anything. `source_commit` in the fixture says which
Go build produced it:

```sh
cd ~/prj/picoclaw && git log --oneline <source_commit>..HEAD -- pkg/tokenizer/
```

Empty output means Go has not moved since these were recorded, so the Rust side
moved. Non-empty means read those commits before assuming anything.

What is never the right move: relaxing an assertion, deleting a case, or changing
this harness to accept a value it used to reject. If a fixture genuinely must
change, the commit that changes it says which side moved and why.

## Corpus design

The curated cases each target one way a port goes wrong — every UTF-8 width,
combining marks and ZWJ sequences where runes and graphemes disagree, the
`Function == nil` fallback, `max(content, system_parts)` rather than the sum,
Go's float format boundaries, values `json.Marshal` refuses.

The fuzz tail is seeded, so it is reproducible rather than merely large. Its
alphabet deliberately mixes one-, two-, three- and four-byte runes because the
seam counts some fields in runes and others in bytes; a corpus of ASCII would
never have found that.

Values Go cannot encode cannot appear in a JSON file, so the corpus writes them as
`{"$go_marshal_error": "NaN"}`. The marker is coarse on purpose — the interesting
fact is that the whole enclosing map is skipped, not which type failed. Each
crate's test maps it onto whatever its own value model uses to represent
"unencodable".
