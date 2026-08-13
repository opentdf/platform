---
status: proposed
date: 2026-08-12
decision: Stream list output through a single entry point, bounding memory for JSON while the styled table buffers to size columns
author: '@michaelschumacher-sketchUX'
deciders: ['@alkalescent', '@jrschumacher', '@jakedoublev', '@ryanulit']
tags:
  - cli
  - output
  - streaming
  - memory
---

# Streaming list output with mode-appropriate memory bounds

## Context and Problem Statement

List commands in `otdfctl` render in two modes: a styled table, or a JSON document under `--json`. Both are produced by handing a fully
materialized value to a single renderer.

Two properties of the current implementation matter for this decision, and both are easy to misstate:

- **List sources are not incremental.** A list command issues one limit/offset RPC and iterates the already-materialized slice on the
  response — see `cmd/policy/namespaces.go`, which calls `h.ListNamespaces(...)` and then ranges over `resp.GetNamespaces()`. The whole
  page is resident in memory before rendering begins.
- **Table columns are not content-derived.** `cli.NewTable` (`pkg/cli/table.go`) builds a `bubble-table` model from *declared* flex
  ratios and constrains it with `WithTargetWidth(TermWidth())`. Column widths come from those ratios and the terminal width, not from
  scanning every cell.

This splits the benefit of streaming into two parts that are worth keeping distinct, because conflating them overstates the case:

- **Realized today: the serialization buffer.** `printJSON` hands the whole response to `json.Encoder.Encode`, which marshals the entire
  document into memory — and, with indentation enabled, into a second buffer — before writing a byte. Encoding one record at a time
  removes that whole-document buffer and lets the first record reach the writer before the last one is serialized. That is a real
  constant-factor reduction in peak memory and a real improvement in time to first byte, available on the very first adoption.
- **Latent until sources change: the response itself.** The records returned by the RPC stay resident regardless of how they are
  encoded. Streaming makes that term bounded only once sources become incremental — multi-page fetches, or a server-streaming API.

So streaming is not a no-op today, but the headline "flat memory in the number of records" is only true after the source side changes
too. We would rather settle the rendering contract before that happens than retrofit it under pressure.

There is also a compatibility constraint any streaming design must confront. Today `HandleSuccess` is passed the whole RPC response, so
`--json` emits an *envelope*: an object containing the records alongside a `pagination` block. The e2e suite depends on this shape,
reading `.pagination.total`, `.pagination.next_offset`, and `.pagination.current_offset` (`e2e/attributes.bats`, `e2e/actions.bats`). A
renderer that emits a bare JSON array is not a formatting change; it is a schema break for every consumer.

The question this ADR settles is what the streaming rendering contract should be, and specifically whether both output modes stream or
only one.

## Decision Drivers

- **Memory bounds under automation**: `--json` is where large result sets are realistic; per-record encoding helps now, and bounds the
  whole path once sources become incremental.
- **Time to first byte**: pipelines should be able to start work before the document is fully serialized, and eventually before the
  producer is exhausted.
- **One rendering entry point**: callers should not branch on output mode to render a list.
- **No JSON schema break**: the existing envelope, including `pagination`, must survive, or the break must be explicit and planned.
- **No terminal-rendering regression**: today's table is clamped to the detected terminal width; output must not become wider than the
  terminal.
- **Readable tables**: whatever the sizing policy, columns must stay aligned and important values must not be silently truncated.
- **Errors stay distinguishable**: a mid-iteration failure must not be indistinguishable from normal exhaustion.
- **No new dependencies**: reuse styling primitives already in the tree.

## Considered Options

1. Status quo — buffer the full result set in both output modes
2. Stream JSON only — leave the styled table on its existing buffered path
3. Unified streaming with fixed column widths — one entry point, both modes memory-bounded
4. Unified streaming with automatic column widths — one entry point, JSON bounded, table buffered to size columns

## Decision Outcome

Chosen option: **"Unified streaming with automatic column widths"**, because it establishes a single list-rendering contract that
becomes memory-bounded on the automation path the moment sources become incremental, without committing us to a column-sizing policy
that truncates values we cannot yet bound.

A single entry point renders a list for both modes. In JSON mode it writes a JSON array, marshaling one item at a time, so the encoder
never holds the full set. In styled mode it drains the sequence into rows and renders a bordered table whose column widths are derived
from the content. The renderer consumes an `iter.Seq2[any, error]` sequence, so an incremental source can be passed through without
materializing it, and a non-nil error aborts the stream and is returned rather than ending it as if the source were exhausted.

This choice is **deliberately scoped**, and the scoping is what makes it defensible:

- It is a decision about the *rendering contract*, not an instruction to migrate existing commands. The helper is in place and adopted
  by no command; adoption is gated on the two conditions below.
- **Adoption requires preserving the JSON envelope.** A command may not move to the streaming path until the renderer can emit records
  inside the existing object alongside `pagination`. Emitting a bare array to today's consumers is out of scope and not sanctioned by
  this ADR.
- **Adoption requires restoring the terminal-width clamp**, so a streamed table does not render wider than the terminal that the
  existing helper respects.

The honest tension is with option 3. Because today's columns are declared flex ratios rather than content-derived widths, fixed-width
streaming is *closer* to current behavior than automatic sizing is, and it bounds memory in both modes. We prefer option 4 because
content-derived widths avoid truncating identifiers and names — the fields users most need intact — and because the styled path is
consumed by humans at human scale, where a hard memory bound buys little. That is a judgment call about which failure mode is worse,
not a claim that option 3 is unworkable. Option 3 remains the right answer if we later find styled output being generated at machine
scale.

### Consequences

- 🟩 **Good**, because the JSON encoder never holds the full encoded document, which lowers peak memory and time to first byte
  immediately, and becomes flat in the number of records once sources are incremental.
- 🟩 **Good**, because callers use one function for both modes and do not branch on output format.
- 🟩 **Good**, because an incremental source can be consumed directly when one exists.
- 🟩 **Good**, because a mid-iteration error is surfaced rather than being indistinguishable from a completed stream.
- 🟩 **Good**, because JSON indentation and HTML-escaping match the existing printer, so per-record encoding is unchanged.
- 🟥 **Bad**, because the styled path is unbounded, so a sufficiently large table can still exhaust memory.
- 🟥 **Bad**, because it changes the column-sizing policy from declared flex ratios to content-derived widths, which is a visible change
  in table appearance and not merely an implementation detail.
- 🟥 **Bad**, because the streamed table is rendered by a different table library than the existing helper, so two renderers coexist.
- 🟥 **Bad**, because as implemented the streamed table is not clamped to the terminal width and carries no pagination footer, both of
  which are regressions that must be closed before any command adopts it.
- 🟥 **Bad**, because a naive adoption would replace the JSON envelope with a bare array and break existing consumers; this ADR forbids
  that, but the hazard is real and easy to trip over.
- 🟨 **Neutral**, because no command has adopted the helper, so the decision is reversible at low cost.
- 🟨 **Neutral**, because only the serialization-buffer share of the memory benefit is realized today; the larger share stays latent
  until sources become incremental.

## Security

Streaming changes *when* and *how* output is written, not *what* is written; no additional data is exposed and no redaction behavior
changes.

One failure mode deserves explicit attention. In JSON mode the array is opened before the first item is written, so if the source fails
mid-iteration the stream aborts before the closing bracket and the emitted document is truncated and not valid JSON. Consumers must
treat a non-zero exit status as authoritative and must not parse partial output as a complete result. This is the correct posture — a
truncated document that fails to parse is safer than a well-formed document that silently omits records — but it must be documented so
automation does not read a partial array as a short-but-complete answer.

## Validation

- Unit tests cover JSON and styled rendering, empty input, HTML-escape parity with the existing printer, and mid-stream error
  propagation.
- No command adopts the streaming path until the JSON envelope is preserved; the existing e2e assertions on `.pagination.*` serve as
  the regression test for that.
- The terminal-width clamp is restored and verified against the existing table helper before adoption.
- First adoption is measured against a large single page to confirm the serialization-buffer saving, and re-measured for flat memory in
  JSON mode once an incremental source exists.
- Linting and race-enabled tests in CI.

## Pros and Cons of the Options

### 1. Status quo — buffer the full result set in both output modes

Commands accumulate every record and render once at the end.

- 🟩 **Good**, because it is the simplest control flow and is already in place.
- 🟩 **Good**, because the JSON envelope and the pagination footer are naturally available, since the full response is in hand.
- 🟩 **Good**, because it matches how the sources actually behave today, so it adds no latent complexity.
- 🟥 **Bad**, because memory grows linearly with the result set in both modes.
- 🟥 **Bad**, because JSON mode pays for the records *and* a full encoded copy of them, since the encoder marshals the whole document
  before writing.
- 🟥 **Bad**, because nothing is emitted until the whole document is serialized, so pipelines cannot overlap work with production.
- 🟥 **Bad**, because it leaves no contract in place for when sources do become incremental.

### 2. Stream JSON only — leave the styled table on its existing buffered path

Add a streaming JSON writer; leave table rendering untouched on its current call path.

- 🟩 **Good**, because it bounds memory exactly where it matters with the smallest possible change.
- 🟩 **Good**, because the styled table keeps its renderer, its flex-ratio sizing, its terminal-width clamp, and its pagination footer,
  so there is no visual risk at all.
- 🟩 **Good**, because it avoids introducing a second table library.
- 🟨 **Neutral**, because end-user-visible behavior is nearly identical to the chosen option.
- 🟥 **Bad**, because callers must branch on output mode, or two call paths must be maintained for one conceptual operation.
- 🟥 **Bad**, because the two paths will drift, and a change to one is easy to forget in the other.
- 🟥 **Bad**, because it offers no single place to add streaming to the styled path later.

### 3. Unified streaming with fixed column widths — one entry point, both modes memory-bounded

One entry point for both modes. Column widths are declared up front — from flex ratios and the terminal width, as today — and each row
is emitted as it arrives, truncating or padding to fit.

- 🟩 **Good**, because memory is bounded in *both* modes, making behavior uniform and easy to explain.
- 🟩 **Good**, because declared widths constrained by terminal width are exactly the current sizing policy, so this preserves today's
  appearance rather than changing it.
- 🟩 **Good**, because the styled path also gains incremental output, so a long list shows progress.
- 🟩 **Good**, because worst-case behavior is predictable regardless of result size.
- 🟥 **Bad**, because values wider than their column must be truncated, and identifiers and names are the most likely casualties.
- 🟥 **Bad**, because a bordered table cannot widen after the first row is emitted, so a late oversized value cannot be accommodated.
- 🟨 **Neutral**, because it requires reimplementing incremental rendering rather than reusing an existing table renderer.

### 4. Unified streaming with automatic column widths — one entry point, JSON bounded, table buffered *(chosen)*

One entry point for both modes. JSON marshals one item at a time; the styled table drains the sequence, then renders with
content-derived column widths.

- 🟩 **Good**, because memory is bounded on the path where large result sets will be realistic.
- 🟩 **Good**, because no cell is truncated, so identifiers and names always render in full.
- 🟩 **Good**, because callers have a single function and do not branch on output mode.
- 🟩 **Good**, because an incremental source can be consumed directly, and mid-stream errors stay distinguishable from exhaustion.
- 🟥 **Bad**, because memory is not bounded in styled mode, so option 3's uniform guarantee is not achieved.
- 🟥 **Bad**, because it changes the column-sizing policy and, as implemented, drops the terminal-width clamp.
- 🟥 **Bad**, because memory characteristics now differ by output mode, which must be documented to avoid surprise.
- 🟨 **Neutral**, because the human-facing path is bounded in practice by what a person will read, not by a hard limit.

## More Information

The chosen option is implemented by the streaming list helper added in <https://github.com/opentdf/platform/pull/3805>. This ADR records
the decision behind that implementation and scopes its adoption; the helper is in place but used by no list command, so the decision can
still be revisited cheaply.

This decision extends the output-formatting direction set in [ADR 0001](0001-printing-with-json.md), which centralized the choice
between styled and JSON output. Streaming keeps that single-entry-point property while changing how the chosen format is produced.

Follow-ups this ADR intentionally leaves open:

- How the streaming renderer should emit the JSON envelope, so records stream while `pagination` is still present.
- Whether the streamed styled table should be clamped to the detected terminal width, matching the non-streaming helper.
- Whether the streamed styled table should support the pagination footer available to the non-streaming helper.
- Whether the two table renderers should be consolidated once streaming is adopted more widely.
- Whether a truncated JSON array on mid-stream failure should be signalled beyond the non-zero exit status.
- Which sources become incremental first, since that is what converts this decision from latent to load-bearing.
