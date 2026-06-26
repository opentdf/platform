# SPIKE: CEL as an alternative to bespoke condition operators

Status: Spike findings. Recommendation below is for discussion, not yet adopted.

Subject Mapping and Subject Condition Set evaluation matches entity values against policy using a
hand-written operator set. Issue [#3335](https://github.com/opentdf/platform/issues/3335) proposes
decomposing the operator enum into comparison + quantifier + case-insensitivity axes to add
`STARTS_WITH` / `ENDS_WITH` and `ALL` / `NONE` without enum sprawl. The DynamicValueMapping
subsystem (commit `090c0f6`) reuses `ConditionComparisonOperatorEnum` for the same matching
problem. This spike asks whether [CEL](https://cel.dev) (Common Expression Language) is a better
long-term fit than continuing to grow bespoke operators and their parallel evaluation code.

## Recommended Option: Raw CEL

Store the condition as a CEL expression and evaluate it directly. The stored artifact is the
executed artifact, so there is no second representation to lower or keep in sync.

The deciding factor is expressiveness. The decomposed comparison + quantifier + case_insensitivity
axes only compare one selector's string values against a fixed string list. Real ABAC needs sit
outside that shape: numeric/ordinal clearance, cross-field comparisons, dynamic set-vs-set relations
(the DynamicValueMapping problem), cardinality, and regex/glob (already deferred by #3335). CEL
expresses all of these; the axes cannot grow into them without becoming a query language (see
[Expressiveness](#expressiveness)). The per-evaluation cost is higher than the native switch but
small against a v2 decision, which is dominated by policy fetch and PDP construction (see
[Tradeoffs](#tradeoffs)), so performance does not constrain the choice. One engine then covers subject
mappings and DynamicValueMapping, and new capabilities need no schema change.

The costs are real but one-time and bounded: a proto/storage change with a migration that backfills
existing conditions to CEL (the `celeval` lowering already does this), server-side validation on
write, and authoring guardrails. These are detailed in [Migration](#migration-and-backward-compatibility)
and [Options Considered](#options-considered).

## What the Spike Built

`service/internal/subjectmappingbuiltin/cel_poc_test.go` builds a cel-go environment and, for a
matrix of operators, target sets, and entities, asserts the CEL result equals the native
`EvaluateCondition` result (`service/internal/subjectmappingbuiltin/subject_mapping_builtin.go`).
`cel-go v0.26.1` is already in `service/go.mod` (it backs proto/buf validation); the spike promotes
it from indirect to direct.

Verified results:

- Every legacy operator (`IN`, `NOT_IN`, `IN_CONTAINS`) matches the native switch across all tested
  entities and target sets.
- The decomposed cases from #3335 that the legacy enum cannot express are evaluable in CEL: the
  `ALL` quantifier, case-insensitive comparison (`lowerAscii()` from the cel-go strings
  extension), and `ENDS_WITH` for safe email-domain matching.
- Invalid expressions fail at `env.Compile`, before evaluation.

Entity value extraction still uses the existing `flattening` helpers
(`lib/flattening/flatten.go`); CEL replaces only the operator switch, not selector resolution.

## Operator Mapping

`values` are the entity values resolved by the selector; `targets` are
`condition.subject_external_values`.

| Current / proposed operator | CEL expression |
| --- | --- |
| `IN` (ANY + EQUALS) | `targets.exists(t, t in values)` |
| `NOT_IN` (NONE) | `!targets.exists(t, t in values)` |
| `IN_CONTAINS` (ANY + CONTAINS) | `targets.exists(t, values.exists(v, v.contains(t)))` |
| `ALL` + EQUALS (#3335) | `targets.all(t, t in values)` |
| `STARTS_WITH` (#3335) | `targets.exists(t, values.exists(v, v.startsWith(t)))` |
| `ENDS_WITH` (#3335) | `targets.exists(t, values.exists(v, v.endsWith(t)))` |
| case-insensitive EQUALS | `targets.exists(t, values.exists(v, v.lowerAscii() == t.lowerAscii()))` |

The comparison axis maps to CEL string functions, the quantifier axis maps to `exists` / `all` /
negation, and case-insensitivity maps to `lowerAscii()`. The 24 combinations #3335 lists as
enum + flag combinations are compositions of these primitives.

## Expressiveness

The decomposed axes cover exactly one shape: one selector's string values compared against a fixed
string list, under a quantifier, optionally case-insensitive. The following needs sit outside that
shape. Each is a one-line CEL expression and each would otherwise be a new proto field plus new Go
(and a duplicate in DynamicValueMapping).

| Need | CEL | Why the axes can't |
| --- | --- | --- |
| Regex / glob (deferred by #3335) | `entity.email.matches('.*@acme\\.(com\|org)$')` | No pattern operator; explicitly out of scope in #3335 |
| Numeric / ordinal (hierarchical clearance) | `int(entity.clearance) >= 3` | Comparisons are string-only; no `>`/`>=`/`<` |
| Cross-field (two entity fields) | `entity.dept == entity.managerDept` | Right side is always a static target list, never another selector |
| Dynamic set-vs-set (resource vs entity) | `resource.compartments.all(c, c in entity.compartments)` | Both sides dynamic; quantifiers only range over a static list |
| Cardinality ("at least N of") | `["a","b","c"].filter(x, x in entity.groups).size() >= 2` | No count or threshold quantifier |
| Conditional logic | `entity.region == 'EU' ? hasX : hasY` | No branching |
| Temporal window | `timestamp(entity.validUntil) > now` | No types or time |

The first three are the most relevant to OpenTDF ABAC: hierarchical/numeric clearance and dynamic
set-vs-set (the DynamicValueMapping problem) are patterns the string axes cannot reach, and regex is
already on the deferred list.

Caveat: these become available only if the evaluation context exposes typed, structured
entity/resource objects to CEL. The spike binds per-selector string lists (to stay equivalent to the
native evaluator), so as built it would not do numeric or cross-field either. The expressive
advantage is real but contingent on enriching what the evaluator is given, which raw CEL makes
worthwhile because the authored expression can use it directly.

## Tradeoffs

**Safety.** CEL is non-Turing-complete, has no unbounded loops, and reads only host-provided data.
Expressions are type-checked at compile time, so a malformed condition is rejected before the hot
path (verified in the POC). This matches the safety posture of the current closed operator set.

**Performance.** Benchmarked; see `docs/performance/cel-condition-evaluation/`. The native Go switch
is faster per evaluation than CEL for both operator sets: legacy 24 ns–8.2 µs, decomposed 48 ns–9.1 µs,
with CEL 3.7–23× slower depending on size, all in the sub-microsecond to tens-of-microseconds range.
At the entitlements level (N subject mappings on a decision) native stays ~6–7× ahead (e.g. 0.70 ms
vs 4.6 ms at 5,000 mappings), both linear in N. CEL compile is three to four orders of magnitude more
than one eval (80 µs–2.3 ms), so any CEL path must compile-once / cache. The v2 PDP
(`service/internal/access/v2`) evaluates in pure Go with no OPA, and per the v2 PDP performance work a
decision is dominated by policy fetch/load and PDP construction, not per-decision evaluation. So this
microsecond-to-low-millisecond engine difference is a small slice of a v2 decision, and performance
does not constrain the engine choice.

**Expressiveness.** This is the decisive advantage and the reason to favor raw CEL. The decomposed
axes cover one shape (selector values vs a static string list); CEL covers regex, numeric/ordinal,
cross-field, dynamic set-vs-set, cardinality, conditional, and temporal logic in one line each (see
[Expressiveness](#expressiveness)). Stored as CEL, each new capability needs no schema change;
stored as decomposed protos, each is another proto field plus Go plus a DynamicValueMapping
duplicate.

**Auditability.** A stored CEL string is human-readable and is the exact artifact evaluated, with no
proto→CEL lowering step between what is reviewed and what runs. The structured proto model is also
auditable, but under any CEL option the proto and the executed expression are two artifacts to keep
aligned; raw CEL removes that gap.

**Portability.** A condition stored as a CEL string transports as a plain string, so SDK clients
that only CRUD policy need no CEL runtime (the Go SDK is pass-through, `sdk/sdkconnect/subjectmapping.go`,
and nothing outside `service` imports cel-go). A CEL runtime in another language is needed only by
consumers that validate or render a condition client-side (admin UIs, non-Go tooling, a future
client-side PDP); server-side `cel.Compile` plus protovalidate covers validation on write. The
original "every SDK needs CEL" concern was overstated.

**Policy-Author UX.** Raw CEL is a language authors and admin UIs must learn, the real UX cost of
this option. Mitigations: a constrained CEL environment (only the selectors/functions policy needs),
server-side compile + protovalidate so malformed expressions are rejected on write, and a documented
library of expressions for the common cases the decomposed axes covered.

**No OPA In v2.** OPA/rego exists only in the legacy v1 authorization service; the v2 path
(`service/internal/access/v2`) evaluates subject mappings in pure Go (`pdp.go:460`). So this decision
is purely native Go switch vs CEL within v2; there is no OPA layer to weigh, and the engine choice is
independent of the v1 path being retired.

## Migration and Backward Compatibility

Raw CEL is a proto/storage change, so migration is the main cost of this option. It is bounded and
the lowering tool already exists:

1. Add a CEL `expression` field to the condition. During transition, keep the legacy `operator` and
   the decomposed `comparison` / `quantifier` / `case_insensitive` fields readable.
2. Backfill: lower every existing stored condition to a CEL string with `celeval` (already
   implemented and equivalence-tested against `EvaluateSubjectSet`), and persist the result in
   `expression`. No condition is authored by hand to migrate.
3. Evaluate `expression` (compile-once / cache). Validate on write with `cel.Compile` against the
   constrained environment plus protovalidate. Where `expression` is empty (not yet backfilled),
   fall back to lowering the structured fields on the fly, so old and new rows both evaluate.
4. Once backfill completes and clients author `expression` directly, deprecate the structured fields.

`celeval`, built in the spike as the equivalence proof, is the backfill tool, so the migration carries
no new lowering code.

## Options Considered

All three are viable; the decomposition merging recently makes the status quo a serious contender,
and the data makes the cost differences concrete.

### Keep Bespoke (decomposed)
Continue the #3335 direction: decomposed enums plus a hand-written switch per axis.

- ✅ Fastest per evaluation: native 24 ns–8.2 µs (legacy), 48 ns–9.1 µs (decomposed), 3.7–23× ahead
  of CEL.
- ✅ No new runtime dependency; the proto decomposition is already merged; authoring surface, SDKs,
  and admin tooling are unchanged.
- ✅ The decomposition already curbs the original enum-sprawl concern (3 axes + 1 flag = 24 combos).
- 🔴 The decomposed axes are not yet evaluated in Go (`EvaluateCondition` only switches on the legacy
  operator); honoring them needs new hand-written switch arms, duplicated again in DynamicValueMapping.
- 🔴 Cannot express needs beyond static string matching (regex/glob, numeric/ordinal, cross-field,
  dynamic set-vs-set, cardinality, conditional, temporal). Each such need is another proto + Go
  change, so the sprawl returns the moment requirements move past the axes.

### Hybrid CEL
Proto stays the authored and stored form; CEL is the internal evaluation strategy (compile each
stored condition to a cached CEL program).

- ✅ One evaluation engine; the decomposed axes are already implemented via `celeval` lowering
  (tested); new operators become expression changes, not enum + switch changes.
- ✅ Expressiveness: with a richer typed context, reaches the regex/numeric/cross-field/set/cardinality
  cases the axes cannot.
- ✅ No proto break and no SDK impact (CEL stays server-internal); eval cost small vs policy fetch / PDP construction in v2.
- 🔴 Slower per eval than native, plus compile cost (80 µs–2.3 ms), so it needs a compile/cache layer.
- 🔴 Two representations to keep aligned (proto ↔ lowered CEL); the lowering is code to own and test.
- 🔴 The expressiveness gains still need a typed entity/resource context, and authors keep editing the
  structured proto, so they cannot use that power directly.

### Raw CEL (Recommended)
Store the CEL expression as the condition and evaluate it directly.

- ✅ Maximum expressiveness, authored directly: regex, numeric/ordinal, cross-field, dynamic
  set-vs-set, cardinality, conditional, temporal (see [Expressiveness](#expressiveness)).
- ✅ No lowering layer and no proto ↔ CEL drift; the stored artifact is the executed artifact.
- ✅ One engine across subject mappings and DynamicValueMapping; new capabilities need no schema
  change.
- ✅ Eval cost equals hybrid and is small against policy fetch / PDP construction in v2.
- 🔴 Proto/storage change superseding the just-merged structured axes; needs a migration (the
  `celeval` lowering backfills existing conditions, so no hand authoring).
- 🔴 Client-side validation or rendering needs a CEL runtime in that language (not transport, which is
  just a string); mitigated by server-side `cel.Compile` + protovalidate.
- 🔴 Authoring UX: authors and admin UIs write CEL instead of structured fields; needs a constrained
  CEL environment and a documented expression library as guardrails.
- 🔴 Slower per eval than native, but small against a v2 decision (policy fetch / PDP construction).

Recommended because expressiveness is the durable differentiator the decomposed axes structurally cannot
grow into, the per-eval cost is paid where it does not matter (a v2 decision is dominated by policy
fetch and PDP construction, not per-decision evaluation), and storing CEL directly avoids a proto↔CEL
sync layer. The migration, client-side validation, and authoring guardrails are one-time, bounded
costs.

## References

- Decompose operators: https://github.com/opentdf/platform/issues/3335
- DynamicValueMapping protos: commit `090c0f65508058502d17a850691957b7beaee785`
- CEL: https://cel.dev and https://github.com/google/cel-go
- POC: `service/internal/subjectmappingbuiltin/cel_poc_test.go`
- Experimental evaluator: `service/internal/subjectmappingbuiltin/celeval/` (lowering + tests; unwired)
- Benchmarks and results: `docs/performance/cel-condition-evaluation/`
- Native evaluation: `service/internal/subjectmappingbuiltin/subject_mapping_builtin.go`
