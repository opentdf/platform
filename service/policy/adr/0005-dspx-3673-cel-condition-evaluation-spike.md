# SPIKE: CEL as an alternative to bespoke condition operators

Status: Spike findings, DSPX-3673. Recommendation below is for discussion, not yet adopted.

Subject Mapping and Subject Condition Set evaluation matches entity values against policy using a
hand-written operator set. Issue [#3335](https://github.com/opentdf/platform/issues/3335) proposes
decomposing the operator enum into comparison + quantifier + case-insensitivity axes to add
`STARTS_WITH` / `ENDS_WITH` and `ALL` / `NONE` without enum sprawl. The DynamicValueMapping
subsystem (commit `090c0f6`) reuses `ConditionComparisonOperatorEnum` for the same matching
problem. This spike asks whether [CEL](https://cel.dev) (Common Expression Language) is a better
long-term fit than continuing to grow bespoke operators and their parallel evaluation code.

## Chosen Option: Hybrid

Keep the proto condition model as the stored, authored form. Add CEL as an internal evaluation
strategy: compile each stored condition to a CEL program once, cache it, and evaluate that program
on the hot path. Do not expose raw CEL to policy authors initially.

This captures CEL's benefits (one evaluation engine, new operators become expression changes
rather than enum + switch changes) without a proto break, without retraining authors on CEL
syntax, and without committing other-language SDKs to a CEL runtime before that cost is measured.

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

## Tradeoffs

**Safety.** CEL is non-Turing-complete, has no unbounded loops, and reads only host-provided data.
Expressions are type-checked at compile time, so a malformed condition is rejected before the hot
path (verified in the POC). This matches the safety posture of the current closed operator set.

**Performance.** Benchmarked; see `docs/performance/DSPX-3673-cel-condition-evaluation/`. CEL is
slower than the native switch per evaluation (24× at one condition, narrowing to ~4× at 50), staying
in the sub-microsecond to tens-of-microseconds range, and compile is three to four orders of
magnitude more than a single eval (84 µs to 2.3 ms), so CEL is only viable compile-once / cache. In
the full entitlements path, though, that gap is immaterial: the OPA wrapper costs ~100× a direct Go
call (69 ms vs 0.66 ms at 5,000 mappings), and the CEL-based path (4.5 ms) is an order of magnitude
under it. The operator engine is not the bottleneck in this path; the OPA layer is. CEL's per-eval
cost is acceptable relative to the path it would sit in, so performance is not the deciding factor.

**Auditability.** A CEL string is human-readable and reviewable. The decomposed proto model
(comparison + quantifier + flag) is also auditable and is what authors would continue to edit under
the hybrid option. Storing proto and deriving CEL keeps the audited artifact stable.

**Portability.** CEL has Go, C++, and Java runtimes sharing one spec, which helps if evaluation
moves across services. SDK clients in other languages would each need a CEL runtime only if raw
CEL is exposed to them. The hybrid option avoids that by keeping CEL internal to the service.

**Policy-Author UX.** Raw CEL is more expressive but is a new language for authors and for any
admin UI. Keeping the structured proto model as the authoring surface avoids that cost; CEL stays
an implementation detail.

**Existing Rego Path.** `subject_mapping_builtin.go` registers a `subjectmapping.resolve` builtin,
and `entitlements.rego` only calls that builtin. Rego does not evaluate operators; it wraps the Go
switch and pays protojson marshalling at the boundary (`entitlements.OpaInput`). So Rego is not a
third operator engine, and the benchmark measures it as wrapper overhead: ~100× a direct Go call and
~130× the allocations (665,686 vs 5,077 allocs/op at 5,000 mappings). Removing or replacing the OPA
layer is a larger performance lever than the operator engine, and is independent of the CEL decision.

## Migration and Backward Compatibility

The condition stays in proto. Migration is internal:

1. Lower a stored `Condition` to a CEL source string: the deprecated `operator` field and the
   decomposed `comparison` / `quantifier` / `case_insensitive` fields map to the expressions in the
   table above. `celeval` already implements this. Existing stored conditions need no rewrite.
2. Compile and cache the CEL program per condition (cache key on the lowered source). Evaluate the
   cached program in place of the operator switch.
3. Run CEL and the native switch side by side in tests until parity is established, then make CEL the
   evaluation path. `celeval`'s equivalence test against `EvaluateSubjectSet` is the seed.

No proto change, no stored-data migration, and the deprecated `operator` field keeps working
because it is one input to the lowering step.

## Options Considered

### Keep Adding Bespoke Operators
Continue the #3335 direction: decomposed enums plus a hand-written switch per axis. Lowest
immediate change. Each new matching need still means proto plus Go plus a parallel implementation
in DynamicValueMapping. Rejected as the long-term path because it does not stop the sprawl this
spike was asked to address.

### Expose Raw CEL to Authors
Store CEL strings directly as the condition. Most expressive and fewest moving parts internally.
Rejected for now: it is a proto and authoring-surface change, pushes a CEL runtime onto every SDK
client that reads conditions, and removes the structured model admin tooling relies on. Worth
revisiting if internal CEL adoption succeeds.

### Hybrid (Chosen)
Proto stays the authored and stored form; CEL is the internal evaluation strategy. Stops operator
sprawl in the evaluator, no proto break, no author retraining, defers the multi-language runtime
question. The benchmark closes the original open item: CEL is slower than the switch but its cost is
small next to the OPA wrapper that surrounds it, so performance does not block adoption. The
remaining open item is the OPA layer itself, which dominates the path and is worth its own decision.

## References

- Decompose operators: https://github.com/opentdf/platform/issues/3335
- DynamicValueMapping protos: commit `090c0f65508058502d17a850691957b7beaee785`
- CEL: https://cel.dev and https://github.com/google/cel-go
- POC: `service/internal/subjectmappingbuiltin/cel_poc_test.go`
- Experimental evaluator: `service/internal/subjectmappingbuiltin/celeval/` (lowering + tests; unwired)
- Benchmarks and results: `docs/performance/DSPX-3673-cel-condition-evaluation/`
- Native evaluation: `service/internal/subjectmappingbuiltin/subject_mapping_builtin.go`
- Prior spike (format reference): DSPX-2754
