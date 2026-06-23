# CEL vs Native Condition Evaluation Benchmarks (DSPX-3673)

Reproducible benchmarks for [DSPX-3673](https://virtru.atlassian.net/browse/DSPX-3673), the spike
asking whether [CEL](https://cel.dev) should replace the bespoke Subject Mapping condition operators
(see `service/policy/adr/0005-dspx-3673-cel-condition-evaluation-spike.md`). Two layers, both
in-memory below the RPC server (matching the `dspx-2754-perf-test` and `DSPX-2541-entitleable-perf-test`
approach, no wired client / server / ERS / Keycloak):

1. **Operator Engine** (no Docker): per-evaluation cost of the native operator switch vs a precompiled
   CEL program, plus the one-time CEL compile cost, swept over condition complexity.
2. **Full Entitlements Path** (no Docker): the cost of computing entitlements three ways, swept over
   subject-mapping count, to separate the OPA wrapper overhead from the operator engine.

A key structural finding sets up Layer 2: `entitlements.rego` only calls the `subjectmapping.resolve`
Go builtin (`service/internal/subjectmappingbuiltin`), so Rego does not evaluate operators. The choice
is CEL vs the Go switch; Rego is an orchestration wrapper measured separately.

## Layer 1: Operator Engine

`TestCELOperatorBenchmark` (`service/internal/subjectmappingbuiltin/cel_operator_bench_test.go`, build
tag `celbench`) builds a `SubjectSet` of `groups × conds` conditions (mixed IN / NOT_IN / IN_CONTAINS,
crafted so every condition is true and the whole set is traversed) and times three arms:

- **native** — `EvaluateSubjectSet` (the hand-written switch).
- **cel** — a `cel.Program` compiled once from the SubjectSet (`celeval`), evaluated per call by
  binding the entity's selector values.
- **cel_compile** — the one-time cost of compiling that program (amortized under compile-once / cache).

Run (no Docker):
```bash
bash docs/performance/DSPX-3673-cel-condition-evaluation/run.sh   # runs both layers
```
Outputs `results.csv` and `charts/operator_latency.svg`.

### Results

| arm | 1×1 | 3×3 (9 conds) | 10×5 (50 conds) |
|-----|-----|---------------|-----------------|
| native | 22 ns | 490 ns | 8.6 µs |
| cel (per-eval) | 532 ns | 4.8 µs | 32.1 µs |
| cel_compile (one-time) | 84 µs | 355 µs | 2.3 ms |
| cel / native | 24× | 9.8× | 3.7× |

The native switch is faster per evaluation at every size (24× at one condition, narrowing to ~4× at
50). CEL's per-eval cost stays in the sub-microsecond to tens-of-microseconds range. Compile is three
to four orders of magnitude more expensive than a single eval, so CEL is only viable with
compile-once / cache, never compile-per-request.

## Layer 2: Full Entitlements Path

`TestCELFullPathBenchmark` (`service/authorization/cel_fullpath_bench_test.go`, build tag `celbench`)
builds N attribute mappings (each one subject mapping matching a single entity) and times three ways
to produce entitlements over the same policy + entity:

- **rego** — the status quo: `entitlements.OpaInput` (protojson marshal) plus the prepared OPA query,
  which calls the builtin into `EvaluateSubjectMappingMultipleEntities`.
- **go_switch** — `EvaluateSubjectMappingMultipleEntities` directly, no OPA.
- **go_cel** — the same orchestration with condition evaluation via precompiled CEL (`celeval`).

Run (no Docker):
```bash
bash docs/performance/DSPX-3673-cel-condition-evaluation/run.sh
CEL_BENCH_MAX_N=1000 bash docs/performance/DSPX-3673-cel-condition-evaluation/run.sh   # cap N for speed
```
Outputs `fullpath_results.csv` and `charts/fullpath_{latency,allocs}.svg`.

### Results

| arm | N=100 | N=1,000 | N=5,000 |
|-----|-------|---------|---------|
| rego | 1.43 ms | 13.2 ms | 69.2 ms |
| go_switch | 9.1 µs | 128 µs | 657 µs |
| go_cel | 68 µs | 725 µs | 4.5 ms |
| rego / go_switch | 158× | 103× | 105× |
| go_cel / go_switch | 7.5× | 5.7× | 6.9× |

The OPA wrapper dominates: Rego is ~100× slower than a direct Go call and allocates ~130× more
(665,686 vs 5,077 allocs/op at N=5,000). Against that, the operator engine difference is small: `go_cel`
is ~6–7× `go_switch`, but both are an order of magnitude under `rego`. The operator engine is not the
bottleneck in the entitlements path; the OPA layer is.

## Takeaway

CEL is slower than the native switch (Layer 1), but in the path where it would actually run (Layer 2)
that difference is dwarfed by the OPA wrapper. The case for CEL is maintainability (one engine, new
operators become expression changes), not speed, and its cost is acceptable relative to the path it
sits in. The larger performance lever surfaced here is the OPA wrapper itself, independent of the
operator engine.

## Environment

Measured on Apple M4 Max, `go version go1.26.1 darwin/arm64`. Numbers are machine-dependent; the ratios
are the portable result. `results.csv` and `fullpath_results.csv` are committed from a full run; the
race detector is off (it skews timing). Regenerate with `run.sh`.

## Scope

Both layers run in-memory below the RPC server, matching the `DSPX-2541-entitleable-perf-test` approach
(no wired client / server / ERS / Keycloak / DB). `celeval` is an experimental, unwired reference
evaluator for the spike; it is not on any request path. The benchmark quantifies the OPA overhead but
does not remove it. Hierarchy and multi-entity fan-out are out of scope.
