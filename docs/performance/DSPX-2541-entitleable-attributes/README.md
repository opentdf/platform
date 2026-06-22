# Entitlements Optimization Benchmarks (DSPX-2541)

Reproducible benchmarks for [DSPX-2541](https://virtru.atlassian.net/browse/DSPX-2541), quantifying the
cost of the decisioning/entitlement path and the projected win from fetching only what's needed. Two
layers, both below the RPC server (matching the `dspx-2754-perf-test` approach — no wired client/server):

1. **In-Memory PDP** (no Docker): construction time, retained heap, and per-operation latency for
   `GetDecision` and `GetEntitlements`.
2. **DB Fetch** (Docker): the cost of fetching policy from Postgres, full-load vs by-FQN.

The corpus mirrors the NG SAP reference scale: one `ANY_OF` definition, 5,000 attribute values, and N
subject mappings spread across them (~N/5,000 per value), swept `10k…1M`.

## Layer 1: In-Memory PDP (`GetDecision` + `GetEntitlements`)

`TestEntitleablePDPBenchmark` (`service/internal/access/v2/entitleable_pdp_bench_test.go`, build tag
`entpdpbench`) measures two modes per operation:

- **full** — `NewPolicyDecisionPoint` over ALL policy (today's per-request load), then the operation.
- **scoped** — PDP over only the subset the operation needs (the resource's value+SMs for a decision;
  the entity's matched values+SMs for entitlements). Projects the optimized fetch the migration (PR B2)
  would realize. It is shape-independent (in-memory protos through the existing PDP) and uses an `ANY_OF`
  corpus so the needed subset is unambiguous. `scoped` is a projected lower bound, not the built
  optimization.

Run (no Docker):
```bash
bash docs/performance/DSPX-2541-entitleable-attributes/run.sh
ENT_PDP_MAX_N=100000 bash docs/performance/DSPX-2541-entitleable-attributes/run.sh   # cap for speed
```
Outputs `pdp_results.csv` and `charts/pdp_{decision,entitlements}_{latency,heap}.svg`.

### Results (full `10k…1M` run)

`GetEntitlements` is the dramatic win — `full` grows O(N) in both latency and heap; `scoped` tracks the
entity's matched set (50 compartments), ~100× lower at 1M:

| op | mode | N | construct ms | heap MB | p50 latency |
|----|------|----|-------------|---------|-------------|
| entitlements | full | 1,000,000 | 58.0 | 873.7 | **927.6 ms** |
| entitlements | scoped | 1,000,000 | 0.6 | 8.5 | **9.1 ms** |
| entitlements | full | 100,000 | 7.1 | 88.6 | 82.0 ms |
| entitlements | scoped | 100,000 | 0.04 | 0.5 | 1.0 ms |

`GetDecision`'s per-call evaluation is already cheap (~28 µs at 1M, both modes) because it only touches
the resource value's mappings. Its cost is the **construction + heap** of loading all policy per request,
which `scoped` removes:

| op | mode | N | construct ms | heap MB | p50 latency |
|----|------|----|-------------|---------|-------------|
| decision | full | 1,000,000 | 67.5 | 873.4 | 28.3 µs |
| decision | scoped | 1,000,000 | 0.008 | ~0 | 24.0 µs |

Takeaway: the full-policy load is the dominant per-request cost (873 MB at 1M). For entitlements it also
dominates latency (linear in N); for decisions it's construction/memory. Both collapse under `scoped`.

## Layer 2: DB Fetch (full-load vs by-FQN)

`TestEntitleableFetchBenchmark` (`service/integration/entitleable_fetch_db_bench_test.go`, build tag
`entbench`) seeds N subject mappings against a real Postgres (testcontainers) and measures, per scale
point, two fetch paths for serving a decision over K=10 value FQNs:

- **fullload** — page all attributes + all subject mappings (the PDP cache build today).
- **byfqns** — `GetEntitleableAttributesByFqns` for the requested FQNs.

Run (requires Docker):
```bash
bash docs/performance/DSPX-2541-entitleable-attributes/run-db.sh
ENT_BENCH_MAX_N=100000 bash docs/performance/DSPX-2541-entitleable-attributes/run-db.sh
```
Outputs `results.csv` and `charts/fetch_ms.svg`. `results.csv` is committed from a capped run
(`ENT_BENCH_MAX_N=50000`); regenerate the full sweep with the script.

| mode | N | rows | ms |
|------|----|------|-----|
| fullload | 10,000 | 10,000 | 901 |
| byfqns | 10,000 | 20 | 510 |
| fullload | 50,000 | 50,000 | 6,518 |
| byfqns | 50,000 | 100 | 1,618 |

Observation worth a follow-up: `byfqns` latency (1.6 s for 100 rows at N=50k) is high relative to the row
count, pointing at the `getSubjectMappingsByValueFqns` filter scanning rather than using an index on the
`subject_mappings → attribute_values → attribute_fqns` join (cf. the existing
`optimize-entitlement-list-indices` migration). An index there should flatten `byfqns` further.

## Scope

Both layers test below the RPC server, matching the `dspx-2754-perf-test` approach (no wired client /
server / ERS / Keycloak). `full` rows measure the existing code at scale; `scoped` rows project the
optimization the migration (PR B2) would realize, and are valid independent of the still-open API-shape
decisions (368/392) because they run in-memory through the existing PDP on an `ANY_OF` corpus. Hierarchy
projection is deferred until that shape settles. The wired full-request-path benchmark is also out of
scope here.
