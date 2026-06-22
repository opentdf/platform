# Entitlements Fetch Path: Full Policy Load vs By-FQN

A reproducible benchmark for [DSPX-2541](https://virtru.atlassian.net/browse/DSPX-2541), comparing how
the decisioning/entitlement path fetches the policy it needs:

- **fullload (before).** The PDP loads the entire policy on every construction and refresh.
  `EntitlementPolicyRetriever.ListAllAttributes` / `ListAllSubjectMappings`
  ([`service/internal/access/v2/policy_store.go`](../../../service/internal/access/v2/policy_store.go))
  page the whole DB, then `NewPolicyDecisionPoint` builds a value-FQN → (attribute, value, subject
  mappings) map over all of it.
- **byfqns (after).** `GetEntitleableAttributesByFqns`
  ([`service/policy/db/attribute_fqn.go`](../../../service/policy/db/attribute_fqn.go)) fetches only the
  value FQNs a decision references, in a bounded number of selective queries.

## Corpus

Mirrors the NG SAP reference scale: one `ANY_OF` definition, **5,000** attribute values, and **N**
subject mappings spread across the values (so each value carries ~N/5,000 mappings). N is swept across
`10k, 50k, 100k, 500k, 1M`. Each decision references **K = 10** value FQNs.

## Hypothesis

- **fullload: O(total policy N).** It reads and indexes every attribute value and every subject mapping
  regardless of what the decision needs, on every load/refresh.
- **byfqns: O(K + mappings on those K values).** It reads only the requested values' definitions and
  their subject mappings (~K·N/5,000 here), independent of the rest of the policy.

Expectation: `fullload` latency grows with N; `byfqns` stays orders of magnitude lower and grows only
with the mappings attached to the requested values.

## What It Measures

`TestEntitleableFetchBenchmark` (`service/integration/entitleable_fetch_db_bench_test.go`, build tag
`entbench`) seeds each corpus against a real Postgres and records, per scale point:

| column | meaning |
|--------|---------|
| `mode` | `fullload` or `byfqns` |
| `n`    | total subject mappings |
| `k`    | requested value FQNs (10) |
| `ms`   | fetch latency in milliseconds |
| `rows` | subject mappings returned/loaded |
| `pages`| list pages read (`fullload`) |

## Running

Requires Docker (testcontainers Postgres). From a fresh clone:

```bash
bash docs/performance/DSPX-2541-entitleable-attributes/run-db.sh
# bound runtime / disk on a smaller host:
ENT_BENCH_MAX_N=100000 bash docs/performance/DSPX-2541-entitleable-attributes/run-db.sh
```

Outputs `results.csv` and `charts/fetch_ms.svg`. The bench is build-tagged, so it never runs in normal
`go test ./...` or CI.

## Results

`results.csv` / `charts/fetch_ms.svg` are committed from a capped run (`ENT_BENCH_MAX_N=50000`, single
local testcontainer); regenerate the full `10k…1M` sweep with `run-db.sh`.

| mode | N | rows | ms |
|------|----|------|-----|
| fullload | 10,000 | 10,000 | 901 |
| byfqns | 10,000 | 20 | 510 |
| fullload | 50,000 | 50,000 | 6,518 |
| byfqns | 50,000 | 100 | 1,618 |

`fullload` latency climbs steeply with N (deep-OFFSET paging over the whole corpus), and it always
returns the entire policy. `byfqns` returns only the requested values' mappings (~K·N/5,000) and stays
well below `fullload`.

Observation worth a follow-up: `byfqns` latency (1.6 s for 100 rows at N=50k) is high relative to the
row count, which points at the `getSubjectMappingsByValueFqns` filter scanning rather than using an
index on the `subject_mappings → attribute_values → attribute_fqns` join. An index there (cf. the
existing `optimize-entitlement-list-indices` migration) should flatten `byfqns` further.

## Scope

This benchmark covers the **DB fetch path**, which is what the new API changes. Wiring the new API into
the in-memory PDP / `GetDecision` (so a decision no longer triggers a full-policy load) is a follow-up
(the decisioning migration), tracked separately and pending the namespace-scoping/tenancy model; an
in-memory decision-latency benchmark belongs with that change.
