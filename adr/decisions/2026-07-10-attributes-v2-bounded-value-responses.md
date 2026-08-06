---
status: proposed
date: 2026-07-10
tags:
 - policy
 - attributes
 - pagination
 - performance
driver: Eugene Yakhnenko
---
# Bounded attribute value responses in the Attributes Service

## Context and Problem Statement

`ListAttributes`, `GetAttribute`, and `ListAttributesByFqns` return all attribute values inline via unbounded `JSON_AGG`. High-cardinality attributes cause Postgres memory pressure, oversized gRPC responses, and high latency.

`ListAttributeValues` was removed in [PR #3108](https://github.com/opentdf/platform/pull/3108), leaving no paginated way to fetch values.

See [issue #3744](https://github.com/opentdf/platform/issues/3744).

## Decision Drivers

* Eliminate unbounded `JSON_AGG` on attribute values
* Provide paginated value retrieval
* No breaking changes to v1 consumers
* Follow existing platform patterns (`ListRegisteredResourceValues`, authorization v2)
* Support multi-attribute value fetching in a single call

## Considered Options

1. **Modify v1 RPCs**: add `values_pagination` to existing requests
2. **v2 with inline sub-pagination**: v2 `GetAttribute` returns paginated values inline, `ListAttributes` strips values
3. **v2 with dedicated ListAttributeValues**: v2 strips values from all attribute RPCs, new `ListAttributeValues` RPC with pagination
4. **Application-layer cap**: `LIMIT` inside `JSON_AGG`, no API changes
5. **Do nothing**: accept current behavior

## Pros and Cons of the Options

### Option 1: Modify v1 RPCs

Add optional `values_pagination` to v1 requests. Default returns all values for backward compatibility.

* 🟩 **Good**, no new service version or RPCs
* 🟩 **Good**, existing consumers unaffected
* 🟥 **Bad**, default path still unbounded
* 🟥 **Bad**, per-attribute pagination cursors inside a list response is complex
* 🟥 **Bad**, Postgres still joins and aggregates all values unless SQL is restructured
* 🟥 **Bad**, using the optional field changes the response shape, making it a breaking change disguised as an optional parameter

### Option 2: v2 with inline sub-pagination on GetAttribute

v2 `ListAttributes` strips values. v2 `GetAttribute` returns attribute + paginated values.

* 🟩 **Good**, single call returns attribute + first page of values
* 🟥 **Bad**, SQL still joins values even when caller only needs attribute metadata
* 🟥 **Bad**, no existing platform pattern for inline sub-resource pagination

### Option 3: v2 with dedicated ListAttributeValues RPC

v2 `ListAttributes` and `GetAttribute` return attributes without values. Separate `ListAttributeValues` RPC with state/sort/search filters, accepts `repeated attribute_ids`.

* 🟩 **Good**, attribute queries fully decoupled from values: no `JSON_AGG`
* 🟩 **Good**, follows `ListRegisteredResourceValues` pattern
* 🟩 **Good**, multi-attribute fetch in one paginated call avoids N+1
* 🟩 **Good**, v2 versioning follows authorization v2 pattern, non-breaking
* 🟥 **Bad**, consumers need two calls for attribute + values
* 🟥 **Bad**, new SQL queries partially duplicate existing ones (minus values join)

### Option 4: Application-layer cap

Cap values via `LIMIT` in `JSON_AGG` (truncate) or error when a threshold is exceeded. No API changes.

* 🟩 **Good**, minimal code change
* 🟥 **Bad**, breaking change either way: truncation drops data silently, erroring fails previously working calls
* 🟥 **Bad**, no pagination mechanism to retrieve beyond the cap
* 🟥 **Bad**, requires SQL restructuring (e.g., lateral subqueries) to avoid full aggregation before capping

### Option 5: Do nothing

Operators manage attribute cardinality through governance.

* 🟩 **Good**, zero effort
* 🟥 **Bad**, no guardrail: one high-cardinality attribute can degrade the service
* 🟥 **Bad**, no paginated value retrieval exists
* 🟥 **Bad**, risk is invisible to operators until an outage

## Decision Outcome

Chosen option: **Option 3, v2 with dedicated ListAttributeValues RPC**. Attribute queries are fully decoupled from value queries, follows existing platform patterns, and is non-breaking.

`repeated attribute_ids` is capped (e.g., 100) and validated server-side to prevent shifting unbounded pressure from output to input. Pagination applies across all matched values flattened.

`ListAttributesByFqns` is replaced by v2 `ListAttributes` with an FQN filter.

### Rejected Alternatives

* **Option 1: Modify v1 RPCs**: breaking change disguised as an optional field.
* **Option 4: Application-layer cap**: breaking change with no pagination path forward.

## Validation

{To be filled after decision is accepted.}

## More Information

* [Issue #3744](https://github.com/opentdf/platform/issues/3744)
* [PR #3108](https://github.com/opentdf/platform/pull/3108) removed `ListAttributeValues`
* Platform patterns: `ListRegisteredResourceValues`, `authorization/v2`, `PageRequest`/`PageResponse`
