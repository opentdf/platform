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

The `AttributesService` RPCs `ListAttributes`, `GetAttribute`, and `ListAttributesByFqns` return **all** attribute values inline via unbounded `JSON_AGG` in SQL. There is no pagination or limit on the number of values returned per attribute.

An attribute with a large number of values (thousands or more) causes:
- High memory pressure on Postgres during aggregation
- Oversized gRPC responses that stress client and server memory
- High latency on what should be lightweight list/get operations

The dedicated `ListAttributeValues` RPC was removed in [PR #3108](https://github.com/opentdf/platform/pull/3108) as "redundant," leaving no paginated way to retrieve values independently.

See [issue #3744](https://github.com/opentdf/platform/issues/3744) for full details.

## Decision Drivers

* Must eliminate unbounded `JSON_AGG` on attribute values in Postgres queries
* Must provide a paginated way to retrieve attribute values
* Must not break existing v1 API consumers
* Should follow existing platform patterns (e.g., `ListRegisteredResourceValues` for paginated sub-resources, authorization v2 for service versioning)
* Should allow fetching values across multiple attributes in a single call to avoid N+1 round trips

## Considered Options

1. **Modify v1 RPCs to add pagination on values**: add a `values_pagination` field to `ListAttributesRequest` and `GetAttributeRequest` to limit and paginate inline values
2. **v2 service: keep values on GetAttribute with sub-pagination**: introduce a v2 with paginated inline values on `GetAttribute`, strip values from `ListAttributes`
3. **v2 service: strip values entirely, add dedicated ListAttributeValues RPC**: v2 `ListAttributes` and `GetAttribute` return attributes without values; a new `ListAttributeValues` RPC provides paginated value access
4. **Application-layer cap**: add a `LIMIT` inside the `JSON_AGG` subquery (e.g., cap at 1000 values) without changing the API surface

## Pros and Cons of the Options

### Option 1: Modify v1 RPCs to add pagination on values

Add optional `values_pagination` (PageRequest) to v1 `ListAttributesRequest` and `GetAttributeRequest`. Default behavior returns all values for backward compatibility; when pagination is provided, values are bounded.

* 🟩 **Good**, because no new service version or RPCs needed
* 🟩 **Good**, because existing consumers continue to work unchanged (default returns all)
* 🟥 **Bad**, because the default (no pagination) still returns unbounded values: the dangerous path remains the easy path
* 🟥 **Bad**, because paginating values nested inside a list of attributes creates complex response semantics (each attribute has its own values pagination cursor)
* 🟥 **Bad**, because it doesn't solve the Postgres-side `JSON_AGG` cost: the query still joins and aggregates all values unless the SQL is fundamentally restructured

### Option 2: v2 service with paginated inline values on GetAttribute

Introduce a v2 `AttributesService`. `ListAttributes` returns attributes without values. `GetAttribute` returns the attribute with paginated values inline (values_pagination on the request, values + values_pagination on the response).

* 🟩 **Good**, because `GetAttribute` is a single-resource call, so sub-pagination is less complex than on a list
* 🟩 **Good**, because consumers get attribute + first page of values in one call
* 🟥 **Bad**, because it still couples value fetching to the attribute fetch: the SQL query must join and aggregate values even when the caller only needs attribute metadata
* 🟥 **Bad**, because `ListAttributes` with 1000 attributes each having even a small page of values (e.g., 10) still produces a large response (10,000 value records)
* 🟥 **Bad**, because paginating sub-resources inline has no existing pattern in the platform to follow

### Option 3: v2 service with dedicated ListAttributeValues RPC

Introduce a v2 `AttributesService` with three RPCs:
- `ListAttributes`: returns attributes **without** values
- `GetAttribute`: returns a single attribute **without** values
- `ListAttributeValues`: paginated values with filters (state, sort, search), accepts multiple attribute IDs

Consumers call `ListAttributes` or `GetAttribute` for attribute metadata, then `ListAttributeValues` for values when needed.

* 🟩 **Good**, because attribute queries are fully decoupled from value queries: no `JSON_AGG` on values in any attribute query
* 🟩 **Good**, because `ListAttributeValues` follows the existing `ListRegisteredResourceValues` platform pattern
* 🟩 **Good**, because accepting `repeated attribute_ids` allows fetching values across multiple attributes in one paginated call, avoiding N+1 round trips
* 🟩 **Good**, because v2 service versioning follows the existing authorization v2 pattern: non-breaking, v1 continues to work
* 🟨 **Neutral**, because consumers need two calls instead of one to get an attribute with its values
* 🟥 **Bad**, because it introduces new SQL queries that partially duplicate existing ones (attribute queries minus the values join)

### Option 4: Application-layer cap on JSON_AGG

Add `LIMIT N` inside the `JSON_AGG` subquery or use `array_agg` with a cap. No API changes.

* 🟩 **Good**, because zero API surface change: fully transparent to consumers
* 🟩 **Good**, because minimal code change
* 🟥 **Bad**, because it silently truncates data: consumers don't know values were dropped and have no way to fetch the rest
* 🟥 **Bad**, because there is no pagination mechanism to retrieve beyond the cap
* 🟥 **Bad**, because it masks the problem rather than solving it: the query still joins all values, just discards some after aggregation

### Option 5: Do nothing

Accept the current behavior. Attribute values are returned inline and unbounded. Operators are expected to manage attribute cardinality through policy governance (i.e., don't create attributes with millions of values).

* 🟩 **Good**, because zero engineering effort
* 🟩 **Good**, because no API changes, no migration, no new queries
* 🟥 **Bad**, because the platform has no guardrail: a single high-cardinality attribute can degrade the entire service
* 🟥 **Bad**, because there is no paginated way to retrieve values after the removal of `ListAttributeValues` in PR #3108
* 🟥 **Bad**, because it shifts the burden to operators who may not be aware of the risk until an outage occurs

## Validation

{To be filled after decision is accepted: describe how compliance with the ADR is validated, e.g., integration tests, load tests against large value sets.}

## More Information

* Issue: [opentdf/platform#3744](https://github.com/opentdf/platform/issues/3744): Unbounded attribute value aggregation in ListAttributes/GetAttribute
* PR #3108 removed `ListAttributeValues` as "redundant"
* Existing platform patterns:
  - `ListRegisteredResourceValues`: paginated sub-resource listing pattern
  - `authorization/v2`: v2 service versioning pattern
  - `PageRequest`/`PageResponse`: shared pagination types in `policy/selectors.proto`
