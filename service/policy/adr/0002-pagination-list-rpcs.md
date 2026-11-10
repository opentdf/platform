# Pagination in policy LIST RPCs

## Table of Contents

- [Background](#background)
- [Chosen Option](#chosen-option)
- [Considered Options](#considered-options)
  - [LIMIT + OFFSET](#limit--offset)
  - [Keyset Pagination](#keyset-pagination)
  - [Cursor Pagination](#cursor-pagination)

## Background

At present, policy LIST RPCs are completely open-ended.

Attribute Namespaces, Definitions, and Values LIST calls may be filtered by _active_ state.

All Policy objects may be retrieved without quantity limits. This presents a challenge at scale if there
are a very large number of any policy object in the platform database when responses become overwhelmingly
large.

Introduction of a `limit` on retrieved items in LIST procedure call responses necessitates the simultaneous introduction of
pagination. This ADR clarifies the unified approach we will take within policy service LIST RPCs
and at the database level for this pagination.

## Chosen Option

[LIMIT + OFFSET](#limit--offset)

Because we do not know the likelihood of platforms running with Policy where any individual object has
enough rows to experience the at-scale performance concerns of `offset` pagination, we will prefer
this simple implementation for now and leave the door open for cursor-based pagination to solve the performance
constraint should it be a realized problem in the future.

## Considered Options

### LIMIT + OFFSET

The simplest approach is a simple update to the proto for LIST RPCs and db queries to take in `limit` and `offset` with default values.

```proto
message ListRequest {
    // ...existing fields omitted
    int32 limit = 3; // default depends on type of policy object
    int32 offset = 4; // default: 0
}
message ListResponse {
    // ...existing fields omitted
    int32 total = 5; // indication of total available for pagination
}
```

```sql
-- subject-mappings example request:
--   'limit' 100
--   'offset' 100
SELECT * FROM opentdf_policy.subject_mappings
ORDER BY created_at
LIMIT 100 OFFSET 100
```

#### Pros & Cons

- :green_circle: Simple - support across any SQL database (just slightly different syntax)
- :green_circle: Stateless - each request can independently paginate by specifying LIMIT / OFFSET
- :green_circle: Flexibile - random-access pagination supported
- :green_circle: Familiar - standard across LIST-type APIs
- :yellow_circle: Create/Update/Delete of data between requests may throw off pages, but this is a relatively small concern when reads are exponentially more frequent than writes in Policy
- :red_circle: Performance: large number of objects _or_ a high offset mean a lot of rows need to be scanned and discarded (skipped). However, (:yellow_circle:) we do not know how often the scale of policy objects will be large enough for this to be a problem

> [!NOTE]
> Pagination is roughly Big O(n) time complexity as offset increases

### Keyset Pagination

We would index a column (the most obvious would be `created_at`) to use as the pagination key for
querying, and facilitate pagination before/after any arbitrary timestamp.

```proto
message ListRequest {
    // ...existing fields omitted
    int32 limit = 3; // default depends on type of policy object
    google.protobuf.Timestamp after = 4; // default: start_of_time
    int32 total = 5; // indication of total that can be paginated through
}
message ListResponse {
    // ...existing fields omitted
    int32 total = 5; // indication of total available for pagination
}
```

```sql
-- subject-mappings example request:
--   'after' 2023-01-01
--   'limit' 100
SELECT * FROM opentdf_policy.subject_mappings
WHERE created_at > '2023-01-01' ORDER BY created_at LIMIT 100;
```

#### Pros & Cons

- :green_circle: Support - supported across any SQL database (just slightly different syntax)
- :green_circle: Speed - much faster in deep pages than OFFSET due to reduced scan row count
- :yellow_circle: Reliability - provisioned policy may contain the same `created_at` timestamp
- :red_circle: Flexibility - pagination is only forward of the `created_at` timestamp
- :red_circle: Complexity - client must maintain state since response timestamps are required to drive subsequent request timestamp pagination, and pagination backwards is not supported
- :red_circle: Complexity - reliance on timestamps introduces timezone differential confusion unless a parameter is also employed to localize the query

### Cursor Pagination

We would index a column (the most obvious would be `created_at`) to use as the pagination key for
querying, but we would utilize an encoded cursor approach.

```proto
message ListRequest {
    // ...existing fields omitted
    int32 limit = 3; // default depends on type of policy object
    string cursor = 4; // defaulted in API layer to cursor for encoded start_of_time
}

message ListResponse {
    // ...existing fields and response data ommitted
    // cursors are encoded by the server as base64'd 'created_at' timestamps
    string previous_cursor = 4;
    string next_cursor = 4;
    int32 total = 5; // indication of total available for pagination
}
```

```sql
-- subject-mappings example, request:
--   'after_cursor' 2023-01-01 00:00:00.000000+00
--   'limit' 100
WITH Data AS (
    SELECT *
    FROM opentdf_policy.subject_mappings
    WHERE created_at >= '2023-01-01 00:00:00.000000+00'
    ORDER BY created_at
    LIMIT 101
),
NextPage AS (
    SELECT *
    FROM Data
    ORDER BY created_at
    LIMIT 100
),
PreviousPage AS (
    SELECT *
    FROM opentdf_policy.subject_mappings
    WHERE created_at < (SELECT MIN(created_at) FROM Data)
    ORDER BY created_at DESC
    LIMIT 101
),
CursorData AS (
    SELECT
        (SELECT MIN(created_at) FROM Data) AS first_item_created_at,
        (SELECT MAX(created_at) FROM NextPage) AS next_cursor_created_at,
        (SELECT MIN(created_at) FROM PreviousPage) AS previous_cursor_created_at
)
SELECT
    (SELECT json_agg(row_to_json(NextPage)) FROM NextPage) AS data,
    (SELECT json_build_object('created_at', next_cursor_created_at) FROM CursorData) AS next_cursor,
    (SELECT json_build_object('created_at', previous_cursor_created_at) FROM CursorData) AS previous_cursor
FROM CursorData;
```

#### Pros & Cons

- :green_circle: Support - supported across any SQL database (just different syntax)
- :green_circle: Speed - much faster in deep pages than OFFSET due to reduced scan row count
- :green_circle: Flexibility - pagination _a single page_ backward made possible by response `previous_cursor` value
- :green_circle: Complexity - timestamp timezone differential is not a problem as cursors are server-determined and an API concern
- :yellow_circle:/:red_circle: Reliability - provisioned policy will sometimes contain the same `created_at` timestamp, making it less than 100% reliable
- :red_circle: New index on the `created_at` timestamp required which adds overhead but little value for management with
time pretty much irrelevant to attributes except if required for sorting
- :red_circle: Complexity - SQL queries become significantly more complex to build and read into responses
- :red_circle: Flexibility - random access is still not supported without client state management and prior knowledge of forward pagination's historical cursors
