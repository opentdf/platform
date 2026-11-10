# Policy Service Architecture Decisions

## Table of Contents
- [Sqlc Queries Layer](#sqlc-queries-layer)
- [DB Layer](#db-layer)
- [Service Layer](#service-layer)
- [Rationale](#rationale)
- [Future Considerations](#future-considerations)

## Sqlc Queries Layer
- Hand-written SQL queries used by Sqlc to generate the Go code to call these SQL queries

**CRUD Behavior**
- Get/List/Special-purpose
  - Returns the full Policy object, query-specific object, or an array of those for List from the table
- Create
  - Returns the new id _only_ using Postgres' `RETURNING id`
- Update
  - Returns the number of rows affected using sqlc's `:execrows`
- Delete
  - Returns the number of rows affected using sqlc's `:execrows`

## DB Layer
- Consumes Sqlc generated code
- Handles normalization of request fields for DB storage
  - e.g. lower-casing namespace, attribute, etc. names
- Translates Postgres errors into more helpful error messages for the Service layer

**CRUD Behavior**
- Get/List/Special-purpose
  - Returns:
    - If no Postgres error:
      - full Policy object, query-specific object, or an array of those for List returned by the SQL query
      - nil error
    - Else:
      - nil object
      - translated error
- Create
  - Returns:
    - If no Postgres error:
      - full Policy object, composed from request fields used to create the new object and the generated ID returned by the SQL query
      - nil error
    - Else:
      - nil object
      - translated error
- Update
  - Returns
    - If no Postgres error && rows affected count != 0:
      - partial version of the Policy object, composed of the ID and _only_ the fields that were updated
      - nil error
    - Else:
      - nil object
      - translated error
- Delete
  - Returns
    - If no Postgres error && rows affected count != 0:
      - partial version of the Policy object, composed of _only_ the ID
      - nil error
    - Else:
      - nil object
      - translated error

## Service Layer
- Consumes DB layer code
- Handles request validation/sanitization, as well as transformation of enum values to their string representations
- Handles audit logging
- Translates errors from DB layer into user-friendly error responses for the API layer

**CRUD Behavior**
- Get/List/Special-purpose
  - Audits:
    - N/A
  - Returns:
    - If no error:
      - full Policy object, query-specific object, or an array of those for List returned by DB layer
      - nil error
    - Else:
      - nil object
      - translated error
- Create
  - Audit log fields:
    - success or failure state
    - action
    - Policy object type
    - created object ID (only if successful)
  - Returns:
    - If no error:
      - full Policy object returned by the DB layer
      - nil error
    - Else:
      - nil object
      - translated error
- Update
  - Audit log fields:
    - success or failure state
    - action
    - Policy object type
    - updated object ID
    - original and updated object versions (only if successful)
  - Returns:
    - If no error:
      - partial version of the Policy object, composed of _only_ the ID
      - nil error
    - Else:
      - nil object
      - translated error
- Delete
  - Audit log fields:
    - success or failure state
    - action
    - Policy object type
    - deleted object ID
  - Returns:
    - If no error:
      - partial version of the Policy object returned by the DB layer
      - nil error
    - Else:
      - nil object
      - translated error

## Rationale
- Focus on simplicity, but leave the door open for complexity down the road
- Deliberately avoid multiple queries in a single DB layer method in case we need to support scaling of DB instances
  - FQN indexing is one exception to this rule, but avoid as much as possible
- Favor duplication of code in some places to avoid initial over-engineering (e.g. cross-cutting concerns such as request/response debug logging and auditing)

## Future Considerations
- Introduce DB transactions to ensure atomicity of multiple queries at scale
- Implement gRPC interceptors for cross-cutting concerns
  - Request/response debug logging should be the first candidate for this
- Refactor duplicated code once the above support is in place