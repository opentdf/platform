# Using Database Transactions in Policy Service

## Table of Contents

- [Background](#background)
- [Chosen Option](#chosen-option)
- [Considered Options](#considered-options)
  - [LIMIT + OFFSET](#limit--offset)
  - [Keyset Pagination](#keyset-pagination)
  - [Cursor Pagination](#cursor-pagination)

## Background

Due to the complex nature of some operations within the Policy service, we need to consider the use of database transactions to ensure data integrity and consistency.

## Use Cases

Primary drivers for implementing database transactions:
- Unsafe operations that update namespace/attribute definition names or attribute values and require FQNs to be updated for consistency
- Attribute defintion creation with multiple attribute values that must be created atomically

> [!NOTE]
> There are likely to be more as the service matures and more complex operations are required.

## Implementation

An abstraction over transactional operations will be introduced to hopefully simplify support for multiple database providers in the future:

```go
type DbTransaction interface {
	Commit(ctx context.Context) error
	Rollback(ctx context.Context)
}
```

### PolicyDBClient Changes

New methods for creating transactions and executing operations will be added:

```go
// Starts a new transaction and returns it
func (c *PolicyDBClient) Begin() (DbTransaction, error) {
    // use desired database client to start a new transaction
    // - initial implementation will use pgx.Tx with Postgres
}
```

```go
// provides a PolicyDBClient instance using the transaction's connection
func (c *PolicyDBClient) WithTx(tx DbTransaction) *PolicyDBClient {
    // use desired database client to create a new PolicyDBClient instance with the transaction's connection
    // - initial implementation will use pgx.Tx with Postgres
}
```

### Usage Example

It is recommended to create the transaction within the service layer, as calling `WithTx()` from the service layer will inherently provide the transaction to any further `PolicyDBClient` methods called within the DB layer.

```go
tx, err := dbClient.Begin()
if err != nil {
    // handle error
}
defer tx.Rollback(ctx)

result, err := dbClient.WithTx(tx).SomeOperation(ctx, ...params)
if err != nil {
    // handle error
}

nextResult, err := dbClient.WithTx(tx).AnotherOperation(ctx, ...params)
if err != nil {
    // handle error
}

err = tx.Commit(ctx)
if err != nil {
    // handle error
}
```