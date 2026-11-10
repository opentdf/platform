# Using Database Transactions in Policy Service

## Table of Contents

- [Background](#background)
- [Use Cases](#use-cases)
- [Platform DB Package Changes](#platform-db-package-changes)
- [PolicyDBClient Changes](#policydbclient-changes)
- [Usage Example](#usage-example)

## Background

Due to the complex nature of some operations within the Policy service, we need to consider the use of database transactions to ensure data integrity and consistency.

## Use Cases

Primary drivers for implementing database transactions:
- Unsafe operations that update namespace/attribute definition names or attribute values and require FQNs to be updated for consistency
- Attribute defintion creation with multiple attribute values that must be created atomically

> [!NOTE]
> There are likely to be more as the service matures and more complex operations are required.

## Platform DB Package Changes

A `Begin` method will be added to the `PgxIface` interface to allow for the creation of transactions:

```go
type PgxIface interface {
+	Begin(ctx context.Context) (pgx.Tx, error)
}
```

### PolicyDBClient Changes

A new `RunInTx` method for performing operations within a transaction will be added to the `PolicyDBClient` struct:


```go
// Creates a new transaction and provides the caller with a handler func to perform operations within the transaction.
// If the handler func returns an error, the transaction will be rolled back.
// If the handler func returns nil, the transaction will be committed. 
func (c *PolicyDBClient) RunInTx(ctx context.Context, query func(txClient *PolicyDBClient) error) error {
	tx, err := c.Client.Pgx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", db.ErrTxBeginFailed, err)
	}

	txClient := &PolicyDBClient{c.Client, c.logger, c.Queries.WithTx(tx), c.listCfg}

	err = query(txClient)
	if err != nil {
		c.logger.WarnContext(ctx, "error during DB transaction, rolling back")

		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			// this should never happen, but if it does, we want to know about it
			return fmt.Errorf("%w, transaction [%w]: %w", db.ErrTxRollbackFailed, err, rollbackErr)
		}

		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: %w", db.ErrTxCommitFailed, err)
	}

	return nil
}
```

### Usage Example

As a general rule, it is recommended to use the `RunInTx()` method within service layer methods to avoid confusion with transaction handling or duplicating a transaction across the service and database layers.  Any additional `PolicyDBClient` methods triggered from the original method call at the service layer, will inherit the transaction created by `RunInTx`.

```go
func (s AttributesService) CreateAttribute(ctx context.Context,
	req *connect.Request[attributes.CreateAttributeRequest],
) (*connect.Response[attributes.CreateAttributeResponse], error) {
	s.logger.Debug("creating new attribute definition", slog.String("name", req.Msg.GetName()))
	rsp := &attributes.CreateAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ActionType: audit.ActionTypeCreate,
	}

    // RunInTX() used here to ensure atomic creation of attribute definition and all values
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		item, err := txClient.CreateAttribute(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		s.logger.Debug("created new attribute definition", slog.String("name", req.Msg.GetName()))

		auditParams.ObjectID = item.GetId()
		auditParams.Original = item
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Attribute = item
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("attribute", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}
```