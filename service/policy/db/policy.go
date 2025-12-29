package db

import (
	"context"
	"fmt"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
)

const (
	stateInactive    transformedState = "INACTIVE"
	stateActive      transformedState = "ACTIVE"
	stateAny         transformedState = "ANY"
	stateUnspecified transformedState = "UNSPECIFIED"
)

type transformedState string

type ListConfig struct {
	limitDefault int32
	limitMax     int32
}

type PolicyDBClient struct {
	*db.Client
	logger  *logger.Logger
	queries *Queries       // PostgreSQL queries (nil for SQLite)
	router  *QueryRouter   // Query router for dual-database support
	listCfg ListConfig
}

// NewClient creates a new PolicyDBClient with support for both PostgreSQL and SQLite.
func NewClient(c *db.Client, logger *logger.Logger, configuredListLimitMax, configuredListLimitDefault int32) PolicyDBClient {
	client := PolicyDBClient{
		Client:  c,
		logger:  logger,
		router:  NewQueryRouter(c),
		listCfg: ListConfig{limitDefault: configuredListLimitDefault, limitMax: configuredListLimitMax},
	}

	// Keep queries field for backwards compatibility with existing code
	if c.DriverType() == db.DriverPostgres {
		client.queries = New(c.Pgx)
	}

	return client
}

// IsSQLite returns true if the client is using SQLite.
func (c *PolicyDBClient) IsSQLite() bool {
	return c.router.IsSQLite()
}

// IsPostgres returns true if the client is using PostgreSQL.
func (c *PolicyDBClient) IsPostgres() bool {
	return c.router.IsPostgres()
}

func (c *PolicyDBClient) RunInTx(ctx context.Context, query func(txClient *PolicyDBClient) error) error {
	if c.IsSQLite() {
		return c.runInSQLiteTx(ctx, query)
	}
	return c.runInPgxTx(ctx, query)
}

// runInPgxTx executes a function within a PostgreSQL transaction.
func (c *PolicyDBClient) runInPgxTx(ctx context.Context, query func(txClient *PolicyDBClient) error) error {
	tx, err := c.Pgx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", db.ErrTxBeginFailed, err)
	}

	txClient := &PolicyDBClient{
		Client:  c.Client,
		logger:  c.logger,
		queries: c.queries.WithTx(tx),
		router:  c.router.WithPgxTx(tx),
		listCfg: c.listCfg,
	}

	err = query(txClient)
	if err != nil {
		c.logger.WarnContext(ctx, "error during DB transaction, rolling back")

		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			return fmt.Errorf("%w, transaction [%w]: %w", db.ErrTxRollbackFailed, err, rollbackErr)
		}

		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: %w", db.ErrTxCommitFailed, err)
	}

	return nil
}

// runInSQLiteTx executes a function within a SQLite transaction.
func (c *PolicyDBClient) runInSQLiteTx(ctx context.Context, query func(txClient *PolicyDBClient) error) error {
	tx, err := c.SQLDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", db.ErrTxBeginFailed, err)
	}

	txClient := &PolicyDBClient{
		Client:  c.Client,
		logger:  c.logger,
		queries: nil, // No PostgreSQL queries for SQLite
		router:  c.router.WithSQLTx(tx),
		listCfg: c.listCfg,
	}

	err = query(txClient)
	if err != nil {
		c.logger.WarnContext(ctx, "error during DB transaction, rolling back")

		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("%w, transaction [%w]: %w", db.ErrTxRollbackFailed, err, rollbackErr)
		}

		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("%w: %w", db.ErrTxCommitFailed, err)
	}

	return nil
}

// WrapError wraps database errors with driver-appropriate error handling.
// For PostgreSQL, it wraps with PostgreSQL-specific error codes.
// For SQLite, it wraps with SQLite-specific error codes.
// This ensures consistent error handling across both database backends.
func (c PolicyDBClient) WrapError(err error) error {
	return db.WrapIfKnownInvalidQueryErrForDriver(err, c.router.DriverType())
}

func getDBStateTypeTransformedEnum(state common.ActiveStateEnum) transformedState {
	switch state.String() {
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE.String():
		return stateActive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE.String():
		return stateInactive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY.String():
		return stateAny
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_UNSPECIFIED.String():
		return stateActive
	default:
		return stateActive
	}
}
