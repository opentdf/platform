package db

import (
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/policy/db/sqlite"
)

// QueryRouter routes database queries to the appropriate backend (PostgreSQL or SQLite).
// It provides a unified interface while handling the type differences between the two
// sqlc-generated query packages.
type QueryRouter struct {
	postgres   *Queries
	sqlite     *sqlite.Queries
	driverType db.DriverType
	sqlDB      *sql.DB // For SQLite transactions
}

// NewQueryRouter creates a new QueryRouter for the given database client.
func NewQueryRouter(client *db.Client) *QueryRouter {
	router := &QueryRouter{
		driverType: client.DriverType(),
		sqlDB:      client.SQLDB,
	}

	switch client.DriverType() {
	case db.DriverSQLite:
		router.sqlite = sqlite.New(client.SQLDB)
	case db.DriverPostgres:
		router.postgres = New(client.Pgx)
	}

	return router
}

// DriverType returns the current database driver type.
func (r *QueryRouter) DriverType() db.DriverType {
	return r.driverType
}

// IsSQLite returns true if the router is configured for SQLite.
func (r *QueryRouter) IsSQLite() bool {
	return r.driverType == db.DriverSQLite
}

// IsPostgres returns true if the router is configured for PostgreSQL.
func (r *QueryRouter) IsPostgres() bool {
	return r.driverType == db.DriverPostgres
}

// PostgresQueries returns the underlying PostgreSQL queries (nil for SQLite).
// Use this for PostgreSQL-specific operations that don't have SQLite equivalents.
func (r *QueryRouter) PostgresQueries() *Queries {
	return r.postgres
}

// SQLiteQueries returns the underlying SQLite queries (nil for PostgreSQL).
// Use this for SQLite-specific operations.
func (r *QueryRouter) SQLiteQueries() *sqlite.Queries {
	return r.sqlite
}

// WithTx returns a new QueryRouter bound to the given transaction.
// For PostgreSQL, use WithPgxTx. For SQLite, use WithSQLTx.
func (r *QueryRouter) WithPgxTx(tx pgx.Tx) *QueryRouter {
	if r.driverType != db.DriverPostgres {
		return r
	}
	return &QueryRouter{
		postgres:   r.postgres.WithTx(tx),
		driverType: r.driverType,
	}
}

// WithSQLTx returns a new QueryRouter bound to the given SQL transaction (for SQLite).
func (r *QueryRouter) WithSQLTx(tx *sql.Tx) *QueryRouter {
	if r.driverType != db.DriverSQLite {
		return r
	}
	return &QueryRouter{
		sqlite:     r.sqlite.WithTx(tx),
		driverType: r.driverType,
		sqlDB:      r.sqlDB,
	}
}

// SQLDB returns the underlying *sql.DB for SQLite operations.
func (r *QueryRouter) SQLDB() *sql.DB {
	return r.sqlDB
}

// ErrUnsupportedOperation is returned when an operation is not supported for the current driver.
var ErrUnsupportedOperation = fmt.Errorf("operation not supported for this database driver")
