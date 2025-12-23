package db

import (
	"context"
	"database/sql"
)

// DriverType represents the database driver type
type DriverType string

const (
	// DriverPostgres is the PostgreSQL driver
	DriverPostgres DriverType = "postgres"
	// DriverSQLite is the SQLite driver
	DriverSQLite DriverType = "sqlite"
)

// String returns the string representation of the driver type
func (d DriverType) String() string {
	return string(d)
}

// IsValid checks if the driver type is valid
func (d DriverType) IsValid() bool {
	switch d {
	case DriverPostgres, DriverSQLite:
		return true
	default:
		return false
	}
}

// Driver is the interface for database drivers that abstracts away
// the underlying database implementation details.
type Driver interface {
	// Dialect returns the driver type
	Dialect() DriverType

	// DB returns the underlying *sql.DB connection
	// This provides a common interface for both PostgreSQL and SQLite
	DB() *sql.DB

	// Close closes the database connection
	Close() error

	// Ping verifies the database connection is alive
	Ping(ctx context.Context) error
}

// PlaceholderFormat returns the appropriate placeholder format for the driver
// PostgreSQL uses $1, $2, etc. while SQLite uses ?, ?, etc.
func PlaceholderFormat(driver DriverType) string {
	switch driver {
	case DriverSQLite:
		return "?"
	default:
		return "$"
	}
}
