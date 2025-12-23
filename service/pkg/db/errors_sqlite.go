package db

import (
	"database/sql"
	"errors"
	"log/slog"
	"strings"

	"github.com/mattn/go-sqlite3"
)

// SQLite extended error codes for constraint violations
// See: https://www.sqlite.org/rescode.html
const (
	sqliteConstraintUnique     = 2067 // SQLITE_CONSTRAINT_UNIQUE
	sqliteConstraintForeignKey = 787  // SQLITE_CONSTRAINT_FOREIGNKEY
	sqliteConstraintNotNull    = 1299 // SQLITE_CONSTRAINT_NOTNULL
	sqliteConstraintCheck      = 275  // SQLITE_CONSTRAINT_CHECK
	sqliteConstraintPrimaryKey = 1555 // SQLITE_CONSTRAINT_PRIMARYKEY
)

// WrapSQLiteError converts SQLite errors to standard database errors.
// This provides consistent error handling across PostgreSQL and SQLite backends.
func WrapSQLiteError(err error) error {
	if err == nil {
		return nil
	}

	// Check for "no rows" error
	if errors.Is(err, sql.ErrNoRows) {
		return errors.Join(ErrNotFound, err)
	}

	// Check for SQLite specific errors
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return wrapSQLite3Error(sqliteErr)
	}

	// Check for extended error info in error message
	// Some drivers return errors as strings
	errMsg := err.Error()
	if strings.Contains(errMsg, "UNIQUE constraint failed") {
		return errors.Join(ErrUniqueConstraintViolation, err)
	}
	if strings.Contains(errMsg, "FOREIGN KEY constraint failed") {
		return errors.Join(ErrForeignKeyViolation, err)
	}
	if strings.Contains(errMsg, "NOT NULL constraint failed") {
		return errors.Join(ErrNotNullViolation, err)
	}
	if strings.Contains(errMsg, "CHECK constraint failed") {
		return errors.Join(ErrCheckViolation, err)
	}
	if strings.Contains(errMsg, "no rows") {
		return errors.Join(ErrNotFound, err)
	}

	return err
}

// wrapSQLite3Error handles sqlite3.Error type specifically
func wrapSQLite3Error(err sqlite3.Error) error {
	slog.Error("encountered SQLite database error",
		slog.Int("code", int(err.Code)),
		slog.Int("extended_code", int(err.ExtendedCode)),
		slog.String("error", err.Error()),
	)

	// Check extended error code first for more specific errors
	switch int(err.ExtendedCode) {
	case sqliteConstraintUnique, sqliteConstraintPrimaryKey:
		return errors.Join(ErrUniqueConstraintViolation, err)
	case sqliteConstraintForeignKey:
		return errors.Join(ErrForeignKeyViolation, err)
	case sqliteConstraintNotNull:
		return errors.Join(ErrNotNullViolation, err)
	case sqliteConstraintCheck:
		return errors.Join(ErrCheckViolation, err)
	}

	// Fall back to base error code
	switch err.Code {
	case sqlite3.ErrConstraint:
		// Generic constraint error - try to determine type from message
		errMsg := err.Error()
		if strings.Contains(errMsg, "UNIQUE") {
			return errors.Join(ErrUniqueConstraintViolation, err)
		}
		if strings.Contains(errMsg, "FOREIGN KEY") {
			return errors.Join(ErrForeignKeyViolation, err)
		}
		if strings.Contains(errMsg, "NOT NULL") {
			return errors.Join(ErrNotNullViolation, err)
		}
		if strings.Contains(errMsg, "CHECK") {
			return errors.Join(ErrCheckViolation, err)
		}
		return errors.Join(ErrRestrictViolation, err)
	case sqlite3.ErrNotFound:
		return errors.Join(ErrNotFound, err)
	default:
		slog.Error("unknown SQLite error code",
			slog.String("error", err.Error()),
			slog.Int("code", int(err.Code)),
		)
		return err
	}
}

// WrapIfKnownInvalidQueryErrForDriver wraps database errors based on the driver type.
// For PostgreSQL, it uses the existing WrapIfKnownInvalidQueryErr.
// For SQLite, it uses WrapSQLiteError.
func WrapIfKnownInvalidQueryErrForDriver(err error, driver DriverType) error {
	if err == nil {
		return nil
	}

	switch driver {
	case DriverSQLite:
		return WrapSQLiteError(err)
	case DriverPostgres:
		return WrapIfKnownInvalidQueryErr(err)
	default:
		return err
	}
}

// IsSQLiteConstraintError checks if an error is a SQLite constraint violation.
func IsSQLiteConstraintError(err error) bool {
	if err == nil {
		return false
	}

	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return sqliteErr.Code == sqlite3.ErrConstraint
	}

	// Check error message as fallback
	errMsg := err.Error()
	return strings.Contains(errMsg, "constraint failed")
}
