package db

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

type DbError string

func (e DbError) Error() string {
	return string(e)
}

const (
	ErrUniqueConstraintViolation DbError = "error: value must be unique"
	ErrNotNullViolation          DbError = "error: value cannot be null"
	ErrForeignKeyViolation       DbError = "error: value must exist in another table"
	ErrRestrictViolation         DbError = "error: value cannot be deleted due to restriction"
	ErrNotFound                  DbError = "error: value not found"
)

// Validate is a PostgreSQL constraint violation for specific table-column value
func IsConstraintViolationForColumnVal(err error, table string, column string) bool {
	if e := WrapIfKnownInvalidQueryErr(err); e != nil {
		if errors.Is(e, ErrUniqueConstraintViolation) && strings.Contains(err.Error(), getConstraintName(table, column)) {
			return true
		}
	}
	return false
}

// Get helpful error message for PostgreSQL violation
func WrapIfKnownInvalidQueryErr(err error) error {
	if e := isPgError(err); e != nil {
		switch e.Code {
		case pgerrcode.UniqueViolation:
			return errors.Join(ErrUniqueConstraintViolation, e)
		case pgerrcode.NotNullViolation:
			return errors.Join(ErrNotNullViolation, e)
		case pgerrcode.ForeignKeyViolation:
			return errors.Join(ErrForeignKeyViolation, e)
		case pgerrcode.RestrictViolation:
			return errors.Join(ErrRestrictViolation, e)
		case pgerrcode.CaseNotFound:
			return errors.Join(ErrNotFound, e)
		default:
			return e
		}
	}
	return err
}

func isPgError(err error) *pgconn.PgError {
	if err == nil {
		return nil
	}

	var e *pgconn.PgError
	if errors.As(err, &e) {
		return e
	}
	// The error is not of type PgError if a SELECT query resulted in no rows
	if strings.Contains(err.Error(), "no rows in result set") {
		return &pgconn.PgError{
			Code:    pgerrcode.CaseNotFound,
			Message: "err: no rows in result set",
		}
	}
	return nil
}

func getConstraintName(table string, column string) string {
	return fmt.Sprintf("%s_%s_key", table, column)
}

func NewUniqueAlreadyExistsError(value string) error {
	return errors.Join(fmt.Errorf("value [%s] already exists and must be unique", value), ErrUniqueConstraintViolation)
}
