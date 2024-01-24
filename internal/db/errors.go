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
)

// Validate is a PostgreSQL constraint violation for specific table-column value
func IsConstraintViolationForColumnVal(err error, table string, column string) bool {
	if e := IsPostgresBadValueError(err); e != nil {
		if errors.Is(e, ErrUniqueConstraintViolation) && strings.Contains(err.Error(), getConstraintName(table, column)) {
			return true
		}
	}
	return false
}

// Get helpful error message for PostgreSQL violation
func IsPostgresBadValueError(err error) error {
	if e := isPgError(err); e != nil {
		switch e.Code {
		case pgerrcode.UniqueViolation:
			return ErrUniqueConstraintViolation
		case pgerrcode.NotNullViolation:
			return ErrNotNullViolation
		case pgerrcode.ForeignKeyViolation:
			return ErrForeignKeyViolation
		case pgerrcode.RestrictViolation:
			return ErrRestrictViolation
		default:
			return nil
		}
	}
	return nil
}

func isPgError(err error) *pgconn.PgError {
	var e *pgconn.PgError
	if errors.As(err, &e) {
		return e
	}
	return nil
}

func getConstraintName(table string, column string) string {
	return fmt.Sprintf("%s_%s_key", table, column)
}

func NewUniqueAlreadyExistsError(value string) error {
	return fmt.Errorf("value [%s] already exists and must be unique", value)
}
