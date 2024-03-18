package db

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type DbError string

func (e DbError) Error() string {
	return string(e)
}

const (
	ErrUniqueConstraintViolation DbError = "ErrUniqueConstraintViolation: value must be unique"
	ErrNotNullViolation          DbError = "ErrNotNullViolation: value cannot be null"
	ErrForeignKeyViolation       DbError = "ErrForeignKeyViolation: value is referenced by another table"
	ErrRestrictViolation         DbError = "ErrRestrictViolation: value cannot be deleted due to restriction"
	ErrNotFound                  DbError = "ErrNotFound: value not found"
	ErrEnumValueInvalid          DbError = "ErrEnumValueInvalid: not a valid enum value"
	ErrUuidInvalid               DbError = "ErrUuidInvalid: value not a valid UUID"
	ErrFqnMissingValue           DbError = "ErrFqnMissingValue: FQN must include a value"
	ErrMissingValue              DbError = "ErrMissingValue: value must be included"
)

// Get helpful error message for PostgreSQL violation
func WrapIfKnownInvalidQueryErr(err error) error {
	if e := isPgError(err); e != nil {
		slog.Error("Encountered database error", slog.String("error", e.Error()))
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
		case pgerrcode.InvalidTextRepresentation:
			if strings.Contains(e.Message, "invalid input syntax for type uuid") {
				return errors.Join(ErrUuidInvalid, e)
			}
			return errors.Join(ErrEnumValueInvalid, e)
		default:
			slog.Error("Unknown error code", slog.String("error", e.Message), slog.String("code", e.Code))
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
	errMsg := err.Error()
	// The error is not of type PgError if a SELECT query resulted in no rows
	if strings.Contains(errMsg, "no rows in result set") || err == pgx.ErrNoRows {
		return &pgconn.PgError{
			Code:    pgerrcode.CaseNotFound,
			Message: "err: no rows in result set",
		}
	}
	return nil
}

func IsQueryBuilderSetClauseError(err error) bool {
	if err != nil && strings.Contains(err.Error(), "at least one Set clause") {
		slog.Error("update SET clause error: no columns updated", slog.String("error", err.Error()))
		return true
	}
	return false
}

func NewUniqueAlreadyExistsError(value string) error {
	return errors.Join(fmt.Errorf("value [%s] already exists and must be unique", value), ErrUniqueConstraintViolation)
}
