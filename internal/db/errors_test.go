package db

import (
	"errors"
	"testing"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"gotest.tools/v3/assert"
)

func Test_Is_Postgres_Invalid_Query_Error(t *testing.T) {
	// Known error types should be wrapped in internal error types
	assert.ErrorIs(t, WrapIfKnownInvalidQueryErr(&pgconn.PgError{Code: pgerrcode.NotNullViolation}), ErrNotNullViolation)
	assert.ErrorIs(t, WrapIfKnownInvalidQueryErr(&pgconn.PgError{Code: pgerrcode.UniqueViolation}), ErrUniqueConstraintViolation)
	assert.ErrorIs(t, WrapIfKnownInvalidQueryErr(&pgconn.PgError{Code: pgerrcode.ForeignKeyViolation}), ErrForeignKeyViolation)
	assert.ErrorIs(t, WrapIfKnownInvalidQueryErr(&pgconn.PgError{Code: pgerrcode.RestrictViolation}), ErrRestrictViolation)
	assert.ErrorIs(t, WrapIfKnownInvalidQueryErr(&pgconn.PgError{Code: pgerrcode.CaseNotFound}), ErrNotFound)

	// Unknown error types should be passed through
	e := &pgconn.PgError{Code: pgerrcode.DataException}
	assert.Equal(t, WrapIfKnownInvalidQueryErr(e), e)
	err := errors.New("test error")
	assert.Equal(t, WrapIfKnownInvalidQueryErr(err), err)
}

func Test_Is_Pg_Error(t *testing.T) {
	pgError := &pgconn.PgError{Code: pgerrcode.UniqueViolation}
	assert.ErrorIs(t, isPgError(pgError), pgError)
	assert.Assert(t, isPgError(errors.New("test error")) == nil)
}
