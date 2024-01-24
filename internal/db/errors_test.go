package db

import (
	"errors"
	"testing"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"gotest.tools/v3/assert"
)

func Test_Get_Constraint_Name(t *testing.T) {
	assert.Equal(t, "test_pk_key", getConstraintName("test", "pk"))
	assert.Equal(t, "test_fk_key", getConstraintName("test", "fk"))
	assert.Equal(t, "table_column_key", getConstraintName("table", "column"))
}

func Test_Is_Constraint_Violation_For_Column_Val(t *testing.T) {
	assert.Equal(t, true, IsConstraintViolationForColumnVal(&pgconn.PgError{Message: "duplicate key value violates unique constraint \"table_column_key\"", Code: pgerrcode.UniqueViolation}, "table", "column"))
	assert.Equal(t, true, IsConstraintViolationForColumnVal(&pgconn.PgError{Message: "duplicate key value violates unique constraint \"attributes_namespaces_name_key\"", Code: pgerrcode.UniqueViolation}, "attributes_namespaces", "name"))
	assert.Equal(t, false, IsConstraintViolationForColumnVal(&pgconn.PgError{Message: "duplicate key value violates unique constraint \"attributes_namespaces_name_key\"", Code: pgerrcode.UniqueViolation}, "attributes_namespaces", "id"))
	assert.Equal(t, false, IsConstraintViolationForColumnVal(&pgconn.PgError{Message: "duplicate key value violates unique constraint \"attributes_namespaces_name_key\"", Code: pgerrcode.CaseNotFound}, "attributes_namespaces", "name"))
}

func Test_Is_Postgres_Bad_Value_Error(t *testing.T) {
	assert.Equal(t, ErrUniqueConstraintViolation, IsPostgresBadValueError(&pgconn.PgError{Code: pgerrcode.UniqueViolation}))
	assert.Equal(t, ErrNotNullViolation, IsPostgresBadValueError(&pgconn.PgError{Code: pgerrcode.NotNullViolation}))
	assert.Equal(t, ErrForeignKeyViolation, IsPostgresBadValueError(&pgconn.PgError{Code: pgerrcode.ForeignKeyViolation}))
	assert.Equal(t, ErrRestrictViolation, IsPostgresBadValueError(&pgconn.PgError{Code: pgerrcode.RestrictViolation}))
	assert.Equal(t, nil, IsPostgresBadValueError(&pgconn.PgError{Code: pgerrcode.CaseNotFound}))
}

func Test_Is_Pg_Error(t *testing.T) {
	pgError := &pgconn.PgError{Code: pgerrcode.UniqueViolation}
	assert.ErrorIs(t, isPgError(pgError), pgError)
	assert.Assert(t, isPgError(errors.New("test error")) == nil)
}
