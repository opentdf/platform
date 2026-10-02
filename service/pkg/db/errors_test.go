package db

import (
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Is_Postgres_Invalid_Query_Error(t *testing.T) {
	// Known error types should be wrapped in internal error types
	require.ErrorIs(t, WrapIfKnownInvalidQueryErr(&pgconn.PgError{Code: pgerrcode.NotNullViolation}), ErrNotNullViolation)
	require.ErrorIs(t, WrapIfKnownInvalidQueryErr(&pgconn.PgError{Code: pgerrcode.UniqueViolation}), ErrUniqueConstraintViolation)
	require.ErrorIs(t, WrapIfKnownInvalidQueryErr(&pgconn.PgError{Code: pgerrcode.ForeignKeyViolation}), ErrForeignKeyViolation)
	require.ErrorIs(t, WrapIfKnownInvalidQueryErr(&pgconn.PgError{Code: pgerrcode.RestrictViolation}), ErrRestrictViolation)
	require.ErrorIs(t, WrapIfKnownInvalidQueryErr(&pgconn.PgError{Code: pgerrcode.CaseNotFound}), ErrNotFound)
	require.ErrorIs(t, WrapIfKnownInvalidQueryErr(&pgconn.PgError{Code: pgerrcode.InvalidTextRepresentation}), ErrEnumValueInvalid)
	require.ErrorIs(t, WrapIfKnownInvalidQueryErr(errors.New("no rows in result set")), ErrNotFound)

	// Unknown error types should be passed through
	e := &pgconn.PgError{Code: pgerrcode.DataException}
	assert.Equal(t, WrapIfKnownInvalidQueryErr(e), e)
	err := errors.New("test error")
	assert.Equal(t, WrapIfKnownInvalidQueryErr(err), err)
}

func Test_Is_Pg_Error(t *testing.T) {
	pgError := &pgconn.PgError{Code: pgerrcode.UniqueViolation}
	require.ErrorIs(t, isPgError(pgError), pgError)
	assert.Nil(t, isPgError(errors.New("test error")))
}

func TestStatusifyErrorUnsafeUpdateKeyErrors(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Config{
		Level:  "error",
		Output: "stdout",
		Type:   "json",
	})
	require.NoError(t, err)

	testCases := []struct {
		name string
		err  error
		code connect.Code
		text string
	}{
		{
			name: "provider config not found",
			err:  ErrUnsafeUpdateKeyProviderConfigNotFound,
			code: connect.CodeNotFound,
			text: ErrorTextUnsafeUpdateKeyProviderConfigNotFound,
		},
		{
			name: "existing mode unsupported",
			err:  ErrUnsafeUpdateKeyExistingModeUnsupported,
			code: connect.CodeInvalidArgument,
			text: ErrorTextUnsafeUpdateKeyExistingModeUnsupported,
		},
		{
			name: "target mode unsupported",
			err:  ErrUnsafeUpdateKeyTargetModeUnsupported,
			code: connect.CodeInvalidArgument,
			text: ErrorTextUnsafeUpdateKeyTargetModeUnsupported,
		},
		{
			name: "provider config existing mode",
			err:  ErrUnsafeUpdateKeyProviderConfigExistingMode,
			code: connect.CodeInvalidArgument,
			text: ErrorTextUnsafeUpdateKeyProviderConfigExistingMode,
		},
		{
			name: "provider config required",
			err:  ErrUnsafeUpdateKeyProviderConfigRequired,
			code: connect.CodeInvalidArgument,
			text: ErrorTextUnsafeUpdateKeyProviderConfigRequired,
		},
		{
			name: "provider config not allowed",
			err:  ErrUnsafeUpdateKeyProviderConfigNotAllowed,
			code: connect.CodeInvalidArgument,
			text: ErrorTextUnsafeUpdateKeyProviderConfigNotAllowed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := StatusifyError(t.Context(), testLogger, tc.err, ErrTextUpdateFailed)

			require.Equal(t, tc.code, connect.CodeOf(got))
			require.Contains(t, got.Error(), tc.text)
		})
	}
}
