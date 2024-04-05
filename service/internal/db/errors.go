package db

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DBError string

func (e DBError) Error() string {
	return string(e)
}

const (
	ErrUniqueConstraintViolation DBError = "ErrUniqueConstraintViolation: value must be unique"
	ErrNotNullViolation          DBError = "ErrNotNullViolation: value cannot be null"
	ErrForeignKeyViolation       DBError = "ErrForeignKeyViolation: value is referenced by another table"
	ErrRestrictViolation         DBError = "ErrRestrictViolation: value cannot be deleted due to restriction"
	ErrNotFound                  DBError = "ErrNotFound: value not found"
	ErrEnumValueInvalid          DBError = "ErrEnumValueInvalid: not a valid enum value"
	ErrUUIDInvalid               DBError = "ErrUUIDInvalid: value not a valid UUID"
	ErrFqnMissingValue           DBError = "ErrFqnMissingValue: FQN must include a value"
	ErrMissingValue              DBError = "ErrMissingValue: value must be included"
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
				return errors.Join(ErrUUIDInvalid, e)
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

const (
	ErrTextCreationFailed      = "resource creation failed"
	ErrTextDeletionFailed      = "resource deletion failed"
	ErrTextDeactivationFailed  = "resource deactivation failed"
	ErrTextGetRetrievalFailed  = "resource retrieval failed"
	ErrTextListRetrievalFailed = "resource list retrieval failed"
	ErrTextUpdateFailed        = "resource update failed"
	ErrTextNotFound            = "resource not found"
	ErrTextConflict            = "resource unique field violation"
	ErrTextRelationInvalid     = "resource relation invalid"
	ErrTextEnumValueInvalid    = "enum value invalid"
	ErrTextUUIDInvalid         = "value not a valid uuid"
	ErrTextRestrictViolation   = "intended action would violate a restriction"
	ErrTextFqnMissingValue     = "FQN must specify a valid value and be of format 'https://<namespace>/attr/<attribute name>/value/<value>'"
)

func StatusifyError(err error, fallbackErr string, log ...any) error {
	l := append([]any{"error", err}, log...)
	if errors.Is(err, ErrUniqueConstraintViolation) {
		slog.Error(ErrTextConflict, l...)
		return status.Error(codes.AlreadyExists, ErrTextConflict)
	}
	if errors.Is(err, ErrNotFound) {
		slog.Error(ErrTextNotFound, l...)
		return status.Error(codes.NotFound, ErrTextNotFound)
	}
	if errors.Is(err, ErrForeignKeyViolation) {
		slog.Error(ErrTextRelationInvalid, l...)
		return status.Error(codes.InvalidArgument, ErrTextRelationInvalid)
	}
	if errors.Is(err, ErrEnumValueInvalid) {
		slog.Error(ErrTextEnumValueInvalid, l...)
		return status.Error(codes.InvalidArgument, ErrTextEnumValueInvalid)
	}
	if errors.Is(err, ErrUUIDInvalid) {
		slog.Error(ErrTextUUIDInvalid, l...)
		return status.Error(codes.InvalidArgument, ErrTextUUIDInvalid)
	}
	if errors.Is(err, ErrRestrictViolation) {
		slog.Error(ErrTextRestrictViolation, l...)
		return status.Error(codes.InvalidArgument, ErrTextRestrictViolation)
	}
	if errors.Is(err, ErrFqnMissingValue) {
		slog.Error(ErrTextFqnMissingValue, l...)
		return status.Error(codes.InvalidArgument, ErrTextFqnMissingValue)
	}
	slog.Error(err.Error(), l...)
	return status.Error(codes.Internal, fallbackErr)
}
