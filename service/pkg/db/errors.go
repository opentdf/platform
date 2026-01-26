package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"connectrpc.com/connect"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/opentdf/platform/service/logger"
)

var (
	ErrUniqueConstraintViolation  = errors.New("ErrUniqueConstraintViolation: value must be unique")
	ErrNotNullViolation           = errors.New("ErrNotNullViolation: value cannot be null")
	ErrForeignKeyViolation        = errors.New("ErrForeignKeyViolation: value is referenced by another table")
	ErrRestrictViolation          = errors.New("ErrRestrictViolation: value cannot be deleted due to restriction")
	ErrNotFound                   = errors.New("ErrNotFound: value not found")
	ErrAttributeValueInactive     = errors.New("ErrAttributeValueInactive: attribute value inactive")
	ErrEnumValueInvalid           = errors.New("ErrEnumValueInvalid: not a valid enum value")
	ErrUUIDInvalid                = errors.New("ErrUUIDInvalid: value not a valid UUID")
	ErrMissingValue               = errors.New("ErrMissingValue: value must be included")
	ErrListLimitTooLarge          = errors.New("ErrListLimitTooLarge: requested limit greater than configured maximum")
	ErrTxBeginFailed              = errors.New("ErrTxBeginFailed: failed to begin DB transaction")
	ErrTxRollbackFailed           = errors.New("ErrTxRollbackFailed: failed to rollback DB transaction")
	ErrTxCommitFailed             = errors.New("ErrTxCommitFailed: failed to commit DB transaction")
	ErrSelectIdentifierInvalid    = errors.New("ErrSelectIdentifierInvalid: invalid identifier value for select query")
	ErrUnknownSelectIdentifier    = errors.New("ErrUnknownSelectIdentifier: unknown identifier type for select query")
	ErrCannotUpdateToUnspecified  = errors.New("ErrCannotUpdateToUnspecified: cannot update to unspecified value")
	ErrKeyRotationFailed          = errors.New("ErrTextKeyRotationFailed: key rotation failed")
	ErrExpectedBase64EncodedValue = errors.New("ErrExpectedBase64EncodedValue: expected base64 encoded value")
	ErrMarshalValueFailed         = errors.New("ErrMashalValueFailed: failed to marshal value")
	ErrUnmarshalValueFailed       = errors.New("ErrUnmarshalValueFailed: failed to unmarshal value")
	ErrNamespaceMismatch          = errors.New("ErrNamespaceMismatch: namespace mismatch")
	ErrKIDMismatch                = errors.New("ErrKIDMismatch: Key ID mismatch")
	ErrKasURIMismatch             = errors.New("ErrKasURIMismatch: KAS URI mismatch")
	ErrInvalidOblTriParam         = errors.New("ErrInvalidOblTriParam: either the obligation value, attribute value, or action provided was not found")
	ErrCheckViolation             = errors.New("ErrCheckViolation: check constraint violation")
	ErrFqnMismatch                = errors.New("ErrFqnMismatch: FQN mismatch")
	ErrInvalidCertificate         = errors.New("ErrInvalidCertificate: invalid certificate")
)

// Get helpful error message for PostgreSQL violation
func WrapIfKnownInvalidQueryErr(err error) error {
	if e := isPgError(err); e != nil {
		slog.Error("encountered database error", slog.Any("error", e))
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
			if strings.Contains(e.Message, ErrTextUUIDInvalid) {
				return errors.Join(ErrUUIDInvalid, e)
			}
			return errors.Join(ErrEnumValueInvalid, e)
		case pgerrcode.CheckViolation:
			return errors.Join(ErrCheckViolation, e)
		default:
			slog.Error("unknown error code",
				slog.String("error", e.Message),
				slog.String("code", e.Code),
			)
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
	if strings.Contains(errMsg, "no rows in result set") || errors.Is(err, pgx.ErrNoRows) {
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
	ErrTextCreationFailed               = "resource creation failed"
	ErrTextDeletionFailed               = "resource deletion failed"
	ErrTextDeactivationFailed           = "resource deactivation failed"
	ErrTextGetRetrievalFailed           = "resource retrieval failed"
	ErrTextListRetrievalFailed          = "resource list retrieval failed"
	ErrTextUpdateFailed                 = "resource update failed"
	ErrTextNotFound                     = "resource not found"
	ErrTextConflict                     = "resource unique field violation"
	ErrTextRelationInvalid              = "resource relation invalid"
	ErrTextEnumValueInvalid             = "enum value invalid"
	ErrTextUUIDInvalid                  = "invalid input syntax for type uuid"
	ErrTextRestrictViolation            = "intended action would violate a restriction"
	ErrTextFqnMissingValue              = "FQN must specify a valid value and be of format 'https://<namespace>/attr/<attribute name>/value/<value>'"
	ErrTextListLimitTooLarge            = "requested pagination limit must be less than or equal to configured limit"
	ErrTextInvalidIdentifier            = "value sepcified as the identifier is invalid"
	ErrorTextUnknownIdentifier          = "could not match identifier to known type"
	ErrorTextUpdateToUnspecified        = "cannot update to unspecified value"
	ErrTextKeyRotationFailed            = "key rotation failed"
	ErrorTextExpectedBase64EncodedValue = "expected base64 encoded value"
	ErrorTextMarshalFailed              = "failed to marshal value"
	ErrorTextUnmarsalFailed             = "failed to unmarshal value"
	ErrorTextNamespaceMismatch          = "namespace mismatch"
	ErrorTextKasURIMismatch             = "kas uri mismatch"
	ErrorTextKIDMismatch                = "key id mismatch"
	ErrorTextInvalidOblTrigParam        = "either the obligation value, attribute value, or action provided is invalid"
	ErrorTextFqnMismatch                = "fqn mismatch"
	ErrorTextInvalidCertificate         = "invalid certificate"
	ErrorTextInactiveAttributeValue     = "inactive attribute value"
)

func StatusifyError(ctx context.Context, l *logger.Logger, err error, fallbackErr string, logs ...any) error {
	l = l.With("error", err.Error())
	if errors.Is(err, ErrUniqueConstraintViolation) {
		l.ErrorContext(ctx, ErrTextConflict, logs...)
		return connect.NewError(connect.CodeAlreadyExists, errors.New(ErrTextConflict))
	}
	if errors.Is(err, ErrNotFound) {
		l.ErrorContext(ctx, ErrTextNotFound, logs...)
		return connect.NewError(connect.CodeNotFound, errors.New(ErrTextNotFound))
	}
	if errors.Is(err, ErrForeignKeyViolation) {
		l.ErrorContext(ctx, ErrTextRelationInvalid, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrTextRelationInvalid))
	}
	if errors.Is(err, ErrEnumValueInvalid) {
		l.ErrorContext(ctx, ErrTextEnumValueInvalid, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrTextEnumValueInvalid))
	}
	if errors.Is(err, ErrUUIDInvalid) {
		l.ErrorContext(ctx, ErrTextUUIDInvalid, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrTextUUIDInvalid))
	}
	if errors.Is(err, ErrRestrictViolation) {
		l.ErrorContext(ctx, ErrTextRestrictViolation, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrTextRestrictViolation))
	}
	if errors.Is(err, ErrListLimitTooLarge) {
		l.ErrorContext(ctx, ErrTextListLimitTooLarge, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrTextListLimitTooLarge))
	}
	if errors.Is(err, ErrSelectIdentifierInvalid) {
		l.ErrorContext(ctx, ErrTextInvalidIdentifier, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrTextInvalidIdentifier))
	}
	if errors.Is(err, ErrUnknownSelectIdentifier) {
		l.ErrorContext(ctx, ErrorTextUnknownIdentifier, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrorTextUnknownIdentifier))
	}
	if errors.Is(err, ErrCannotUpdateToUnspecified) {
		l.ErrorContext(ctx, ErrorTextUpdateToUnspecified, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrorTextUpdateToUnspecified))
	}
	if errors.Is(err, ErrKeyRotationFailed) {
		l.ErrorContext(ctx, ErrTextKeyRotationFailed, logs...)
		return connect.NewError(connect.CodeInternal, errors.New(ErrTextKeyRotationFailed))
	}
	if errors.Is(err, ErrExpectedBase64EncodedValue) {
		l.ErrorContext(ctx, ErrorTextExpectedBase64EncodedValue, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrorTextExpectedBase64EncodedValue))
	}
	if errors.Is(err, ErrMarshalValueFailed) {
		l.ErrorContext(ctx, ErrorTextMarshalFailed, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrorTextMarshalFailed))
	}
	if errors.Is(err, ErrKIDMismatch) {
		l.ErrorContext(ctx, ErrorTextKIDMismatch, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrorTextKIDMismatch))
	}
	if errors.Is(err, ErrKasURIMismatch) {
		l.ErrorContext(ctx, ErrorTextKasURIMismatch, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrorTextKasURIMismatch))
	}
	if errors.Is(err, ErrInvalidOblTriParam) {
		l.ErrorContext(ctx, ErrorTextInvalidOblTrigParam, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrorTextInvalidOblTrigParam))
	}
	if errors.Is(err, ErrFqnMismatch) {
		l.ErrorContext(ctx, ErrorTextFqnMismatch, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrorTextFqnMismatch))
	}
	if errors.Is(err, ErrInvalidCertificate) {
		l.ErrorContext(ctx, ErrorTextInvalidCertificate, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrorTextInvalidCertificate))
	}
	if errors.Is(err, ErrAttributeValueInactive) {
		l.ErrorContext(ctx, ErrorTextInactiveAttributeValue, logs...)
		return connect.NewError(connect.CodeInvalidArgument, errors.New(ErrorTextInactiveAttributeValue))
	}

	l.ErrorContext(ctx, "request error", append(logs, slog.Any("error", err))...)
	return connect.NewError(connect.CodeInternal, errors.New(fallbackErr))
}
