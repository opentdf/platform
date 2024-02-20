package services

import (
	"errors"
	"log/slog"

	"github.com/opentdf/platform/internal/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	ErrCreationFailed      = "resource creation failed"
	ErrDeletionFailed      = "resource deletion failed"
	ErrGetRetrievalFailed  = "resource retrieval failed"
	ErrListRetrievalFailed = "resource list retrieval failed"
	ErrUpdateFailed        = "resource update failed"
	ErrNotFound            = "resource not found"
	ErrConflict            = "resource unique field violation"
	ErrRelationInvalid     = "resource relation invalid"
	ErrEnumValueInvalid    = "enum value invalid"
	ErrUuidInvalid         = "value not a valid uuid"
	ErrRestrictViolation   = "intended action would violate a restriction"
)

func HandleError(err error, fallbackErr string, log ...any) error {
	l := append([]any{"error", err.Error()}, log...)
	if errors.Is(err, db.ErrUniqueConstraintViolation) {
		slog.Error(ErrConflict, l...)
		return status.Error(codes.AlreadyExists, ErrConflict)
	}
	if errors.Is(err, db.ErrNotFound) {
		slog.Error(ErrNotFound, l...)
		return status.Error(codes.NotFound, ErrNotFound)
	}
	if errors.Is(err, db.ErrForeignKeyViolation) {
		slog.Error(ErrRelationInvalid, l...)
		return status.Error(codes.InvalidArgument, ErrRelationInvalid)
	}
	if errors.Is(err, db.ErrEnumValueInvalid) {
		slog.Error(ErrEnumValueInvalid, l...)
		return status.Error(codes.InvalidArgument, ErrEnumValueInvalid)
	}
	if errors.Is(err, db.ErrUuidInvalid) {
		slog.Error(ErrUuidInvalid, l...)
		return status.Error(codes.InvalidArgument, ErrUuidInvalid)
	}
	if errors.Is(err, db.ErrRestrictViolation) {
		slog.Error(ErrRestrictViolation, l...)
		return status.Error(codes.InvalidArgument, ErrRestrictViolation)
	}
	slog.Error(err.Error(), l...)
	return status.Error(codes.Internal, fallbackErr)
}
