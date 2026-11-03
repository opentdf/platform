package authorization

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
)

func TestStatusifyWrappedEvaluationCodes(t *testing.T) {
	for _, tt := range []struct{ input, want connect.Code }{
		{connect.CodeInternal, connect.CodeInternal},
		{connect.CodeUnavailable, connect.CodeUnavailable},
		{connect.CodeDeadlineExceeded, connect.CodeDeadlineExceeded},
		{connect.CodeCanceled, connect.CodeCanceled},
		{connect.CodeResourceExhausted, connect.CodeResourceExhausted},
		{connect.CodePermissionDenied, connect.CodePermissionDenied},
		{connect.CodeUnknown, connect.CodeInternal},
		{connect.CodeUnauthenticated, connect.CodeInternal},
		{connect.CodeInvalidArgument, connect.CodeInternal},
	} {
		t.Run(tt.input.String(), func(t *testing.T) {
			upstream := connect.NewError(tt.input, errors.New("upstream error"))
			err := statusifyError(t.Context(), logger.CreateTestLogger(), errors.Join(ErrFailedToGetDecision, fmt.Errorf("entity resolution: %w", upstream)))
			var response *connect.Error
			require.ErrorAs(t, err, &response)
			require.Equal(t, tt.want, response.Code())
			require.Equal(t, ErrResponseSafeInternalError.Error(), response.Message())
			require.ErrorIs(t, err, ErrResponseSafeInternalError)
		})
	}
}

func TestStatusifyContextAndUnknownErrors(t *testing.T) {
	for _, tt := range []struct {
		name  string
		cause error
		want  connect.Code
	}{
		{"canceled", context.Canceled, connect.CodeCanceled},
		{"deadline", context.DeadlineExceeded, connect.CodeDeadlineExceeded},
		{"unknown", errors.New("unclassified error"), connect.CodeInternal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := statusifyError(t.Context(), logger.CreateTestLogger(), fmt.Errorf("entity resolution: %w", tt.cause))
			require.Equal(t, tt.want, connect.CodeOf(err))
			require.ErrorIs(t, err, ErrResponseSafeInternalError)
		})
	}
}

func TestStatusifyPreservesExistingNotFoundResponse(t *testing.T) {
	for _, sentinel := range []error{access.ErrFQNNotFound, access.ErrDefinitionNotFound} {
		cause := fmt.Errorf("original missing-policy detail: %w", sentinel)
		err := statusifyError(t.Context(), logger.CreateTestLogger(), cause)
		var response *connect.Error
		require.ErrorAs(t, err, &response)
		require.Equal(t, connect.CodeNotFound, response.Code())
		require.Equal(t, cause.Error(), response.Message())
		require.ErrorIs(t, err, cause)
	}
}

func TestSecurityRejectionDoesNotBecomeRetryableOnTimeout(t *testing.T) {
	cause := connect.NewError(connect.CodePermissionDenied, context.DeadlineExceeded)
	err := statusifyError(t.Context(), logger.CreateTestLogger(), cause)
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	require.ErrorIs(t, err, ErrResponseSafeInternalError)
}
