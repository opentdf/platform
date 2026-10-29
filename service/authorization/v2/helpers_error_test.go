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
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestStatusifyEvaluationFailure(t *testing.T) {
	for _, code := range []connect.Code{connect.CodeInternal, connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeCanceled, connect.CodeResourceExhausted, connect.CodeUnknown, connect.CodePermissionDenied, connect.CodeUnauthenticated, connect.CodeInvalidArgument} {
		t.Run(code.String(), func(t *testing.T) {
			upstream := connect.NewError(code, errors.New("secret dependency error"))
			upstream.Meta().Set("X-Secret", "secret")
			detail, err := connect.NewErrorDetail(wrapperspb.String("secret error detail"))
			require.NoError(t, err)
			upstream.AddDetail(detail)
			err = statusifyError(t.Context(), logger.CreateTestLogger(), fmt.Errorf("entity resolution: %w", upstream))
			want := code
			if code == connect.CodeUnknown {
				want = connect.CodeInternal
			}
			require.Equal(t, want, connect.CodeOf(err))
			require.ErrorIs(t, err, upstream)
			require.NotContains(t, err.Error(), "secret")
			var response *connect.Error
			require.ErrorAs(t, err, &response)
			require.Empty(t, response.Meta())
			require.Empty(t, response.Details())
		})
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		err := statusifyError(t.Context(), logger.CreateTestLogger(), fmt.Errorf("entity resolution: %w", cause))
		want := connect.CodeCanceled
		if errors.Is(cause, context.DeadlineExceeded) {
			want = connect.CodeDeadlineExceeded
		}
		require.Equal(t, want, connect.CodeOf(err))
		require.ErrorIs(t, err, cause)
	}
}

func TestMissingPolicyErrorIsRedacted(t *testing.T) {
	for _, cause := range []error{access.ErrFQNNotFound, access.ErrDefinitionNotFound} {
		err := statusifyError(t.Context(), logger.CreateTestLogger(), fmt.Errorf("secret namespace or resource: %w", cause))
		require.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
		require.EqualError(t, err, "not_found: an unexpected error occurred")
		require.ErrorIs(t, err, cause)
	}
}

func TestSecurityRejectionDoesNotBecomeRetryableOnTimeout(t *testing.T) {
	cause := connect.NewError(connect.CodePermissionDenied, context.DeadlineExceeded)
	err := statusifyError(t.Context(), logger.CreateTestLogger(), cause)
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}
