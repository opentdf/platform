package access

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestOrganizationIDClientInterceptor_ForwardsOptionalOrganizationID(t *testing.T) {
	assertForwarded := func(t *testing.T, ctx context.Context, expectedHeader string) {
		t.Helper()
		var actualHeader string
		next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			actualHeader = req.Header().Get(OrganizationIDHeader)
			return connect.NewResponse(&emptypb.Empty{}), nil
		}

		_, err := NewOrganizationIDClientInterceptor()(next)(ctx, connect.NewRequest(&emptypb.Empty{}))

		require.NoError(t, err)
		require.Equal(t, expectedHeader, actualHeader)
	}

	t.Run("absent", func(t *testing.T) {
		assertForwarded(t, t.Context(), "")
	})
	t.Run("present", func(t *testing.T) {
		assertForwarded(t, WithOrganizationID(t.Context(), "organization-id"), "organization-id")
	})
}
