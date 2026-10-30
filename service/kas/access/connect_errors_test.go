package access

import (
	"errors"
	"testing"

	"connectrpc.com/connect/v2"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestErrorHelpersKeepSentinels(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		code     connect.Code
		sentinel error
		status   error
	}{
		{"err400", err400("bad"), connect.CodeInvalidArgument, ErrUser, status.Error(codes.InvalidArgument, "bad")},
		{"err401", err401("bad"), connect.CodeUnauthenticated, ErrUser, status.Error(codes.Unauthenticated, "bad")},
		{"err403", err403("bad"), connect.CodePermissionDenied, ErrUser, status.Error(codes.PermissionDenied, "bad")},
		{"err500", err500("bad"), connect.CodeInternal, ErrInternal, status.Error(codes.Internal, "bad")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, tt.err, tt.sentinel)
			var connectErr *connect.Error
			require.ErrorAs(t, tt.err, &connectErr)
			assert.Equal(t, tt.code, connectErr.Code())
			assert.Equal(t, errors.Join(tt.sentinel, tt.status).Error(), connectErr.Message())
		})
	}
}

func TestLookupKidKeepsConfigSentinel(t *testing.T) {
	p := &Provider{Logger: logger.CreateTestLogger()}

	_, err := p.lookupKid(t.Context(), security.AlgorithmRSA2048)

	require.ErrorIs(t, err, ErrConfig)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}
