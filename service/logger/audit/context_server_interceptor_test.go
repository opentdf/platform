package audit

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContextServerInterceptorIgnoresForwardedActorHeader(t *testing.T) {
	token, err := jwt.NewBuilder().Subject("verified-subject").Build()
	require.NoError(t, err)
	ctx := ctxAuth.ContextWithAuthNInfo(t.Context(), nil, token, "raw-token")
	req := connect.NewRequest(&struct{}{})
	req.Header().Set(sdkAudit.ActorIDHeaderKey.String(), "spoofed-subject")

	var captured ContextData
	next := ContextServerInterceptor(createDiscardLogger())(
		func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			captured = GetAuditDataFromContext(ctx)
			return nil, nil //nolint:nilnil // response is irrelevant to context propagation
		},
	)

	_, err = next(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "verified-subject", captured.ActorID)
}

func TestContextServerInterceptorDoesNotTreatHeaderAsPrincipal(t *testing.T) {
	req := connect.NewRequest(&struct{}{})
	req.Header().Set(sdkAudit.ActorIDHeaderKey.String(), "spoofed-subject")

	var captured ContextData
	next := ContextServerInterceptor(createDiscardLogger())(
		func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			captured = GetAuditDataFromContext(ctx)
			return nil, nil //nolint:nilnil // response is irrelevant to context propagation
		},
	)

	_, err := next(t.Context(), req)
	require.NoError(t, err)
	assert.Empty(t, captured.ActorID)
}

func createDiscardLogger() *Logger {
	logger, _ := createTestLogger()
	return logger
}
