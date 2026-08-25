package audit

import (
	"context"
	"net"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/server/realip"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContextServerInterceptorUsesResolvedIP(t *testing.T) {
	ctx := context.WithValue(t.Context(), realip.ClientIP{}, net.ParseIP("127.0.0.1"))
	req := connect.NewRequest(&struct{}{})
	req.Header().Set(sdkAudit.RequestIPHeaderKey.String(), "203.0.113.10")
	requestID := uuid.New()
	req.Header().Set(sdkAudit.RequestIDHeaderKey.String(), requestID.String())

	var captured ContextData
	var propagatedIP string
	var propagatedRequestID uuid.UUID
	next := ContextServerInterceptor(createDiscardLogger())(
		func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			captured = GetAuditDataFromContext(ctx)
			propagatedIP, _ = ctx.Value(sdkAudit.RequestIPContextKey).(string)
			propagatedRequestID, _ = ctx.Value(sdkAudit.RequestIDContextKey).(uuid.UUID)
			return nil, nil //nolint:nilnil // response is irrelevant to context propagation
		},
	)

	_, err := next(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", captured.RequestIP)
	assert.Equal(t, "127.0.0.1", propagatedIP)
	assert.Equal(t, requestID, propagatedRequestID)
}

func TestContextServerInterceptorIgnoresForwardedActorHeader(t *testing.T) {
	token, err := jwt.NewBuilder().Subject("verified-subject").Build()
	require.NoError(t, err)
	ctx := ctxAuth.ContextWithAuthNInfo(t.Context(), nil, token, "raw-token")
	req := connect.NewRequest(&struct{}{})
	req.Header().Set(sdkAudit.ActorIDHeaderKey.String(), "spoofed-subject") //nolint:staticcheck // regression test for the deprecated spoofable header

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
	req.Header().Set(sdkAudit.ActorIDHeaderKey.String(), "spoofed-subject") //nolint:staticcheck // regression test for the deprecated spoofable header

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
