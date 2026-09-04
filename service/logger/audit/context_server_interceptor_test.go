package audit

import (
	"context"
	"errors"
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

func TestContextServerInterceptorCancelsBufferedEventsOnReturnedError(t *testing.T) {
	logger := createDiscardLogger()
	var processed Event
	logger.processor = ProcessorFunc(func(_ context.Context, event Event) error {
		processed = event
		return nil
	})
	requestErr := errors.New("request failed")
	next := ContextServerInterceptor(logger)(
		func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			logger.PolicyCRUDSuccess(ctx, policyCRUDParams)
			return nil, requestErr
		},
	)

	_, err := next(t.Context(), connect.NewRequest(&struct{}{}))

	require.ErrorIs(t, err, requestErr)
	assert.Equal(t, ActionResultCancel, processed.Action.Result)
	assert.Equal(t, requestErr.Error(), processed.EventMetaData["cancellation_error"])
}

func TestContextServerInterceptorPreservesBufferedErrorOnReturnedError(t *testing.T) {
	logger := createDiscardLogger()
	var processed Event
	logger.processor = ProcessorFunc(func(_ context.Context, event Event) error {
		processed = event
		return nil
	})
	requestErr := errors.New("request failed")
	next := ContextServerInterceptor(logger)(
		func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			logger.PolicyCRUDFailure(ctx, policyCRUDParams)
			return nil, requestErr
		},
	)

	_, err := next(t.Context(), connect.NewRequest(&struct{}{}))

	require.ErrorIs(t, err, requestErr)
	assert.Equal(t, ActionResultError, processed.Action.Result)
	assert.Equal(t, requestErr.Error(), processed.EventMetaData["cancellation_error"])
}

func createDiscardLogger() *Logger {
	logger, _ := createTestLogger()
	return logger
}
