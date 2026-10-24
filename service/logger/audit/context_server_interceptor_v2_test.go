package audit

import (
	"context"
	"net"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/opentdf/platform/service/internal/server/realip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestContextServerInterceptorV2(t *testing.T) {
	const procedure = "/audit.test.v1.AuditService/Call"
	withClientIP := func(next connectv2.ServerFunc) connectv2.ServerFunc {
		return func(ctx context.Context, spec connectv2.Spec, stream connectv2.ServerStream) error {
			return next(context.WithValue(ctx, realip.ClientIP{}, net.ParseIP("127.0.0.1")), spec, stream)
		}
	}
	var captured ContextData
	var propagatedRequestID uuid.UUID
	server := connectv2.NewServer(withClientIP, ContextServerInterceptorV2())
	server.Register(connectv2.Method{
		Spec: connectv2.Spec{Procedure: procedure, StreamType: connectv2.StreamTypeUnary},
		Handler: func(ctx context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
			var req emptypb.Empty
			if err := stream.Receive(&req); err != nil {
				return err
			}
			captured = GetAuditDataFromContext(ctx)
			propagatedRequestID, _ = ctx.Value(sdkAudit.RequestIDContextKey).(uuid.UUID)
			return stream.Send(&emptypb.Empty{})
		},
	})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	srv := memhttp.New(mux)
	t.Cleanup(func() { _ = srv.Close() })

	requestID := uuid.New()
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](srv.Client(), srv.Listener.Addr().String()+procedure)
	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set(sdkAudit.RequestIDHeaderKey.String(), requestID.String())
	req.Header().Set(sdkAudit.UserAgentHeaderKey.String(), "audit-test")

	_, err := client.CallUnary(t.Context(), req)

	require.NoError(t, err)
	assert.Equal(t, requestID, captured.RequestID)
	assert.Equal(t, requestID, propagatedRequestID)
	assert.Equal(t, "127.0.0.1", captured.RequestIP)
	assert.Equal(t, "audit-test", captured.UserAgent)
}
