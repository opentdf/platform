package connectcompat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	connectv1 "connectrpc.com/connect"
	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const compatTestProcedure = "/compat.test.v1.CompatService/Call"

func TestCodeOf(t *testing.T) {
	v2Err := connect.NewError(connect.CodeNotFound, "missing")
	v1Err := connectv1.NewError(connectv1.CodePermissionDenied, errors.New("denied"))

	assert.Equal(t, connect.CodeNotFound, CodeOf(v2Err))
	assert.Equal(t, connect.CodeNotFound, CodeOf(fmt.Errorf("wrapped: %w", v2Err)))
	assert.Equal(t, connect.CodePermissionDenied, CodeOf(v1Err))
	assert.Equal(t, connect.CodePermissionDenied, CodeOf(fmt.Errorf("wrapped: %w", v1Err)))
	assert.Equal(t, connect.CodeUnknown, CodeOf(errors.New("plain")))
	assert.Equal(t, connect.CodeUnknown, CodeOf(nil))
}

func TestToV2ErrorKeepsLocalErrors(t *testing.T) {
	local := connect.NewError(connect.CodeNotFound, "missing")
	wrapped := fmt.Errorf("wrapped: %w", local)

	require.NoError(t, ToV2Error(t.Context(), nil))
	assert.Same(t, local, ToV2Error(t.Context(), local))
	assert.Equal(t, wrapped, ToV2Error(t.Context(), wrapped))
}

// TestServerInterceptor checks what a v1 client receives from a v2 handler
// for each kind of error, with and without the interceptor, over every
// protocol the platform serves.
func TestServerInterceptor(t *testing.T) {
	detail, err := connectv1.NewErrorDetail(wrapperspb.String("detail"))
	require.NoError(t, err)

	handlerErrors := map[string]error{
		"v1": func() error {
			v1Err := connectv1.NewError(connectv1.CodeNotFound, errors.New("upstream missing"))
			v1Err.AddDetail(detail)
			v1Err.Meta().Set("X-Upstream", "meta")
			return v1Err
		}(),
		"remote":   connect.NewError(connect.CodeFailedPrecondition, "remote precondition").WithRemote(),
		"plain":    errors.New("db timeout"),
		"local":    connect.NewError(connect.CodePermissionDenied, "denied"),
		"canceled": context.Canceled,
	}
	newServer := func(t *testing.T, interceptors ...connect.ServerInterceptor) *memhttp.Server {
		t.Helper()
		server := connect.NewServer(interceptors...)
		server.Register(connect.Method{
			Spec: connect.Spec{Procedure: compatTestProcedure, StreamType: connect.StreamTypeUnary},
			Handler: func(_ context.Context, _ connect.Spec, stream connect.ServerStream) error {
				var req wrapperspb.StringValue
				if err := stream.Receive(&req); err != nil {
					return err
				}
				return handlerErrors[req.GetValue()]
			},
		})
		mux := http.NewServeMux()
		connecthttp.Mount(mux, server)
		srv := memhttp.New(mux)
		t.Cleanup(func() { _ = srv.Close() })
		return srv
	}
	call := func(t *testing.T, srv *memhttp.Server, value string, opts ...connectv1.ClientOption) *connectv1.Error {
		t.Helper()
		client := connectv1.NewClient[wrapperspb.StringValue, wrapperspb.StringValue](
			srv.Client(), srv.Listener.Addr().String()+compatTestProcedure, opts...,
		)
		_, err := client.CallUnary(t.Context(), connectv1.NewRequest(wrapperspb.String(value)))
		var connectErr *connectv1.Error
		require.ErrorAs(t, err, &connectErr)
		return connectErr
	}

	protocols := map[string][]connectv1.ClientOption{
		"connect": nil,
		"grpc":    {connectv1.WithGRPC()},
		"grpcweb": {connectv1.WithGRPCWeb()},
	}
	cases := []struct {
		value       string
		wantCode    connectv1.Code
		wantMessage string
	}{
		{"v1", connectv1.CodeNotFound, "upstream missing"},
		{"remote", connectv1.CodeFailedPrecondition, "remote precondition"},
		{"plain", connectv1.CodeUnknown, "db timeout"},
		{"local", connectv1.CodePermissionDenied, "denied"},
		{"canceled", connectv1.CodeCanceled, context.Canceled.Error()},
	}
	srv := newServer(t, ServerInterceptor())
	for protocol, opts := range protocols {
		for _, tc := range cases {
			t.Run(protocol+"/"+tc.value, func(t *testing.T) {
				connectErr := call(t, srv, tc.value, opts...)

				assert.Equal(t, tc.wantCode, connectErr.Code())
				assert.Equal(t, tc.wantMessage, connectErr.Message())
				if tc.value == "v1" {
					require.Len(t, connectErr.Details(), 1)
					value, err := connectErr.Details()[0].Value()
					require.NoError(t, err)
					stringValue, ok := value.(*wrapperspb.StringValue)
					require.True(t, ok)
					assert.Equal(t, "detail", stringValue.GetValue())
					assert.Equal(t, "meta", connectErr.Meta().Get("X-Upstream"))
				}
			})
		}
	}

	t.Run("without the interceptor v2 drops the message", func(t *testing.T) {
		bare := newServer(t)

		v1Err := call(t, bare, "v1")
		assert.Equal(t, connectv1.CodeUnknown, v1Err.Code())
		assert.Empty(t, v1Err.Message())

		remoteErr := call(t, bare, "remote")
		assert.Equal(t, connectv1.CodeInternal, remoteErr.Code())
		assert.Empty(t, remoteErr.Message())
	})
}

func TestHTTPHeader(t *testing.T) {
	var header connect.Header
	header.Add("Authorization", "Bearer token")
	header.Add("X-Multi", "a")
	header.Add("X-Multi", "b")

	out := HTTPHeader(&header)

	assert.Equal(t, "Bearer token", out.Get("Authorization"))
	assert.Equal(t, []string{"a", "b"}, out.Values("X-Multi"))
	assert.Empty(t, HTTPHeader(nil))
	assert.Empty(t, RequestHeader(t.Context()))
}
