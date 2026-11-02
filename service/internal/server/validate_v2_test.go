package server

import (
	"context"
	"net/http"
	"testing"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/validate"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validateTestProcedure = "/policy.actions.ActionService/CreateAction"

// TestValidateServerInterceptor_MatchesV1 checks that v2 validation failures
// reach clients exactly as v1 validation failures do.
func TestValidateServerInterceptor_MatchesV1(t *testing.T) {
	v1Handler := connect.NewUnaryHandler(
		validateTestProcedure,
		func(context.Context, *connect.Request[actions.CreateActionRequest]) (*connect.Response[actions.CreateActionResponse], error) {
			return connect.NewResponse(&actions.CreateActionResponse{}), nil
		},
		connect.WithInterceptors(validate.NewInterceptor()),
	)
	v2Calls := 0
	server := connectv2.NewServer(validateServerInterceptor())
	server.Register(connectv2.Method{
		Spec: connectv2.Spec{Procedure: validateTestProcedure, StreamType: connectv2.StreamTypeUnary},
		Handler: func(_ context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
			var req actions.CreateActionRequest
			if err := stream.Receive(&req); err != nil {
				return err
			}
			v2Calls++
			return stream.Send(&actions.CreateActionResponse{})
		},
	})
	v2Mux := http.NewServeMux()
	connecthttp.Mount(v2Mux, server)

	call := func(t *testing.T, handler http.Handler, req *actions.CreateActionRequest) error {
		t.Helper()
		srv := memhttp.New(handler)
		t.Cleanup(func() { _ = srv.Close() })
		client := connect.NewClient[actions.CreateActionRequest, actions.CreateActionResponse](
			srv.Client(), srv.Listener.Addr().String()+validateTestProcedure,
		)
		_, err := client.CallUnary(t.Context(), connect.NewRequest(req))
		return err
	}

	invalid := &actions.CreateActionRequest{Name: "!", NamespaceId: "8f1f5a3c-5c61-4a7c-9f3b-4f3c2f6f9e10"}
	v1Err := call(t, v1Handler, invalid)
	v2Err := call(t, v2Mux, invalid)

	var v1ConnectErr, v2ConnectErr *connect.Error
	require.ErrorAs(t, v1Err, &v1ConnectErr)
	require.ErrorAs(t, v2Err, &v2ConnectErr)
	assert.Equal(t, connect.CodeInvalidArgument, v2ConnectErr.Code())
	assert.Equal(t, v1ConnectErr.Message(), v2ConnectErr.Message())
	require.Len(t, v2ConnectErr.Details(), 1)
	assert.Equal(t, v1ConnectErr.Details()[0].Type(), v2ConnectErr.Details()[0].Type())
	assert.Equal(t, v1ConnectErr.Details()[0].Bytes(), v2ConnectErr.Details()[0].Bytes())
	assert.Zero(t, v2Calls)

	valid := &actions.CreateActionRequest{Name: "valid_name", NamespaceId: "8f1f5a3c-5c61-4a7c-9f3b-4f3c2f6f9e10"}
	require.NoError(t, protovalidate.GlobalValidator.Validate(valid))
	require.NoError(t, call(t, v2Mux, valid))
	assert.Equal(t, 1, v2Calls)
}
