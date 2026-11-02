package serviceregistry

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	registrationTestService   = "registration.v1.TestService"
	registrationTestProcedure = "/registration.v1.TestService/Call"
	registrationTestOther     = "/registration.v1.TestService/Other"
)

type testImpl struct{ name string }

func registerTestImpl(seen *string) func(*connectv2.Server, testImpl) {
	return func(srv *connectv2.Server, impl testImpl) {
		*seen = impl.name
		handler := func(_ context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
			var req emptypb.Empty
			if err := stream.Receive(&req); err != nil {
				return err
			}
			return stream.Send(&emptypb.Empty{})
		}
		srv.Register(
			connectv2.Method{Spec: connectv2.Spec{Procedure: registrationTestProcedure, StreamType: connectv2.StreamTypeUnary}, Handler: handler},
			connectv2.Method{Spec: connectv2.Spec{Procedure: registrationTestOther, StreamType: connectv2.StreamTypeUnary}, Handler: handler},
		)
	}
}

func newTestService(opts ServiceOptions[testImpl]) Service[testImpl] {
	opts.ServiceDesc = &grpc.ServiceDesc{ServiceName: registrationTestService}
	return Service[testImpl]{impl: testImpl{name: "impl"}, ServiceOptions: opts}
}

func padded(t *testing.T, size int) []byte {
	t.Helper()
	for payload := size - 1; payload >= 0; payload-- {
		if 1+protowire.SizeVarint(uint64(payload))+payload == size {
			return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), make([]byte, payload))
		}
	}
	require.FailNow(t, "cannot pad message", "size %d", size)
	return nil
}

func post(t *testing.T, mux http.Handler, procedure string, size int) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, procedure, bytes.NewReader(padded(t, size)))
	req.Header.Set("Content-Type", "application/proto")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr.Code
}

func TestRegisterConnectRPCServiceHandler(t *testing.T) {
	newRPC := func() *server.ConnectRPC { return &server.ConnectRPC{Mux: http.NewServeMux()} }

	t.Run("connect-go v2 registration", func(t *testing.T) {
		var seen string
		var mountImpl testImpl
		svc := newTestService(ServiceOptions[testImpl]{
			ConnectRPCRegisterFunc: registerTestImpl(&seen),
			ConnectRPCMountOptions: func(impl testImpl) []connecthttp.Option {
				mountImpl = impl
				return ConnectReadLimitOptions(1024)
			},
		})
		rpc := newRPC()

		require.NoError(t, svc.RegisterConnectRPCServiceHandler(t.Context(), rpc))

		assert.Equal(t, "impl", seen)
		assert.Equal(t, "impl", mountImpl.name)
		assert.Equal(t, []string{registrationTestService}, rpc.ServiceReflection)
		assert.Equal(t, http.StatusOK, post(t, rpc.Mux, registrationTestProcedure, 1024))
		assert.Equal(t, http.StatusTooManyRequests, post(t, rpc.Mux, registrationTestProcedure, 1025))
	})

	t.Run("connect-go v1 registration", func(t *testing.T) {
		var gotImpl testImpl
		svc := newTestService(ServiceOptions[testImpl]{
			ConnectRPCFunc: func(impl testImpl, opts ...connect.HandlerOption) (string, http.Handler) {
				gotImpl = impl
				return "/registration.v1.TestService/", connect.NewUnaryHandler(
					registrationTestProcedure,
					func(context.Context, *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
						return connect.NewResponse(&emptypb.Empty{}), nil
					},
					opts...,
				)
			},
		})
		rpc := newRPC()

		require.NoError(t, svc.RegisterConnectRPCServiceHandler(t.Context(), rpc))

		assert.Equal(t, "impl", gotImpl.name)
		assert.Equal(t, []string{registrationTestService}, rpc.ServiceReflection)
		assert.Equal(t, http.StatusOK, post(t, rpc.Mux, registrationTestProcedure, 8))
	})

	t.Run("both versions is invalid", func(t *testing.T) {
		var seen string
		svc := newTestService(ServiceOptions[testImpl]{
			ConnectRPCRegisterFunc: registerTestImpl(&seen),
			ConnectRPCFunc: func(testImpl, ...connect.HandlerOption) (string, http.Handler) {
				return "/", http.NotFoundHandler()
			},
		})

		require.ErrorIs(t, svc.RegisterConnectRPCServiceHandler(t.Context(), newRPC()), ErrInvalidConnectRPCRegistration)
	})

	t.Run("mount options need a v2 registration", func(t *testing.T) {
		svc := newTestService(ServiceOptions[testImpl]{
			ConnectRPCMountOptions: func(testImpl) []connecthttp.Option { return nil },
		})

		require.ErrorIs(t, svc.RegisterConnectRPCServiceHandler(t.Context(), newRPC()), ErrInvalidConnectRPCRegistration)
	})

	t.Run("no handler", func(t *testing.T) {
		svc := newTestService(ServiceOptions[testImpl]{})

		require.ErrorIs(t, svc.RegisterConnectRPCServiceHandler(t.Context(), newRPC()), ErrNoConnectRPCHandler)
	})
}

func TestConnectProcedureReadLimits(t *testing.T) {
	var seen string
	svc := newTestService(ServiceOptions[testImpl]{
		ConnectRPCRegisterFunc: registerTestImpl(&seen),
		ConnectRPCMountOptions: func(testImpl) []connecthttp.Option {
			return append(ConnectReadLimitOptions(1024), ConnectProcedureReadLimits(map[string]int{registrationTestOther: 4096}))
		},
	})
	rpc := &server.ConnectRPC{Mux: http.NewServeMux(), MountOptions: ConnectReadLimitOptions(2048)}
	require.NoError(t, svc.RegisterConnectRPCServiceHandler(t.Context(), rpc))

	assert.Equal(t, http.StatusTooManyRequests, post(t, rpc.Mux, registrationTestProcedure, 1025), "service options override the server's")
	assert.Equal(t, http.StatusOK, post(t, rpc.Mux, registrationTestOther, 4096), "procedure limits override the service's")
	assert.Equal(t, http.StatusTooManyRequests, post(t, rpc.Mux, registrationTestOther, 4097))
}
