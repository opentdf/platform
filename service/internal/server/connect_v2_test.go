package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/creasty/defaults"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	dualStackV1Procedure = "/dual.v1.LegacyService/Call"
	dualStackV2Procedure = "/dual.v1.CurrentService/Call"
)

// registerTestV2Service returns a register func for a one-procedure v2 service
// that counts calls.
func registerTestV2Service(calls *atomic.Int32) func(*connectv2.Server) {
	return func(srv *connectv2.Server) {
		srv.Register(connectv2.Method{
			Spec: connectv2.Spec{Procedure: dualStackV2Procedure, StreamType: connectv2.StreamTypeUnary},
			Handler: func(_ context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
				var req emptypb.Empty
				if err := stream.Receive(&req); err != nil {
					return err
				}
				calls.Add(1)
				return stream.Send(&emptypb.Empty{})
			},
		})
	}
}

func newTestV1Handler(calls *atomic.Int32) func(...connect.HandlerOption) (string, http.Handler) {
	return func(opts ...connect.HandlerOption) (string, http.Handler) {
		return "/dual.v1.LegacyService/", connect.NewUnaryHandler(
			dualStackV1Procedure,
			func(context.Context, *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
				calls.Add(1)
				return connect.NewResponse(&emptypb.Empty{}), nil
			},
			opts...,
		)
	}
}

func postEmpty(t *testing.T, handler http.Handler, procedure string, body []byte) int {
	t.Helper()
	return serveConnectUnaryTo(t, handler, procedure, body, false).Code
}

func TestConnectRPC_DualStack(t *testing.T) {
	var v1Calls, v2Calls, interceptorCalls atomic.Int32
	rpc := &ConnectRPC{
		Mux: http.NewServeMux(),
		ServerInterceptors: []connectv2.ServerInterceptor{func(next connectv2.ServerFunc) connectv2.ServerFunc {
			return func(ctx context.Context, spec connectv2.Spec, stream connectv2.ServerStream) error {
				interceptorCalls.Add(1)
				return next(ctx, spec, stream)
			}
		}},
		MountOptions: ReadLimitMountOptions(1024),
	}

	require.NoError(t, rpc.RegisterConnectV1("dual.v1.LegacyService", newTestV1Handler(&v1Calls)))
	require.NoError(t, rpc.RegisterConnectV2("dual.v1.CurrentService", registerTestV2Service(&v2Calls)))

	assert.Equal(t, http.StatusOK, postEmpty(t, rpc.Mux, dualStackV1Procedure, nil))
	assert.Equal(t, http.StatusOK, postEmpty(t, rpc.Mux, dualStackV2Procedure, paddedProtoMessage(t, 1024)))
	assert.Equal(t, http.StatusTooManyRequests, postEmpty(t, rpc.Mux, dualStackV2Procedure, paddedProtoMessage(t, 1025)), "mount options apply to v2 services")
	assert.Equal(t, int32(1), v1Calls.Load())
	assert.Equal(t, int32(1), v2Calls.Load())
	assert.Equal(t, int32(2), interceptorCalls.Load(), "server interceptors wrap v2 services")
	assert.Equal(t, []string{"dual.v1.LegacyService", "dual.v1.CurrentService"}, rpc.ServiceReflection)

	t.Run("service options follow the server's", func(t *testing.T) {
		var calls atomic.Int32
		raised := &ConnectRPC{Mux: http.NewServeMux(), MountOptions: ReadLimitMountOptions(1024)}
		require.NoError(t, raised.RegisterConnectV2("dual.v1.CurrentService", registerTestV2Service(&calls), ReadLimitMountOptions(4096)...))

		assert.Equal(t, http.StatusOK, postEmpty(t, raised.Mux, dualStackV2Procedure, paddedProtoMessage(t, 4096)))
	})

	t.Run("mounting a service twice is an error", func(t *testing.T) {
		var calls atomic.Int32
		err := rpc.RegisterConnectV2("dual.v1.CurrentService", registerTestV2Service(&calls))

		require.ErrorIs(t, err, ErrInvalidConnectRPCRegistration)
	})
}

func TestConnectRPC_ExtraInterceptorsFailClosed(t *testing.T) {
	v1Only := ExtraInterceptor{Name: "v1-only", V1: noopInterceptor()}
	v2Only := ExtraInterceptor{Name: "v2-only", V2: noopServerInterceptor()}
	both := ExtraInterceptor{Name: "both", V1: noopInterceptor(), V2: noopServerInterceptor()}

	t.Run("both forms register either version", func(t *testing.T) {
		var calls atomic.Int32
		rpc := &ConnectRPC{Mux: http.NewServeMux()}
		rpc.AddExtraInterceptors(both)

		require.NoError(t, rpc.RegisterConnectV1("dual.v1.LegacyService", newTestV1Handler(&calls)))
		require.NoError(t, rpc.RegisterConnectV2("dual.v1.CurrentService", registerTestV2Service(&calls)))
	})

	t.Run("a v1-only interceptor blocks v2 services", func(t *testing.T) {
		var calls atomic.Int32
		rpc := &ConnectRPC{Mux: http.NewServeMux()}
		rpc.AddExtraInterceptors(v1Only)

		err := rpc.RegisterConnectV2("dual.v1.CurrentService", registerTestV2Service(&calls))
		require.ErrorIs(t, err, ErrMissingInterceptorForm)
		assert.Contains(t, err.Error(), "v1-only")
		require.NoError(t, rpc.RegisterConnectV1("dual.v1.LegacyService", newTestV1Handler(&calls)))
	})

	t.Run("a v2-only interceptor blocks v1 services", func(t *testing.T) {
		var calls atomic.Int32
		rpc := &ConnectRPC{Mux: http.NewServeMux()}
		rpc.AddExtraInterceptors(v2Only)

		err := rpc.RegisterConnectV1("dual.v1.LegacyService", newTestV1Handler(&calls))
		require.ErrorIs(t, err, ErrMissingInterceptorForm)
		assert.Contains(t, err.Error(), "v2-only")
		require.NoError(t, rpc.RegisterConnectV2("dual.v1.CurrentService", registerTestV2Service(&calls)))
	})

	t.Run("services mounted directly fail every call", func(t *testing.T) {
		var calls atomic.Int32
		rpc := &ConnectRPC{Mux: http.NewServeMux()}
		rpc.AddExtraInterceptors(v1Only, v2Only)

		path, handler := newTestV1Handler(&calls)(rpc.Interceptors...)
		rpc.Mux.Handle(path, handler)
		srv := connectv2.NewServer(rpc.ServerInterceptors...)
		registerTestV2Service(&calls)(srv)
		connecthttp.Mount(rpc.Mux, srv)

		assert.Equal(t, http.StatusInternalServerError, postEmpty(t, rpc.Mux, dualStackV1Procedure, nil))
		assert.Equal(t, http.StatusInternalServerError, postEmpty(t, rpc.Mux, dualStackV2Procedure, nil))
		assert.Zero(t, calls.Load())
	})
}

func TestNewConnectRPC_V2InterceptorOrdering(t *testing.T) {
	var order []string
	named := func(name string) connectv2.ServerInterceptor {
		return func(next connectv2.ServerFunc) connectv2.ServerFunc {
			return func(ctx context.Context, spec connectv2.Spec, stream connectv2.ServerStream) error {
				order = append(order, name)
				return next(ctx, spec, stream)
			}
		}
	}
	cfg := Config{Auth: auth.Config{Enabled: true}}
	rpc, err := newConnectRPC(cfg, connectRPCInterceptors{
		auth:        []connect.Interceptor{noopInterceptor()},
		authV2:      []connectv2.ServerInterceptor{named("auth")},
		requestIP:   noopInterceptor(),
		requestIPV2: named("requestIP"),
		extras:      []ExtraInterceptor{{Name: "extra", V1: noopInterceptor(), V2: named("extra")}},
	}, logger.CreateTestLogger())
	require.NoError(t, err)
	var calls atomic.Int32
	require.NoError(t, rpc.RegisterConnectV2("dual.v1.CurrentService", registerTestV2Service(&calls)))

	assert.Equal(t, http.StatusOK, postEmpty(t, rpc.Mux, dualStackV2Procedure, nil))
	assert.Equal(t, []string{"auth", "requestIP", "extra"}, order)
}

// countingReader counts the request body bytes the handler reads.
type countingReader struct {
	io.ReadCloser

	read *atomic.Int64
}

func (r countingReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.read.Add(int64(n))
	return n, err
}

func TestNewOpenTDFServer_DualStackAuthentication(t *testing.T) {
	policyCfg := authz.PolicyConfig{}
	require.NoError(t, defaults.Set(&policyCfg))
	cfg := Config{
		WellKnownConfigRegister: func(string, any) error { return nil },
		Auth: auth.Config{
			Enabled: true,
			AuthNConfig: auth.AuthNConfig{
				Issuer:   newTestOIDCServer(t).URL,
				Audience: "test",
				Policy:   policyCfg,
			},
		},
	}
	srv, err := NewOpenTDFServer(cfg, logger.CreateTestLogger(), nil)
	require.NoError(t, err)

	var v1Calls, v2Calls atomic.Int32
	require.NoError(t, srv.ConnectRPC.RegisterConnectV1("dual.v1.LegacyService", newTestV1Handler(&v1Calls)))
	require.NoError(t, srv.ConnectRPC.RegisterConnectV2("dual.v1.CurrentService", registerTestV2Service(&v2Calls)))

	var read atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = countingReader{ReadCloser: r.Body, read: &read}
		routeConnectRPCRequests(srv.ConnectRPC.Mux, http.NotFoundHandler()).ServeHTTP(w, r)
	})
	oversized := paddedProtoMessage(t, 8<<20)
	for _, procedure := range []string{dualStackV1Procedure, dualStackV2Procedure} {
		t.Run(procedure, func(t *testing.T) {
			read.Store(0)
			req := httptest.NewRequest(http.MethodPost, procedure, bytes.NewReader(oversized))
			req.Header.Set("Content-Type", "application/proto")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusUnauthorized, rr.Code)
			assert.Zero(t, read.Load(), "unauthenticated requests are rejected before the body is read")
		})
	}
	assert.Zero(t, v1Calls.Load())
	assert.Zero(t, v2Calls.Load())
}

func TestNewOpenTDFServer_V2ReadLimitsExternalOnly(t *testing.T) {
	cfg := Config{WellKnownConfigRegister: func(string, any) error { return nil }}
	cfg.GRPC.MaxRecvMsgSizeBytes = 1024
	srv, err := NewOpenTDFServer(cfg, logger.CreateTestLogger(), nil)
	require.NoError(t, err)

	var externalCalls, ipcCalls atomic.Int32
	require.NoError(t, srv.ConnectRPC.RegisterConnectV2("dual.v1.CurrentService", registerTestV2Service(&externalCalls)))
	require.NoError(t, srv.ConnectRPCInProcess.RegisterConnectV2("dual.v1.CurrentService", registerTestV2Service(&ipcCalls)))

	large := paddedProtoMessage(t, defaultMaxRecvMsgSizeBytes+1)
	assert.Equal(t, http.StatusTooManyRequests, postEmpty(t, srv.ConnectRPC.Mux, dualStackV2Procedure, paddedProtoMessage(t, 1025)))
	assert.Equal(t, http.StatusOK, postEmpty(t, srv.ConnectRPC.Mux, dualStackV2Procedure, paddedProtoMessage(t, 1024)))
	assert.Equal(t, http.StatusOK, postEmpty(t, srv.ConnectRPCInProcess.Mux, dualStackV2Procedure, large), "in-process calls stay unlimited")
	assert.Equal(t, int32(1), externalCalls.Load())
	assert.Equal(t, int32(1), ipcCalls.Load())
}
