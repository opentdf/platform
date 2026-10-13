package server

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func noopServerInterceptor() connectv2.ServerInterceptor {
	return func(next connectv2.ServerFunc) connectv2.ServerFunc { return next }
}

func TestWithConnectServerInterceptors(t *testing.T) {
	first := ConnectServerInterceptor{Name: "first", V1: noopInterceptor(), V2: noopServerInterceptor()}
	second := ConnectServerInterceptor{Name: "second", V2: noopServerInterceptor()}

	cfg := WithConnectServerInterceptors(first)(StartConfig{})
	cfg = WithConnectServerInterceptors(second)(cfg)
	cfg = WithIPCServerInterceptors(first)(cfg)

	require.Len(t, cfg.extraConnectServerInterceptors, 2)
	assert.Equal(t, "first", cfg.extraConnectServerInterceptors[0].Name)
	assert.Equal(t, "second", cfg.extraConnectServerInterceptors[1].Name)
	require.Len(t, cfg.extraIPCServerInterceptors, 1)
}

func TestValidateExternalInterceptorFactoryAcceptsServerFactory(t *testing.T) {
	err := validateExternalInterceptorFactory(InterceptorFactory{
		Name: "v2",
		ServerFactory: func(InterceptorParams) (connectv2.ServerInterceptor, error) {
			return noopServerInterceptor(), nil
		},
	})

	require.NoError(t, err)
}

func TestBuildExternalInterceptor(t *testing.T) {
	t.Run("both forms", func(t *testing.T) {
		extra, err := buildExternalInterceptor(InterceptorFactory{
			Name:          "both",
			Factory:       func(InterceptorParams) (connect.Interceptor, error) { return noopInterceptor(), nil },
			ServerFactory: func(InterceptorParams) (connectv2.ServerInterceptor, error) { return noopServerInterceptor(), nil },
		}, InterceptorParams{})

		require.NoError(t, err)
		assert.Equal(t, "both", extra.Name)
		assert.NotNil(t, extra.V1)
		assert.NotNil(t, extra.V2)
	})

	t.Run("factory error", func(t *testing.T) {
		_, err := buildExternalInterceptor(InterceptorFactory{
			Name:          "broken",
			ServerFactory: func(InterceptorParams) (connectv2.ServerInterceptor, error) { return nil, errors.New("boom") },
		}, InterceptorParams{})

		require.ErrorContains(t, err, `"broken"`)
	})
}

// registrationTestService registers a connect-go v1 or v2 handler with no
// procedures, enough to exercise registration.
func registrationTestService(v2 bool) serviceregistry.IService {
	opts := serviceregistry.ServiceOptions[struct{}]{
		Namespace:   "registration",
		ServiceDesc: &grpc.ServiceDesc{ServiceName: "registration.v1.TestService"},
		RegisterFunc: func(serviceregistry.RegistrationParams) (struct{}, serviceregistry.HandlerServer) {
			return struct{}{}, nil
		},
	}
	if v2 {
		opts.ConnectRPCRegisterFunc = func(*connectv2.Server, struct{}) {}
	} else {
		opts.ConnectRPCFunc = func(struct{}, ...connect.HandlerOption) (string, http.Handler) {
			return "/registration.v1.TestService/", http.NotFoundHandler()
		}
	}
	return &serviceregistry.Service[struct{}]{ServiceOptions: opts}
}

func TestRegisterConnectRPCHandler(t *testing.T) {
	log := logger.CreateTestLogger()
	newRPC := func(extras ...ConnectServerInterceptor) *server.ConnectRPC {
		rpc := &server.ConnectRPC{Mux: http.NewServeMux()}
		rpc.AddExtraInterceptors(extras...)
		return rpc
	}
	v1Only := ConnectServerInterceptor{Name: "license", V1: noopInterceptor()}
	v2Only := ConnectServerInterceptor{Name: "license", V2: noopServerInterceptor()}

	t.Run("a v1-only interceptor stops a v2 service", func(t *testing.T) {
		err := registerConnectRPCHandler(t.Context(), registrationTestService(true), newRPC(v1Only), log)

		require.ErrorIs(t, err, serviceregistry.ErrMissingInterceptorForm)
		assert.Contains(t, err.Error(), "license")
	})

	t.Run("a v2-only interceptor stops a v1 service", func(t *testing.T) {
		err := registerConnectRPCHandler(t.Context(), registrationTestService(false), newRPC(v2Only), log)

		require.ErrorIs(t, err, serviceregistry.ErrMissingInterceptorForm)
	})

	t.Run("matching forms register", func(t *testing.T) {
		require.NoError(t, registerConnectRPCHandler(t.Context(), registrationTestService(true), newRPC(v2Only), log))
		require.NoError(t, registerConnectRPCHandler(t.Context(), registrationTestService(false), newRPC(v1Only), log))
	})

	t.Run("a service without a handler is skipped", func(t *testing.T) {
		svc := &serviceregistry.Service[struct{}]{ServiceOptions: serviceregistry.ServiceOptions[struct{}]{
			Namespace:   "registration",
			ServiceDesc: &grpc.ServiceDesc{ServiceName: "registration.v1.TestService"},
		}}

		require.NoError(t, registerConnectRPCHandler(context.Background(), svc, newRPC(), log))
	})
}
