package server

import (
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

// noopExtra returns a pass-through interceptor in both connect-go forms.
func noopExtra(name string) ConnectServerInterceptor {
	return ConnectServerInterceptor{Name: name, V1: noopInterceptor(), V2: noopServerInterceptor()}
}

func TestValidateExternalInterceptorFactoryAcceptsFactory(t *testing.T) {
	err := validateExternalInterceptorFactory(InterceptorFactory{
		Name: "both",
		Factory: func(InterceptorParams) (ConnectServerInterceptor, error) {
			return noopExtra(""), nil
		},
	})

	require.NoError(t, err)
}

func TestBuildExternalInterceptor(t *testing.T) {
	t.Run("both forms named after the factory", func(t *testing.T) {
		extra, err := buildExternalInterceptor(InterceptorFactory{
			Name:    "both",
			Factory: func(InterceptorParams) (ConnectServerInterceptor, error) { return noopExtra("other"), nil },
		}, InterceptorParams{})

		require.NoError(t, err)
		assert.Equal(t, "both", extra.Name)
		assert.NotNil(t, extra.V1)
		assert.NotNil(t, extra.V2)
	})

	t.Run("factory error", func(t *testing.T) {
		_, err := buildExternalInterceptor(InterceptorFactory{
			Name: "broken",
			Factory: func(InterceptorParams) (ConnectServerInterceptor, error) {
				return ConnectServerInterceptor{}, errors.New("boom")
			},
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

		require.NoError(t, registerConnectRPCHandler(t.Context(), svc, newRPC(), log))
	})
}
