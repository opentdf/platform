package server

import (
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
)

func newConnectRPCIPC(_ Config, a *auth.Authentication, _ *logger.Logger) (*ConnectRPC, error) {
	interceptors := make([]connect.HandlerOption, 0)

	// Auth interceptor
	interceptors = append(interceptors, connect.WithInterceptors(a.IPCUnaryServerInterceptor()))

	// Add protovalidate interceptor
	validationInterceptor, err := validate.NewInterceptor()
	if err != nil {
		return nil, fmt.Errorf("failed to create validation interceptor: %w", err)
	}

	interceptors = append(interceptors, connect.WithInterceptors(validationInterceptor, audit.ContextServerInterceptor()))

	return &ConnectRPC{
		Interceptors: interceptors,
		Mux:          http.NewServeMux(),
	}, nil
}

func newConnectRPC(_ Config, a *auth.Authentication, _ *logger.Logger) (*ConnectRPC, error) {
	interceptors := make([]connect.HandlerOption, 0)

	// Auth interceptor
	interceptors = append(interceptors, connect.WithInterceptors(a.ConnectUnaryServerInterceptor()))

	// Add protovalidate interceptor
	validationInterceptor, err := validate.NewInterceptor()
	if err != nil {
		return nil, fmt.Errorf("failed to create validation interceptor: %w", err)
	}

	interceptors = append(interceptors, connect.WithInterceptors(validationInterceptor, audit.ContextServerInterceptor()))

	return &ConnectRPC{
		Interceptors: interceptors,
		Mux:          http.NewServeMux(),
	}, nil
}
