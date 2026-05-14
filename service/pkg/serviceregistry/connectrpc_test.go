package serviceregistry

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestConnectRPCSplitDefaultsToExistingHandler(t *testing.T) {
	t.Parallel()

	var calls []string
	service := newConnectRPCTestService(
		func(impl string, _ ...connect.HandlerOption) (string, http.Handler) {
			calls = append(calls, impl)
			return "/test.Default/Call", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		},
		nil,
		nil,
	)

	require.NoError(t, service.Start(context.Background(), RegistrationParams{}))
	require.NoError(t, service.RegisterExternalConnectRPCServiceHandler(context.Background(), newTestConnectRPC()))
	require.NoError(t, service.RegisterIPCConnectRPCServiceHandler(context.Background(), newTestConnectRPC()))

	require.Equal(t, []string{"impl", "impl"}, calls)
}

func TestConnectRPCSplitUsesExplicitExternalAndIPCHandlers(t *testing.T) {
	t.Parallel()

	var calls []string
	service := newConnectRPCTestService(
		nil,
		func(impl string, _ ...connect.HandlerOption) (string, http.Handler) {
			calls = append(calls, "external:"+impl)
			return "/test.External/Call", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		},
		func(impl string, _ ...connect.HandlerOption) (string, http.Handler) {
			calls = append(calls, "ipc:"+impl)
			return "/test.IPC/Call", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		},
	)

	require.NoError(t, service.Start(context.Background(), RegistrationParams{}))
	require.NoError(t, service.RegisterExternalConnectRPCServiceHandler(context.Background(), newTestConnectRPC()))
	require.NoError(t, service.RegisterIPCConnectRPCServiceHandler(context.Background(), newTestConnectRPC()))

	require.Equal(t, []string{"external:impl", "ipc:impl"}, calls)
}

func TestConnectRPCSplitRejectsOnlyExternalHandler(t *testing.T) {
	t.Parallel()

	service := newConnectRPCTestService(
		nil,
		func(string, ...connect.HandlerOption) (string, http.Handler) {
			return "/test.External/Call", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		},
		nil,
	)

	require.ErrorContains(
		t,
		service.Start(context.Background(), RegistrationParams{}),
		"external and IPC ConnectRPC handlers must be configured together",
	)
}

func TestConnectRPCSplitRejectsOnlyIPCHandler(t *testing.T) {
	t.Parallel()

	service := newConnectRPCTestService(
		nil,
		nil,
		func(string, ...connect.HandlerOption) (string, http.Handler) {
			return "/test.IPC/Call", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		},
	)

	require.ErrorContains(
		t,
		service.Start(context.Background(), RegistrationParams{}),
		"external and IPC ConnectRPC handlers must be configured together",
	)
}

func newConnectRPCTestService(
	defaultFunc func(string, ...connect.HandlerOption) (string, http.Handler),
	externalFunc func(string, ...connect.HandlerOption) (string, http.Handler),
	ipcFunc func(string, ...connect.HandlerOption) (string, http.Handler),
) *Service[string] {
	return &Service[string]{
		ServiceOptions: ServiceOptions[string]{
			ServiceDesc: &grpc.ServiceDesc{ServiceName: "test.Service"},
			RegisterFunc: func(RegistrationParams) (string, HandlerServer) {
				return "impl", nil
			},
			ConnectRPCFunc:         defaultFunc,
			ExternalConnectRPCFunc: externalFunc,
			IPCConnectRPCFunc:      ipcFunc,
		},
	}
}

func newTestConnectRPC() *server.ConnectRPC {
	return &server.ConnectRPC{
		Mux: http.NewServeMux(),
	}
}
