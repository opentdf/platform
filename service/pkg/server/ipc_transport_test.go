package server

import (
	"context"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/actions/actionsconnect"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/namespaces/namespacesconnect"
	"github.com/opentdf/platform/service/internal/auth"
	internalserver "github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ipcTestID        = "00000000-0000-0000-0000-000000000099"
	ipcTestFailureID = "00000000-0000-0000-0000-000000000098"
)

type ipcActionHandler struct {
	actionsconnect.UnimplementedActionServiceHandler
	calls atomic.Int64
	peers chan string
}

func (h *ipcActionHandler) GetAction(_ context.Context, req *connect.Request[actions.GetActionRequest]) (*connect.Response[actions.GetActionResponse], error) {
	h.calls.Add(1)
	h.peers <- req.Peer().Addr
	if req.Msg.GetId() == ipcTestFailureID {
		panic("controlled failure after side effect")
	}
	return connect.NewResponse(&actions.GetActionResponse{Action: &policy.Action{Id: req.Msg.GetId(), Name: "routed"}}), nil
}

type ipcNamespaceHandler struct {
	namespacesconnect.UnimplementedNamespaceServiceHandler
	peers chan string
}

func (h *ipcNamespaceHandler) GetNamespace(_ context.Context, req *connect.Request[namespaces.GetNamespaceRequest]) (*connect.Response[namespaces.GetNamespaceResponse], error) {
	h.peers <- req.Peer().Addr
	return connect.NewResponse(&namespaces.GetNamespaceResponse{Namespace: &policy.Namespace{Id: req.Msg.GetNamespaceId(), Name: "v1"}}), nil
}

func ipcTestRegistry(t *testing.T, modes []string) *serviceregistry.Registry {
	t.Helper()
	reg := serviceregistry.NewServiceRegistry()
	_, err := reg.RegisterServicesFromConfiguration(modes, getServiceConfigurations())
	require.NoError(t, err)
	return reg
}

func newIPCTestServer(t *testing.T) *internalserver.OpenTDFServer {
	t.Helper()
	otdf, err := internalserver.NewOpenTDFServer(internalserver.Config{
		Auth: auth.Config{Enabled: false},
		GRPC: internalserver.GRPCConfig{
			MaxCallRecvMsgSizeBytes: 4 << 20,
			MaxCallSendMsgSizeBytes: 4 << 20,
		},
		WellKnownConfigRegister: func(string, any) error { return nil },
	}, logger.CreateTestLogger(), nil)
	require.NoError(t, err)
	t.Cleanup(otdf.Stop)
	return otdf
}

func TestValidateIPCTransportAgainstRegisteredDescriptorsAndMode(t *testing.T) {
	tests := []struct {
		name          string
		transport     string
		modes         []string
		want          string
		errorContains string
	}{
		{name: "empty retains default v1", modes: []string{"kas"}, want: internalserver.IPCTransportConnectV1},
		{name: "explicit v1 remote mode", transport: internalserver.IPCTransportConnectV1, modes: []string{"kas"}, want: internalserver.IPCTransportConnectV1},
		{name: "v2 core with Action descriptor", transport: internalserver.IPCTransportLocalHTTPV2, modes: []string{"core"}, want: internalserver.IPCTransportLocalHTTPV2},
		{name: "v2 unsupported remote mode", transport: internalserver.IPCTransportLocalHTTPV2, modes: []string{"kas"}, errorContains: "requires a local IPC deployment mode"},
		{name: "v2 missing Action descriptor", transport: internalserver.IPCTransportLocalHTTPV2, modes: []string{"all", "-policy"}, errorContains: actionsconnect.ActionServiceName},
		{name: "invalid defensive check", transport: "direct", modes: []string{"all"}, errorContains: "supported values"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{Mode: test.modes}
			cfg.Server.IPC.Transport = test.transport
			got, err := validateIPCTransport(cfg, ipcTestRegistry(t, test.modes))
			if test.errorContains != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, test.errorContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestSetupIPCSDKRoutesOnlyActionsToSelectedTransport(t *testing.T) {
	for _, transport := range []string{internalserver.IPCTransportConnectV1, internalserver.IPCTransportLocalHTTPV2} {
		t.Run(transport, func(t *testing.T) {
			otdf := newIPCTestServer(t)
			actionHandler := &ipcActionHandler{peers: make(chan string, 2)}
			actionPath, actionHTTPHandler := actionsconnect.NewActionServiceHandler(actionHandler, otdf.ConnectRPCInProcess.Interceptors...)
			otdf.ConnectRPCInProcess.Mux.Handle(actionPath, actionHTTPHandler)
			namespaceHandler := &ipcNamespaceHandler{peers: make(chan string, 2)}
			namespacePath, namespaceHTTPHandler := namespacesconnect.NewNamespaceServiceHandler(namespaceHandler, otdf.ConnectRPCInProcess.Interceptors...)
			otdf.ConnectRPCInProcess.Mux.Handle(namespacePath, namespaceHTTPHandler)

			cfg := &config.Config{Mode: []string{"all"}}
			cfg.Server.IPC.Transport = transport
			selected, err := validateIPCTransport(cfg, ipcTestRegistry(t, cfg.Mode))
			require.NoError(t, err)
			client, err := setupIPCSDK(cfg, nil, otdf, logger.CreateTestLogger(), nil, selected)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, client.Close()) })

			action, err := client.Actions.GetAction(t.Context(), &actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: ipcTestID}})
			require.NoError(t, err)
			assert.Equal(t, "routed", action.GetAction().GetName())
			actionPeer := <-actionHandler.peers

			namespace, err := client.Namespaces.GetNamespace(t.Context(), &namespaces.GetNamespaceRequest{Identifier: &namespaces.GetNamespaceRequest_NamespaceId{NamespaceId: ipcTestID}})
			require.NoError(t, err)
			assert.Equal(t, "v1", namespace.GetNamespace().GetName())
			namespacePeer := <-namespaceHandler.peers

			v1Endpoint := otdf.ConnectRPCInProcess.Conn().Endpoint
			assert.Equal(t, v1Endpoint, client.Conn().Endpoint, "SDK.Conn must retain the v1 core connection")
			assert.NotEqual(t, "local-http-ipc", namespacePeer, "non-Action SDK clients must retain v1")
			if transport == internalserver.IPCTransportLocalHTTPV2 {
				assert.Equal(t, "local-http-ipc", actionPeer)
				_, err = client.Actions.GetAction(t.Context(), &actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: ipcTestFailureID}})
				require.Error(t, err)
				assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
				assert.Equal(t, int64(2), actionHandler.calls.Load(), "a v2 failure after handler side effects must not be replayed through v1")
				assert.Equal(t, "local-http-ipc", <-actionHandler.peers)

				_, err = client.Namespaces.GetNamespace(t.Context(), &namespaces.GetNamespaceRequest{Identifier: &namespaces.GetNamespaceRequest_NamespaceId{NamespaceId: ipcTestID}})
				require.NoError(t, err, "a failed v2 call must leave the retained v1 connection usable")
			} else {
				assert.NotEqual(t, "local-http-ipc", actionPeer)
			}
		})
	}
}
