package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/actions/actionsconnect"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/namespaces/namespacesconnect"
	"github.com/opentdf/platform/sdk"
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

func TestLogIPCBindingInventoryReportsRemoteERSInCoreMode(t *testing.T) {
	var output bytes.Buffer
	log := &logger.Logger{Logger: slog.New(slog.NewJSONHandler(&output, nil))}
	cfg := &config.Config{Mode: []string{serviceregistry.ModeCore.String()}}

	remoteERS := usesRemoteERSBinding(cfg)
	require.True(t, remoteERS)
	logIPCBindingInventory(log, internalserver.IPCTransportLocalHTTPV2, true, remoteERS)

	var record map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	assert.Equal(t, internalserver.IPCTransportLocalHTTPV2, record["sdk_actions_binding"])
	assert.Equal(t, internalserver.IPCTransportConnectV1, record["sdk_conn_binding"])
	assert.Equal(t, "remote-connect", record["sdk_entity_resolution_binding"])
	assert.Equal(t, "connect-v1-or-remote", record["other_sdk_bindings"])
}

func TestSetupIPCSDKRetainsRemoteERSInCoreMode(t *testing.T) {
	remoteRequests := make(chan string, 1)
	remoteERS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		remoteRequests <- req.URL.Path
		http.Error(w, "remote ERS fixture", http.StatusServiceUnavailable)
	}))
	t.Cleanup(remoteERS.Close)

	otdf := newIPCTestServer(t)
	actionHandler := &ipcActionHandler{peers: make(chan string, 1)}
	actionPath, actionHTTPHandler := actionsconnect.NewActionServiceHandler(actionHandler, otdf.ConnectRPCInProcess.Interceptors...)
	otdf.ConnectRPCInProcess.Mux.Handle(actionPath, actionHTTPHandler)
	namespaceHandler := &ipcNamespaceHandler{peers: make(chan string, 1)}
	namespacePath, namespaceHTTPHandler := namespacesconnect.NewNamespaceServiceHandler(namespaceHandler, otdf.ConnectRPCInProcess.Interceptors...)
	otdf.ConnectRPCInProcess.Mux.Handle(namespacePath, namespaceHTTPHandler)

	cfg := &config.Config{Mode: []string{serviceregistry.ModeCore.String()}}
	cfg.Server.IPC.Transport = internalserver.IPCTransportLocalHTTPV2
	cfg.SDKConfig.EntityResolutionConnection.Endpoint = remoteERS.URL
	cfg.SDKConfig.EntityResolutionConnection.Plaintext = true
	selected, err := validateIPCTransport(cfg, ipcTestRegistry(t, cfg.Mode))
	require.NoError(t, err)
	client, err := setupIPCSDK(cfg, nil, otdf, logger.CreateTestLogger(), nil, selected)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	action, err := client.Actions.GetAction(t.Context(), &actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: ipcTestID}})
	require.NoError(t, err)
	assert.Equal(t, "routed", action.GetAction().GetName())
	assert.Equal(t, "local-http-ipc", <-actionHandler.peers)

	namespace, err := client.Namespaces.GetNamespace(t.Context(), &namespaces.GetNamespaceRequest{Identifier: &namespaces.GetNamespaceRequest_NamespaceId{NamespaceId: ipcTestID}})
	require.NoError(t, err)
	assert.Equal(t, "v1", namespace.GetNamespace().GetName())
	assert.NotEqual(t, "local-http-ipc", <-namespaceHandler.peers)

	_, err = client.EntityResoution.ResolveEntities(t.Context(), &entityresolution.ResolveEntitiesRequest{})
	require.Error(t, err)
	assert.Equal(t, "/entityresolution.EntityResolutionService/ResolveEntities", <-remoteRequests)
	assert.Equal(t, otdf.ConnectRPCInProcess.Conn().Endpoint, client.Conn().Endpoint)
}

func TestIPCTransportSelectionRemainsStartupOnlyAcrossConfigReload(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "ipc-reload.yaml")
	writeConfig := func(transport string) {
		require.NoError(t, os.WriteFile(configPath, []byte("mode: all\nserver:\n  ipc:\n    transport: "+transport+"\n"), 0o600))
	}
	writeConfig(internalserver.IPCTransportLocalHTTPV2)
	fileLoader, err := config.NewConfigFileLoader("ipc-reload", configPath)
	require.NoError(t, err)
	defaultLoader, err := config.NewDefaultSettingsLoader()
	require.NoError(t, err)
	cfg, err := config.Load(t.Context(), fileLoader, defaultLoader)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cfg.Close(t.Context())) })

	otdf := newIPCTestServer(t)
	actionHandler := &ipcActionHandler{peers: make(chan string, 2)}
	actionPath, actionHTTPHandler := actionsconnect.NewActionServiceHandler(actionHandler, otdf.ConnectRPCInProcess.Interceptors...)
	otdf.ConnectRPCInProcess.Mux.Handle(actionPath, actionHTTPHandler)
	selected, err := validateIPCTransport(cfg, ipcTestRegistry(t, cfg.Mode))
	require.NoError(t, err)
	client, err := setupIPCSDK(cfg, nil, otdf, logger.CreateTestLogger(), nil, selected)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	writeConfig(internalserver.IPCTransportConnectV1)
	require.NoError(t, cfg.Reload(t.Context()))
	require.Equal(t, internalserver.IPCTransportConnectV1, cfg.Server.IPC.Transport)

	response, err := client.Actions.GetAction(t.Context(), &actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: ipcTestID}})
	require.NoError(t, err)
	assert.Equal(t, "routed", response.GetAction().GetName())
	assert.Equal(t, "local-http-ipc", <-actionHandler.peers, "reload must not dynamically rebind a startup-selected SDK client")
}

func TestStartLaterFailureRunsDeferredIPCResourceCleanup(t *testing.T) {
	if os.Getenv("OPENTDF_IPC_START_FAILURE_HELPER") == "1" {
		injected := errors.New("injected failure after SDK and server construction")
		var capturedClient *sdk.SDK
		err := Start(
			WithConfigFile(os.Getenv("OPENTDF_IPC_START_FAILURE_CONFIG")),
			WithConfigKey("ipc-start-failure"),
			WithConfigLoaderOrder([]string{config.LoaderNameFile, config.LoaderNameDefaultSettings}),
			WithExternalInterceptorFactories(InterceptorFactory{
				Name: "capture-and-fail",
				Factory: func(params InterceptorParams) (connect.Interceptor, error) {
					capturedClient = params.SDK
					return nil, injected
				},
			}),
		)
		require.ErrorIs(t, err, injected)
		require.NotNil(t, capturedClient)

		_, actionErr := capturedClient.Actions.GetAction(t.Context(), &actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: ipcTestID}})
		require.Error(t, actionErr)
		require.ErrorContains(t, actionErr, "local HTTP transport is closed")
		_, namespaceErr := capturedClient.Namespaces.GetNamespace(t.Context(), &namespaces.GetNamespaceRequest{
			Identifier: &namespaces.GetNamespaceRequest_NamespaceId{NamespaceId: ipcTestID},
		})
		require.Error(t, namespaceErr, "the retained v1 server must be closed by Start's deferred cleanup")
		return
	}

	configPath := filepath.Join(t.TempDir(), "ipc-start-failure.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`mode: all
logger:
  level: info
  output: stderr
  type: json
server:
  port: 0
  auth:
    enabled: false
  ipc:
    transport: local-http-v2
`), 0o600))
	cmd := exec.Command(os.Args[0], "-test.run=^TestStartLaterFailureRunsDeferredIPCResourceCleanup$", "-test.v")
	cmd.Env = append(os.Environ(),
		"OPENTDF_IPC_START_FAILURE_HELPER=1",
		"OPENTDF_IPC_START_FAILURE_CONFIG="+configPath,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "helper output:\n%s", output)
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
