package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/actions/actionsconnect"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/namespaces/namespacesconnect"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/fixtures"
	internalserver "github.com/opentdf/platform/service/internal/server"
	platformserver "github.com/opentdf/platform/service/pkg/server"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

const (
	ipcProbeProcedure  = "/test.ipc.ProbeService/Probe"
	ipcProbeActionID   = "e3e3df5f-02c8-4a41-88af-1c7436a43722"
	ipcProbeActionName = "custom_action_1"
	ipcProbeNamespace  = "8f1d8839-2851-4bf4-8bf4-5243dbfe517d"
	ipcProbeAudience   = "ipc-startup-probe"
)

type ipcProbeHandler interface {
	Probe(context.Context, *connect.Request[actions.GetActionRequest]) (*connect.Response[actions.GetActionResponse], error)
}

type ipcProbeService struct {
	client *sdk.SDK
}

func (s *ipcProbeService) Probe(ctx context.Context, req *connect.Request[actions.GetActionRequest]) (*connect.Response[actions.GetActionResponse], error) {
	action, err := s.client.Actions.GetAction(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	namespace, err := s.client.Namespaces.GetNamespace(ctx, &namespaces.GetNamespaceRequest{
		Identifier: &namespaces.GetNamespaceRequest_NamespaceId{NamespaceId: ipcProbeNamespace},
	})
	if err != nil {
		return nil, err
	}
	if namespace.GetNamespace().GetName() != "example.com" {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unexpected retained Namespace payload %q", namespace.GetNamespace().GetName()))
	}
	return connect.NewResponse(action), nil
}

func newIPCProbeRegistration() serviceregistry.IService {
	return &serviceregistry.Service[ipcProbeHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[ipcProbeHandler]{
			Namespace:   "ipcprobe",
			ServiceDesc: &grpc.ServiceDesc{ServiceName: "test.ipc.ProbeService"},
			RegisterFunc: func(params serviceregistry.RegistrationParams) (ipcProbeHandler, serviceregistry.HandlerServer) {
				return &ipcProbeService{client: params.SDK}, nil
			},
			ConnectRPCFunc: func(handler ipcProbeHandler, options ...connect.HandlerOption) (string, http.Handler) {
				return "/test.ipc.ProbeService/", connect.NewUnaryHandler(ipcProbeProcedure, handler.Probe, options...)
			},
		},
	}
}

type ipcProbeObservation struct {
	Procedure string `json:"procedure"`
	Peer      string `json:"peer"`
}

type ipcProbeRecorder struct {
	path string
	mu   sync.Mutex
}

func (r *ipcProbeRecorder) interceptor() connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			response, err := next(ctx, req)
			if req.Spec().Procedure == actionsconnect.ActionServiceGetActionProcedure ||
				req.Spec().Procedure == namespacesconnect.NamespaceServiceGetNamespaceProcedure {
				r.record(ipcProbeObservation{Procedure: req.Spec().Procedure, Peer: req.Peer().Addr})
			}
			return response, err
		}
	})
}

func (r *ipcProbeRecorder) record(observation ipcProbeObservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	file, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(observation); err != nil {
		panic(err)
	}
}

func TestStartupInternalActionProbeHelper(t *testing.T) {
	if os.Getenv("OPENTDF_IPC_PROBE_HELPER") != "1" {
		return
	}
	recorder := &ipcProbeRecorder{path: os.Getenv("OPENTDF_IPC_PROBE_OBSERVATIONS")}
	err := platformserver.Start(
		platformserver.WithWaitForShutdownSignal(),
		platformserver.WithConfigFile(os.Getenv("OPENTDF_IPC_PROBE_CONFIG")),
		platformserver.WithConfigKey("ipc-startup-probe"),
		platformserver.WithCoreServices(newIPCProbeRegistration()),
		platformserver.WithIPCInterceptors(recorder.interceptor()),
		platformserver.WithBuiltinAuthZPolicy("p, role:admin, *, *, allow\ng, opentdf-admin, role:admin"),
	)
	require.NoError(t, err)
}

type ipcProbeOIDC struct {
	server      *httptest.Server
	privateKey  *rsa.PrivateKey
	keyID       string
	jwksRequest atomic.Int64
}

func newIPCProbeOIDC(t *testing.T) *ipcProbeOIDC {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey, err := jwk.FromRaw(privateKey.PublicKey)
	require.NoError(t, err)
	const keyID = "ipc-startup-probe-key"
	require.NoError(t, publicKey.Set(jws.KeyIDKey, keyID))
	require.NoError(t, publicKey.Set(jwk.AlgorithmKey, jwa.RS256))
	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(publicKey))

	fixture := &ipcProbeOIDC{privateKey: privateKey, keyID: keyID}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   fixture.server.URL,
				"jwks_uri": fixture.server.URL + "/jwks",
			})
		case "/jwks":
			fixture.jwksRequest.Add(1)
			_ = json.NewEncoder(w).Encode(keySet)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *ipcProbeOIDC) token(t *testing.T) string {
	t.Helper()
	now := time.Now()
	token := jwt.New()
	require.NoError(t, token.Set(jwt.SubjectKey, "ipc-probe-user"))
	require.NoError(t, token.Set(jwt.IssuedAtKey, now))
	require.NoError(t, token.Set(jwt.ExpirationKey, now.Add(time.Hour)))
	require.NoError(t, token.Set(jwt.IssuerKey, f.server.URL))
	require.NoError(t, token.Set(jwt.AudienceKey, ipcProbeAudience))
	require.NoError(t, token.Set("azp", "ipc-probe-client"))
	require.NoError(t, token.Set("realm_access", map[string][]string{"roles": {"opentdf-admin"}}))
	key, err := jwk.FromRaw(f.privateKey)
	require.NoError(t, err)
	require.NoError(t, key.Set(jws.KeyIDKey, f.keyID))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.RS256))
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
	require.NoError(t, err)
	return string(signed)
}

func ipcProbePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	require.NoError(t, listener.Close())
	return tcpAddr.Port
}

func writeIPCProbeConfig(t *testing.T, transport, schema string, port int, oidcURL string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opentdf.yaml")
	contents := fmt.Sprintf(`mode: core
logger:
  level: info
  type: json
  output: stderr
db:
  host: %s
  port: %d
  user: %s
  password: %s
  database: %s
  schema: %s
  sslmode: disable
  runMigrations: true
server:
  host: 127.0.0.1
  port: %d
  tls:
    enabled: false
  ipc:
    transport: %s
  auth:
    enabled: true
    issuer: %s
    audience: %s
    dpop:
      enforce: false
sdk_config:
  entityresolution:
    endpoint: http://127.0.0.1:1
    plaintext: true
`, Config.DB.Host, Config.DB.Port, Config.DB.User, Config.DB.Password, Config.DB.Database, schema, port, transport, oidcURL, ipcProbeAudience)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func waitForIPCProbe(t *testing.T, client *connect.Client[actions.GetActionRequest, actions.GetActionResponse]) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, err := client.CallUnary(t.Context(), connect.NewRequest(&actions.GetActionRequest{
			Identifier: &actions.GetActionRequest_Id{Id: ipcProbeActionID},
		}))
		return connect.CodeOf(err) == connect.CodeUnauthenticated
	}, 20*time.Second, 25*time.Millisecond, "probe must become externally reachable and reject an unauthenticated request")
}

func readIPCProbeObservations(t *testing.T, path string) []ipcProbeObservation {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	var observations []ipcProbeObservation
	decoder := json.NewDecoder(file)
	for {
		var observation ipcProbeObservation
		err := decoder.Decode(&observation)
		if errors.Is(err, io.EOF) {
			return observations
		}
		require.NoError(t, err)
		observations = append(observations, observation)
	}
}

func TestAuthenticatedStartupInternalActionProbe(t *testing.T) {
	oidc := newIPCProbeOIDC(t)
	for _, transport := range []string{internalserver.IPCTransportConnectV1, internalserver.IPCTransportLocalHTTPV2} {
		t.Run(transport, func(t *testing.T) {
			schemaBase := "test_ipc_startup_" + strconv.FormatInt(time.Now().UnixNano(), 36)
			fixtureConfig := *Config
			fixtureConfig.DB.Schema = schemaBase + "_policy"
			database := fixtures.NewDBInterface(t.Context(), fixtureConfig)
			fixture := fixtures.NewFixture(database)
			fixture.Provision(t.Context())
			t.Cleanup(func() {
				fixture.TearDown(context.Background())
				database.Client.Close()
			})

			port := ipcProbePort(t)
			configPath := writeIPCProbeConfig(t, transport, schemaBase, port, oidc.server.URL)
			observationPath := filepath.Join(t.TempDir(), "ipc-observations.jsonl")
			logPath := filepath.Join(t.TempDir(), "platform.log")
			logFile, err := os.Create(logPath)
			require.NoError(t, err)
			cmd := exec.Command(os.Args[0], "-test.run=^TestStartupInternalActionProbeHelper$", "-test.v")
			cmd.Env = append(os.Environ(),
				"OPENTDF_IPC_PROBE_HELPER=1",
				"OPENTDF_IPC_PROBE_CONFIG="+configPath,
				"OPENTDF_IPC_PROBE_OBSERVATIONS="+observationPath,
			)
			cmd.Stdout = logFile
			cmd.Stderr = logFile
			require.NoError(t, cmd.Start(), "platform log: %s", logPath)
			stopped := false
			t.Cleanup(func() {
				if !stopped && cmd.Process != nil {
					_ = cmd.Process.Signal(os.Interrupt)
					_ = cmd.Wait()
				}
				_ = logFile.Close()
			})

			probeClient := connect.NewClient[actions.GetActionRequest, actions.GetActionResponse](
				http.DefaultClient,
				fmt.Sprintf("http://127.0.0.1:%d%s", port, ipcProbeProcedure),
			)
			waitForIPCProbe(t, probeClient)

			forged := connect.NewRequest(&actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: ipcProbeActionID}})
			forged.Header().Set("Authorization", "Bearer not-a-signed-token")
			_, err = probeClient.CallUnary(t.Context(), forged)
			require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

			request := connect.NewRequest(&actions.GetActionRequest{Identifier: &actions.GetActionRequest_Id{Id: ipcProbeActionID}})
			request.Header().Set("Authorization", "Bearer "+oidc.token(t))
			response, err := probeClient.CallUnary(t.Context(), request)
			require.NoError(t, err, "platform log: %s", logPath)
			require.NotNil(t, response.Msg.GetAction())
			assert.Equal(t, ipcProbeActionID, response.Msg.GetAction().GetId())
			assert.Equal(t, ipcProbeActionName, response.Msg.GetAction().GetName())
			require.Positive(t, oidc.jwksRequest.Load(), "the public token must be verified against the real JWKS fixture")

			require.NoError(t, cmd.Process.Signal(os.Interrupt))
			waitErr := cmd.Wait()
			stopped = true
			require.NoError(t, waitErr, "platform log: %s", logPath)
			require.NoError(t, logFile.Close())

			observations := readIPCProbeObservations(t, observationPath)
			var actionObservations, namespaceObservations []ipcProbeObservation
			for _, observation := range observations {
				switch observation.Procedure {
				case actionsconnect.ActionServiceGetActionProcedure:
					actionObservations = append(actionObservations, observation)
				case namespacesconnect.NamespaceServiceGetNamespaceProcedure:
					namespaceObservations = append(namespaceObservations, observation)
				}
			}
			require.Len(t, actionObservations, 1, "the authenticated probe must dispatch Action exactly once")
			require.Len(t, namespaceObservations, 1, "the retained Namespace binding must dispatch exactly once")
			assert.NotEqual(t, "local-http-ipc", namespaceObservations[0].Peer)
			if transport == internalserver.IPCTransportLocalHTTPV2 {
				assert.Equal(t, "local-http-ipc", actionObservations[0].Peer)
			} else {
				assert.NotEqual(t, "local-http-ipc", actionObservations[0].Peer)
			}
		})
	}
}
