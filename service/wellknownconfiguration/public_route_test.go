package wellknownconfiguration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	wellknown "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration/wellknownconfigurationconnect"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration/wellknownconfigurationconnectv2"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestIDP serves the OIDC discovery document and an empty JWKS, which is
// all the authenticator needs to start.
func newTestIDP(t *testing.T) *httptest.Server {
	t.Helper()
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, idp.URL, idp.URL+"/jwks")
		case "/jwks":
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)
	return idp
}

// Clients choose a DPoP proof format from the well-known configuration, so it
// must be readable without credentials even when DPoP is enforced and nonces
// are required (DSPX-5635). This wires the real handlers behind the
// authentication layers the platform server uses.
func TestWellKnownConfiguration_PublicWithoutCredentials(t *testing.T) {
	rwMutex.Lock()
	wellKnownConfiguration = make(map[string]any)
	rwMutex.Unlock()
	t.Cleanup(func() {
		rwMutex.Lock()
		wellKnownConfiguration = make(map[string]any)
		rwMutex.Unlock()
	})

	idp := newTestIDP(t)
	log := logger.CreateTestLogger()
	authn, err := auth.NewAuthenticator(
		t.Context(),
		auth.Config{AuthNConfig: auth.AuthNConfig{
			Issuer:    idp.URL,
			Audience:  "test",
			DPoPSkew:  time.Hour,
			TokenSkew: time.Minute,
			DPoP: auth.DPoPConfig{
				Enforce:         true,
				RequireNonce:    true,
				NonceExpiration: 5 * time.Minute,
				HTU: auth.DPoPHTUConfig{
					Strict:  true,
					Origins: []string{"https://platform.example"},
				},
			},
		}},
		log,
		RegisterConfiguration,
	)
	require.NoError(t, err)

	wk, registerHTTP := NewRegistration().RegisterFunc(serviceregistry.RegistrationParams{Logger: log})

	t.Run("HTTP GET", func(t *testing.T) {
		mux := http.NewServeMux()
		require.NoError(t, registerHTTP(t.Context(), mux))
		server := httptest.NewServer(authn.MuxHandler(mux))
		t.Cleanup(server.Close)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/.well-known/opentdf-configuration", nil)
		require.NoError(t, err)
		resp, err := server.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Contains(t, body, "dpop")
	})

	t.Run("Connect RPC", func(t *testing.T) {
		rpc := connectv2.NewServer(authn.ConnectAuthNInterceptorV2(), authn.ConnectAuthZInterceptorV2())
		wellknownconfigurationconnectv2.RegisterWellKnownServiceHandler(rpc, wk)
		mux := http.NewServeMux()
		connecthttp.Mount(mux, rpc)
		server := httptest.NewServer(mux)
		t.Cleanup(server.Close)

		client := wellknownconfigurationconnect.NewWellKnownServiceClient(server.Client(), server.URL)
		resp, err := client.GetWellKnownConfiguration(t.Context(), connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{}))
		require.NoError(t, err)
		assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "dpop")
	})
}
