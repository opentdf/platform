package sdk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type staticTokenSource struct{}

func (staticTokenSource) AccessToken(context.Context, *http.Client) (auth.AccessToken, error) {
	return "test-token", nil
}

func (staticTokenSource) MakeToken(func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return nil, nil
}

// dpopPlatform records the htu of each PublicKey call and counts discovery
// requests. It never advertises RFC 9449 itself, so any compliant proof it sees
// comes from the SDK's own configuration.
type dpopPlatform struct {
	mu          sync.Mutex
	htus        []string
	discoveries int
}

func newDPoPPlatform(t *testing.T, key jwk.Key) (*dpopPlatform, *httptest.Server) {
	t.Helper()
	p := &dpopPlatform{}
	mux := http.NewServeMux()
	path, health := grpchealth.NewHandler(grpchealth.NewStaticChecker())
	mux.Handle(path, health)
	mux.HandleFunc("/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.discoveries++
		p.mu.Unlock()
		http.NotFound(w, r)
	})
	mux.HandleFunc("/kas.AccessService/PublicKey", func(w http.ResponseWriter, r *http.Request) {
		proof, err := jwt.Parse([]byte(r.Header.Get("DPoP")), jwt.WithKey(key.Algorithm(), key))
		if !assert.NoError(t, err) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		htuClaim, _ := proof.Get("htu")
		htu, _ := htuClaim.(string)
		p.mu.Lock()
		p.htus = append(p.htus, htu)
		p.mu.Unlock()
		w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	})
	return p, httptest.NewServer(mux)
}

func TestNew_DPoPModeFromPlatformConfiguration(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.ES256))
	pub, err := key.PublicKey()
	require.NoError(t, err)

	idp := map[string]any{"issuer": "https://idp.example", "token_endpoint": "https://idp.example/token"}
	tests := []struct {
		name            string
		config          PlatformConfiguration
		opts            []Option
		wantRFC9449     bool
		wantDiscoveries int
	}{
		{
			name:        "advertised in well-known: seeded, no discovery",
			config:      PlatformConfiguration{"idp": idp, "dpop_signing_alg_values_supported": []any{"ES256"}},
			wantRFC9449: true,
		},
		{
			name:            "not advertised: discover, then legacy",
			config:          PlatformConfiguration{"idp": idp},
			wantDiscoveries: 1,
		},
		{
			name:        "explicit rfc9449 overrides a step-One configuration",
			config:      PlatformConfiguration{"idp": idp},
			opts:        []Option{WithDPoPMode(auth.DPoPModeRFC9449)},
			wantRFC9449: true,
		},
		{
			name:   "explicit legacy overrides an advertising configuration",
			config: PlatformConfiguration{"idp": idp, "dpop_signing_alg_values_supported": []any{"ES256"}},
			opts:   []Option{WithDPoPMode(auth.DPoPModeLegacy)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			platform, server := newDPoPPlatform(t, pub)
			defer server.Close()

			opts := append([]Option{
				WithPlatformConfiguration(tt.config),
				withCustomAccessTokenSource(staticTokenSource{}),
				WithDPoPJWK(key),
			}, tt.opts...)
			s, err := New(server.URL, opts...)
			require.NoError(t, err)
			defer s.Close()

			conn := s.Conn()
			client := kasconnect.NewAccessServiceClient(conn.Client, conn.Endpoint, conn.Options...)
			_, err = client.PublicKey(t.Context(), connect.NewRequest(&kas.PublicKeyRequest{}))
			require.NoError(t, err)

			want := "/kas.AccessService/PublicKey"
			if tt.wantRFC9449 {
				want = server.URL + want
			}
			assert.Equal(t, []string{want}, platform.htus)
			assert.Equal(t, tt.wantDiscoveries, platform.discoveries)
		})
	}
}
