package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	publicKeyProcedure = "/kas.AccessService/PublicKey"
	legacyPublicKeyHTU = publicKeyProcedure
)

// fakeDPoPServer is a platform stand-in that advertises (or doesn't) RFC 9449
// support and records the htu and Authorization of each PublicKey call.
type fakeDPoPServer struct {
	wellKnown         map[string]any // nil: the RPC returns 404, like a non-platform origin
	wellKnownStatus   int            // overrides the well-known response status when set
	protectedResource bool           // serve RFC 9728 metadata
	nonce             string         // challenge the first PublicKey call with this nonce

	mu             sync.Mutex
	key            jwk.Key
	htus           []string
	authorizations []string
	discoveries    int
}

func (f *fakeDPoPServer) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownConfigurationProcedure, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.discoveries++
		status := f.wellKnownStatus
		f.mu.Unlock()
		assert.Empty(t, r.Header.Get("Authorization"), "discovery must not send credentials")
		assert.Empty(t, r.Header.Get("DPoP"), "discovery must not send a proof")
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		if f.wellKnown == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"configuration": f.wellKnown})
	})
	mux.HandleFunc(protectedResourceMetadataPath, func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"), "discovery must not send credentials")
		if !f.protectedResource {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":                          "https://" + r.Host,
			"dpop_signing_alg_values_supported": []string{"ES256"},
		})
	})
	mux.HandleFunc(publicKeyProcedure, func(w http.ResponseWriter, r *http.Request) {
		proof, ok := parseDPoPProof(t, r.Header.Get("DPoP"), f.key)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		htuClaim, _ := proof.Get("htu")
		htu, _ := htuClaim.(string)
		nonce, _ := proof.Get("nonce")
		f.mu.Lock()
		f.htus = append(f.htus, htu)
		f.authorizations = append(f.authorizations, r.Header.Get("Authorization"))
		f.mu.Unlock()
		if f.nonce != "" && nonce != f.nonce {
			w.Header().Set("DPoP-Nonce", f.nonce)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// callPublicKey makes count PublicKey RPCs to serverURL through transport.
func callPublicKey(t *testing.T, serverURL string, transport *DPoPTransport, count int) {
	t.Helper()
	client := kasconnect.NewAccessServiceClient(&http.Client{Transport: transport}, serverURL)
	for range count {
		_, err := client.PublicKey(t.Context(), connect.NewRequest(&kas.PublicKeyRequest{}))
		require.NoError(t, err)
	}
}

func newModeTransport(f *fakeDPoPServer, mode DPoPMode) *DPoPTransport {
	return &DPoPTransport{
		Base:        http.DefaultTransport,
		DPoPKey:     f.key,
		TokenSource: &mockTokenSource{token: "test-token"},
		Mode:        mode,
	}
}

func TestServerSupportsRFC9449(t *testing.T) {
	algs := []any{"ES256"}
	tests := []struct {
		name string
		cfg  map[string]any
		want bool
	}{
		{"dpop block says yes", map[string]any{"dpop": map[string]any{"rfc9449": true}}, true},
		{"dpop block overrides top-level key", map[string]any{"dpop": map[string]any{"rfc9449": false}, "dpop_signing_alg_values_supported": algs}, false},
		{"top-level key only (v0.18.0+)", map[string]any{"dpop_signing_alg_values_supported": algs}, true},
		{"empty alg list", map[string]any{"dpop_signing_alg_values_supported": []any{}}, false},
		{"no advertisement (step One)", map[string]any{"platform_issuer": "https://idp"}, false},
		{"nil config", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ServerSupportsRFC9449(tt.cfg))
		})
	}
}

func TestDPoPModeAuto_PicksStyleFromAdvertisement(t *testing.T) {
	block := map[string]any{"dpop": map[string]any{"rfc9449": true}}
	topLevel := map[string]any{"dpop_signing_alg_values_supported": []any{"ES256"}}
	stepOne := map[string]any{"platform_issuer": "https://idp"}
	tests := []struct {
		name              string
		wellKnown         map[string]any
		protectedResource bool
		wantRFC9449       bool
	}{
		{"well-known dpop block only", block, false, true},
		{"well-known top-level key only", topLevel, false, true},
		{"RFC 9728 only", stepOne, true, true},
		{"both", block, true, true},
		{"neither: step-One server", stepOne, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeDPoPServer{key: generateTestKey(t), wellKnown: tt.wellKnown, protectedResource: tt.protectedResource}
			server := httptest.NewServer(f.handler(t))
			defer server.Close()

			callPublicKey(t, server.URL, newModeTransport(f, DPoPModeAuto), 2)

			want := legacyPublicKeyHTU
			if tt.wantRFC9449 {
				want = server.URL + publicKeyProcedure
			}
			assert.Equal(t, []string{want, want}, f.htus)
			// Step-One servers accept the DPoP scheme, and strict_scheme servers require it.
			assert.Equal(t, []string{"DPoP test-token", "DPoP test-token"}, f.authorizations)
			assert.Equal(t, 1, f.discoveries, "discovery result should be cached per origin")
		})
	}
}

func TestDPoPModeAuto_DiscoveryFailureIsLegacyAndRetried(t *testing.T) {
	f := &fakeDPoPServer{
		key:             generateTestKey(t),
		wellKnown:       map[string]any{"dpop_signing_alg_values_supported": []any{"ES256"}},
		wellKnownStatus: http.StatusServiceUnavailable,
	}
	server := httptest.NewServer(f.handler(t))
	defer server.Close()
	transport := newModeTransport(f, DPoPModeAuto)

	callPublicKey(t, server.URL, transport, 1)
	assert.Equal(t, []string{legacyPublicKeyHTU}, f.htus, "failed discovery falls back to legacy")

	f.mu.Lock()
	f.wellKnownStatus = 0
	f.mu.Unlock()
	callPublicKey(t, server.URL, transport, 1)
	assert.Equal(t, server.URL+publicKeyProcedure, f.htus[1], "a failed discovery must not be cached")
	assert.Equal(t, 2, f.discoveries)
}

func TestDPoPMode_ExplicitModesSkipDiscovery(t *testing.T) {
	advertising := map[string]any{"dpop": map[string]any{"rfc9449": true}}
	tests := []struct {
		name      string
		mode      DPoPMode
		wellKnown map[string]any
		wantHTU   func(serverURL string) string
	}{
		{"legacy against an advertising server", DPoPModeLegacy, advertising, func(string) string { return legacyPublicKeyHTU }},
		{"rfc9449 against a step-One server", DPoPModeRFC9449, nil, func(u string) string { return u + publicKeyProcedure }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeDPoPServer{key: generateTestKey(t), wellKnown: tt.wellKnown}
			server := httptest.NewServer(f.handler(t))
			defer server.Close()

			callPublicKey(t, server.URL, newModeTransport(f, tt.mode), 1)

			assert.Equal(t, []string{tt.wantHTU(server.URL)}, f.htus)
			assert.Zero(t, f.discoveries)
		})
	}
}

func TestDPoPModeAuto_SeededOriginSkipsDiscovery(t *testing.T) {
	f := &fakeDPoPServer{key: generateTestKey(t)}
	server := httptest.NewServer(f.handler(t))
	defer server.Close()
	transport := newModeTransport(f, DPoPModeAuto)
	// The SDK seeds the platform origin from the well-known config it already fetched.
	transport.SetServerRFC9449Support(server.URL+"/some/base/path", true)

	callPublicKey(t, server.URL, transport, 1)

	assert.Equal(t, []string{server.URL + publicKeyProcedure}, f.htus)
	assert.Zero(t, f.discoveries)
}

func TestDPoPModeAuto_NonceRetryKeepsStyle(t *testing.T) {
	for _, tt := range []struct {
		name        string
		wellKnown   map[string]any
		wantRFC9449 bool
	}{
		{"rfc9449", map[string]any{"dpop_signing_alg_values_supported": []any{"ES256"}}, true},
		{"legacy", map[string]any{}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeDPoPServer{key: generateTestKey(t), wellKnown: tt.wellKnown, nonce: "server-nonce"}
			server := httptest.NewServer(f.handler(t))
			defer server.Close()

			callPublicKey(t, server.URL, newModeTransport(f, DPoPModeAuto), 1)

			want := legacyPublicKeyHTU
			if tt.wantRFC9449 {
				want = server.URL + publicKeyProcedure
			}
			assert.Equal(t, []string{want, want}, f.htus, "challenge and retry use the same htu form")
		})
	}
}

func TestLegacyHTU(t *testing.T) {
	connectReq := func(target string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, target, nil)
		req.Header.Set("Connect-Protocol-Version", "1")
		return req
	}
	grpcReq := httptest.NewRequest(http.MethodPost, "https://platform.example/kas.AccessService/Rewrap", nil)
	grpcReq.Header.Set("Content-Type", "application/grpc+proto")
	plainReq := httptest.NewRequest(http.MethodGet, "https://platform.example:443/kas/v2/kas_public_key?algorithm=rsa", nil)

	assert.Equal(t, "/kas.AccessService/Rewrap", legacyHTU(connectReq("https://platform.example/kas.AccessService/Rewrap")))
	assert.Equal(t, "/kas.AccessService/Rewrap", legacyHTU(connectReq("https://proxy.example/prefix/kas.AccessService/Rewrap")),
		"a reverse-proxy path prefix is not part of the procedure")
	assert.Equal(t, "/kas.AccessService/Rewrap", legacyHTU(grpcReq))
	assert.Equal(t, "https://platform.example/kas/v2/kas_public_key", legacyHTU(plainReq),
		"non-RPC requests were always checked against the full URI")
	assert.True(t, strings.HasPrefix(legacyHTU(connectReq("https://platform.example/healthz")), "https://"),
		"a single segment is not a procedure")
}
