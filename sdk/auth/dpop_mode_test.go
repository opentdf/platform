package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

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
	wellKnownRaw      string         // with wellKnownStatus, the raw response body
	wellKnownBlock    chan struct{}  // when set, the well-known RPC waits for it to close
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
		if f.wellKnownBlock != nil {
			<-f.wellKnownBlock
		}
		if status != 0 {
			if status/100 == 3 {
				http.Redirect(w, r, "/advertise", status)
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(f.wellKnownRaw))
			return
		}
		if f.wellKnown == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"configuration": f.wellKnown})
	})
	mux.HandleFunc("/advertise", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"configuration": map[string]any{"dpop_signing_alg_values_supported": []string{"ES256"}}})
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

// inProcessOrigin is the origin of requests served by inProcessTransport.
const inProcessOrigin = "http://platform.test"

// inProcessTransport serves requests with h without a network, so tests can run
// in a synctest bubble: network I/O, even over loopback, never counts as
// durably blocked there. Like a real transport it gives up when the request's
// context ends.
func inProcessTransport(h http.Handler) http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.ServeHTTP(rec, req)
		}()
		select {
		case <-done:
			return rec.Result(), nil
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	})
}

// newInProcessAutoTransport is an auto-mode transport for f served in-process.
func newInProcessAutoTransport(t *testing.T, f *fakeDPoPServer) *DPoPTransport {
	transport := newModeTransport(f, DPoPModeAuto)
	transport.Base = inProcessTransport(f.handler(t))
	return transport
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
		{"dpop block without rfc9449 defers to top-level key", map[string]any{"dpop": map[string]any{"nonce_required": true}, "dpop_signing_alg_values_supported": algs}, true},
		{"non-boolean rfc9449 is ignored", map[string]any{"dpop": map[string]any{"rfc9449": "true"}}, false},
		{"alg list built in Go", map[string]any{"dpop_signing_alg_values_supported": []string{"ES256"}}, true},
		{"top-level key only (v0.18.0+)", map[string]any{"dpop_signing_alg_values_supported": algs}, true},
		{"empty alg list", map[string]any{"dpop_signing_alg_values_supported": []any{}}, false},
		{"no advertisement (legacy server)", map[string]any{"platform_issuer": "https://idp"}, false},
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
	legacyServer := map[string]any{"platform_issuer": "https://idp"}
	tests := []struct {
		name              string
		wellKnown         map[string]any
		protectedResource bool
		wantRFC9449       bool
	}{
		{"well-known dpop block only", block, false, true},
		{"well-known top-level key only", topLevel, false, true},
		{"RFC 9728 only", legacyServer, true, true},
		{"both", block, true, true},
		{"neither: legacy server", legacyServer, false, false},
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
			assert.Equal(t, []string{"DPoP test-token", "DPoP test-token"}, f.authorizations)
			assert.Equal(t, 1, f.discoveries, "discovery result should be cached per origin")
		})
	}
}

func TestDPoPModeAuto_DiscoveryFailureIsLegacyAndRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeDPoPServer{
			key:             generateTestKey(t),
			wellKnown:       map[string]any{"dpop_signing_alg_values_supported": []any{"ES256"}},
			wellKnownStatus: http.StatusServiceUnavailable,
		}
		transport := newInProcessAutoTransport(t, f)

		callPublicKey(t, inProcessOrigin, transport, 2)
		assert.Equal(t, []string{legacyPublicKeyHTU, legacyPublicKeyHTU}, f.htus, "failed discovery falls back to legacy")
		assert.Equal(t, 1, f.discoveries, "the fallback is reused until the retry interval passes")

		f.mu.Lock()
		f.wellKnownStatus = 0
		f.mu.Unlock()
		time.Sleep(dpopDiscoveryRetryInterval)
		callPublicKey(t, inProcessOrigin, transport, 1)
		assert.Equal(t, inProcessOrigin+publicKeyProcedure, f.htus[2], "a failed discovery must not be cached for good")
		assert.Equal(t, 2, f.discoveries)
	})
}

func TestDPoPModeAuto_DiscoveryTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeDPoPServer{key: generateTestKey(t), wellKnownBlock: make(chan struct{})}
		defer close(f.wellKnownBlock)
		transport := newInProcessAutoTransport(t, f)

		start := time.Now()
		callPublicKey(t, inProcessOrigin, transport, 1)

		assert.Equal(t, dpopDiscoveryTimeout, time.Since(start), "a hung server delays the request by the discovery timeout")
		assert.Equal(t, []string{legacyPublicKeyHTU}, f.htus)
	})
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
		{"rfc9449 against a legacy server", DPoPModeRFC9449, nil, func(u string) string { return u + publicKeyProcedure }},
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
	require.NoError(t, transport.SetServerRFC9449Support(server.URL+"/some/base/path", true))

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

func TestDPoPModeAuto_DiscoveryAnswers(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		body           string
		wantConclusive bool
	}{
		{"404: no well-known endpoint", http.StatusNotFound, "", true},
		{"405", http.StatusMethodNotAllowed, "", true},
		{"501", http.StatusNotImplemented, "", true},
		{"200 catch-all page", http.StatusOK, "<html>login</html>", true},
		{"200 truncated document", http.StatusOK, `{"configuration": {`, false},
		{"401 from an auth gateway", http.StatusUnauthorized, "", false},
		{"403", http.StatusForbidden, "", false},
		{"429", http.StatusTooManyRequests, "", false},
		{"503", http.StatusServiceUnavailable, "", false},
		{"redirect is not followed", http.StatusFound, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := &fakeDPoPServer{key: generateTestKey(t), wellKnownStatus: tt.status, wellKnownRaw: tt.body}
				transport := newInProcessAutoTransport(t, f)

				callPublicKey(t, inProcessOrigin, transport, 1)
				time.Sleep(dpopDiscoveryRetryInterval)
				callPublicKey(t, inProcessOrigin, transport, 1)

				assert.Equal(t, []string{legacyPublicKeyHTU, legacyPublicKeyHTU}, f.htus)
				wantDiscoveries := 2
				if tt.wantConclusive {
					wantDiscoveries = 1
				}
				assert.Equal(t, wantDiscoveries, f.discoveries)
			})
		})
	}
}

func TestDPoPModeAuto_TokenRequestsSkipDiscovery(t *testing.T) {
	for _, mode := range []DPoPMode{DPoPModeLegacy, DPoPModeAuto} {
		t.Run(mode.String(), func(t *testing.T) {
			key := generateTestKey(t)
			var htu string
			idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/token", r.URL.Path, "the IdP must see no discovery requests")
				if proof, ok := parseDPoPProof(t, r.Header.Get("DPoP"), key); ok {
					claim, _ := proof.Get("htu")
					htu, _ = claim.(string)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer idp.Close()
			transport := &DPoPTransport{Base: http.DefaultTransport, DPoPKey: key, TokenEndpoint: idp.URL + "/token", Mode: mode}

			resp, err := (&http.Client{Transport: transport}).Post(idp.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader("grant_type=client_credentials"))
			require.NoError(t, err)
			resp.Body.Close()

			assert.Equal(t, idp.URL+"/token", htu)
		})
	}
}

func TestDPoPModeAuto_OriginsCachedSeparately(t *testing.T) {
	key := generateTestKey(t)
	modern := &fakeDPoPServer{key: key, wellKnown: map[string]any{"dpop_signing_alg_values_supported": []any{"ES256"}}}
	legacy := &fakeDPoPServer{key: key}
	modernServer := httptest.NewServer(modern.handler(t))
	defer modernServer.Close()
	legacyServer := httptest.NewServer(legacy.handler(t))
	defer legacyServer.Close()
	transport := newModeTransport(modern, DPoPModeAuto)

	callPublicKey(t, modernServer.URL, transport, 1)
	callPublicKey(t, legacyServer.URL, transport, 1)
	callPublicKey(t, modernServer.URL, transport, 1)

	assert.Equal(t, []string{modernServer.URL + publicKeyProcedure, modernServer.URL + publicKeyProcedure}, modern.htus)
	assert.Equal(t, []string{legacyPublicKeyHTU}, legacy.htus)
	assert.Equal(t, 1, modern.discoveries)
	assert.Equal(t, 1, legacy.discoveries)
}

func TestDPoPModeAuto_ConcurrentFirstRequestsShareDiscovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeDPoPServer{
			key:            generateTestKey(t),
			wellKnown:      map[string]any{"dpop_signing_alg_values_supported": []any{"ES256"}},
			wellKnownBlock: make(chan struct{}),
		}
		transport := newInProcessAutoTransport(t, f)

		const callers = 8
		var wg sync.WaitGroup
		for range callers {
			wg.Go(func() { callPublicKey(t, inProcessOrigin, transport, 1) })
		}
		synctest.Wait() // every caller is waiting on the one discovery
		assert.Equal(t, 1, f.discoveries)
		close(f.wellKnownBlock)
		wg.Wait()

		assert.Equal(t, 1, f.discoveries)
		assert.Len(t, f.htus, callers)
		for _, htu := range f.htus {
			assert.Equal(t, inProcessOrigin+publicKeyProcedure, htu)
		}
	})
}

func TestDPoPModeAuto_CallerCancellationFailsRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeDPoPServer{key: generateTestKey(t), wellKnownBlock: make(chan struct{})}
		defer close(f.wellKnownBlock)
		transport := newInProcessAutoTransport(t, f)

		ctx, cancel := context.WithCancel(t.Context())
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, inProcessOrigin+publicKeyProcedure, strings.NewReader("{}"))
		require.NoError(t, err)
		req.Header.Set("Connect-Protocol-Version", "1")
		errs := make(chan error)
		go func() {
			_, err := transport.RoundTrip(req)
			errs <- err
		}()
		synctest.Wait() // the request is waiting on discovery
		require.Equal(t, 1, f.discoveries)
		cancel()

		require.ErrorIs(t, <-errs, context.Canceled)
		assert.Empty(t, f.htus, "a canceled request must not be sent")
	})
}

// recordingHandler keeps every record it handles.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler            { return h }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func TestDPoPModeAuto_DiscoveryLogging(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		injected := &recordingHandler{}
		global := &recordingHandler{}
		previous := slog.Default()
		slog.SetDefault(slog.New(global))
		defer slog.SetDefault(previous)

		quiet := &fakeDPoPServer{key: generateTestKey(t)}
		callPublicKey(t, inProcessOrigin, newInProcessAutoTransport(t, quiet), 1)
		assert.Empty(t, global.records, "without a logger the transport must not log, even to slog.Default")

		f := &fakeDPoPServer{key: generateTestKey(t), wellKnownStatus: http.StatusServiceUnavailable}
		transport := newInProcessAutoTransport(t, f)
		transport.Logger = slog.New(injected)
		callPublicKey(t, inProcessOrigin, transport, 1)

		assert.Empty(t, global.records)
		require.Len(t, injected.records, 1)
		record := injected.records[0]
		assert.Equal(t, slog.LevelDebug, record.Level)
		attrs := map[string]slog.Value{}
		record.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value
			return true
		})
		assert.Equal(t, inProcessOrigin, attrs["origin"].String())
		assert.False(t, attrs["conclusive"].Bool())
	})
}

func TestSetServerRFC9449Support_RejectsURLWithoutScheme(t *testing.T) {
	transport := &DPoPTransport{}
	for _, serverURL := range []string{"platform.example.com", "platform.example.com:8443", "/path", "://bad"} {
		require.Error(t, transport.SetServerRFC9449Support(serverURL, true), serverURL)
	}
	require.NoError(t, transport.SetServerRFC9449Support("https://platform.example.com:443/base", true))
}

func TestDPoPMode_UnknownModeSignsRFC9449(t *testing.T) {
	f := &fakeDPoPServer{key: generateTestKey(t)}
	server := httptest.NewServer(f.handler(t))
	defer server.Close()

	callPublicKey(t, server.URL, newModeTransport(f, DPoPMode(99)), 1)

	assert.Equal(t, []string{server.URL + publicKeyProcedure}, f.htus)
	assert.Zero(t, f.discoveries)
}
