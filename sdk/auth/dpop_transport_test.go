package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
)

// mockTokenSource implements AccessTokenSource for testing
type mockTokenSource struct {
	token string
	err   error
}

func (m *mockTokenSource) AccessToken(_ context.Context, _ *http.Client) (AccessToken, error) {
	if m.err != nil {
		return "", m.err
	}
	return AccessToken(m.token), nil
}

func (m *mockTokenSource) MakeToken(_ func(jwk.Key) ([]byte, error)) ([]byte, error) {
	// Not used in transport tests
	return nil, nil
}

func generateTestKey(t *testing.T) jwk.Key {
	t.Helper()
	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	key, err := jwk.FromRaw(rawKey)
	if err != nil {
		t.Fatalf("failed to create JWK: %v", err)
	}

	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("failed to set algorithm: %v", err)
	}

	return key
}

func parseDPoPProof(t *testing.T, proofStr string, key jwk.Key) jwt.Token {
	t.Helper()

	token, err := jwt.Parse([]byte(proofStr), jwt.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatalf("failed to parse DPoP proof: %v", err)
	}

	return token
}

func TestDPoPTransport_AddsProofToRequests(t *testing.T) {
	key := generateTestKey(t)
	ts := &mockTokenSource{token: "test-access-token"}

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		// Verify DPoP header exists
		dpopHeader := r.Header.Get("DPoP")
		if dpopHeader == "" {
			t.Error("DPoP header not present")
			return
		}

		// Verify Authorization header
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "DPoP ") {
			t.Errorf("Authorization header = %q, want prefix 'DPoP '", authHeader)
		}

		// Parse and verify the proof
		publicKey, err := key.PublicKey()
		if err != nil {
			t.Fatalf("failed to get public key: %v", err)
		}

		token := parseDPoPProof(t, dpopHeader, publicKey)

		// Check htm claim
		if htm, ok := token.Get("htm"); !ok || htm != "GET" {
			t.Errorf("htm claim = %v, want 'GET'", htm)
		}

		// Check htu claim (should be normalized)
		htu, ok := token.Get("htu")
		if !ok {
			t.Error("htu claim missing")
		} else if htuStr, isStr := htu.(string); !isStr {
			t.Errorf("htu claim not a string: %v", htu)
		} else if htuStr == "" {
			t.Error("htu claim is empty")
		}

		// Check ath claim (access token hash)
		if ath, athOK := token.Get("ath"); !athOK {
			t.Error("ath claim missing")
		} else {
			expectedHash := sha256.Sum256([]byte("test-access-token"))
			expectedATH := base64.RawURLEncoding.EncodeToString(expectedHash[:])
			if ath != expectedATH {
				t.Errorf("ath claim = %v, want %v", ath, expectedATH)
			}
		}

		// Check jti claim
		if jti, jtiOK := token.Get("jti"); !jtiOK || jti == "" {
			t.Error("jti claim missing or empty")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &DPoPTransport{
		Base:        http.DefaultTransport,
		DPoPKey:     key,
		TokenSource: ts,
	}

	client := &http.Client{Transport: transport}
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if !called {
		t.Error("server handler was not called")
	}
}

func TestDPoPTransport_NonceRetry(t *testing.T) {
	key := generateTestKey(t)
	ts := &mockTokenSource{token: "test-token"}

	callCount := 0
	nonce := "test-nonce-12345"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		dpopHeader := r.Header.Get("DPoP")
		if dpopHeader == "" {
			t.Error("DPoP header not present")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		publicKey, err := key.PublicKey()
		if err != nil {
			t.Fatalf("failed to get public key: %v", err)
		}

		token := parseDPoPProof(t, dpopHeader, publicKey)

		if callCount == 1 {
			// First request should not have nonce
			if _, ok := token.Get("nonce"); ok {
				t.Error("first request should not have nonce claim")
			}

			// Send 401 with nonce challenge
			w.Header().Set("DPoP-Nonce", nonce)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Second request should have the nonce
		if nonceVal, ok := token.Get("nonce"); !ok {
			t.Error("second request missing nonce claim")
		} else if nonceVal != nonce {
			t.Errorf("nonce claim = %v, want %v", nonceVal, nonce)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &DPoPTransport{
		Base:        http.DefaultTransport,
		DPoPKey:     key,
		TokenSource: ts,
	}

	client := &http.Client{Transport: transport}
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if callCount != 2 {
		t.Errorf("expected 2 calls (initial + retry), got %d", callCount)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestDPoPTransport_NonceRetryReplaysBodyWithoutGetBody reproduces the failure
// path that ConnectRPC/gRPC clients hit: they set req.Body and ContentLength
// but never set req.GetBody. The first round trip consumes the body; without
// buffering, the nonce retry sends ContentLength=N with an empty body and the
// HTTP/1.x transport aborts with "ContentLength=N with Body length 0".
func TestDPoPTransport_NonceRetryReplaysBodyWithoutGetBody(t *testing.T) {
	key := generateTestKey(t)
	ts := &mockTokenSource{token: "test-token"}

	const expectedBody = `{"foo":"bar"}`
	nonce := "test-nonce-12345"
	var receivedBodies []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("call %d: read body: %v", len(receivedBodies)+1, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		receivedBodies = append(receivedBodies, string(body))

		if len(receivedBodies) == 1 {
			w.Header().Set("DPoP-Nonce", nonce)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &DPoPTransport{
		Base:        http.DefaultTransport,
		DPoPKey:     key,
		TokenSource: ts,
	}

	client := &http.Client{Transport: transport}

	req, err := http.NewRequest(http.MethodPost, server.URL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	bodyBytes := []byte(expectedBody)
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))
	// GetBody intentionally NOT set — mirrors ConnectRPC/gRPC generated clients.

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if len(receivedBodies) != 2 {
		t.Fatalf("expected 2 calls (initial + retry), got %d", len(receivedBodies))
	}
	for i, got := range receivedBodies {
		if got != expectedBody {
			t.Errorf("call %d body = %q, want %q", i+1, got, expectedBody)
		}
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestDPoPTransport_NonceRetryReplaysConnectUnaryBody is the end-to-end
// regression for the bug that broke every body-bearing otdfctl/SDK call when
// the platform enables the DPoP-Nonce challenge (RFC 9449 §8): the nonce
// retry would re-issue the request with an exhausted body, and net/http
// would abort with "ContentLength=N with Body length 0". This exercises a
// real Connect-go unary client (the production code path), not a hand-built
// http.Request.
func TestDPoPTransport_NonceRetryReplaysConnectUnaryBody(t *testing.T) {
	key := generateTestKey(t)
	ts := &mockTokenSource{token: "test-token"}

	const nonce = "test-nonce-12345"
	var (
		mu             sync.Mutex
		receivedBodies [][]byte
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/kas.AccessService/PublicKey", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		mu.Lock()
		receivedBodies = append(receivedBodies, append([]byte(nil), body...))
		callNum := len(receivedBodies)
		mu.Unlock()

		if callNum == 1 {
			w.Header().Set("DPoP-Nonce", nonce)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	httpClient := &http.Client{Transport: &DPoPTransport{
		Base:        http.DefaultTransport,
		DPoPKey:     key,
		TokenSource: ts,
	}}

	client := kasconnect.NewAccessServiceClient(httpClient, server.URL)

	// A non-trivial body — mirrors what otdfctl sends for any unary RPC with
	// payload (e.g. policy attributes value key assign, KAS Rewrap).
	resp, err := client.PublicKey(context.Background(), connect.NewRequest(&kas.PublicKeyRequest{
		Algorithm: "rsa:2048",
		Fmt:       "pem",
	}))
	if err != nil {
		t.Fatalf("unary call failed: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}

	mu.Lock()
	defer mu.Unlock()

	if len(receivedBodies) != 2 {
		t.Fatalf("expected 2 calls (initial + retry), got %d", len(receivedBodies))
	}
	if len(receivedBodies[0]) == 0 {
		t.Fatal("first call body was empty — Connect-go did not send a payload")
	}
	if !bytes.Equal(receivedBodies[0], receivedBodies[1]) {
		t.Errorf("retry body differs from initial body\n  initial (len=%d): %x\n  retry   (len=%d): %x",
			len(receivedBodies[0]), receivedBodies[0],
			len(receivedBodies[1]), receivedBodies[1])
	}
}

func TestDPoPTransport_URINormalization(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "https default port",
			url:      "https://example.com:443/path",
			expected: "https://example.com/path",
		},
		{
			name:     "http default port",
			url:      "http://example.com:80/path",
			expected: "http://example.com/path",
		},
		{
			name:     "https non-default port",
			url:      "https://example.com:8443/path",
			expected: "https://example.com:8443/path",
		},
		{
			name:     "uppercase scheme and host",
			url:      "HTTPS://EXAMPLE.COM/Path",
			expected: "https://example.com/Path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := generateTestKey(t)
			ts := &mockTokenSource{token: "test-token"}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				dpopHeader := r.Header.Get("DPoP")
				publicKey, err := key.PublicKey()
				if err != nil {
					t.Fatalf("failed to get public key: %v", err)
				}

				token := parseDPoPProof(t, dpopHeader, publicKey)

				htu, ok := token.Get("htu")
				if !ok {
					t.Fatal("htu claim missing")
				}

				// The htu should have normalized the URL
				htuStr, isStr := htu.(string)
				if !isStr {
					t.Fatalf("htu claim is not a string: %T", htu)
				}
				if !strings.Contains(htuStr, "/path") {
					t.Errorf("htu = %s, want to contain normalized path", htuStr)
				}

				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			transport := &DPoPTransport{
				Base:        http.DefaultTransport,
				DPoPKey:     key,
				TokenSource: ts,
			}

			client := &http.Client{Transport: transport}

			// Use the server URL but replace path
			testURL := server.URL + "/path"
			req, err := http.NewRequest(http.MethodGet, testURL, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
		})
	}
}

func TestDPoPTransport_TokenEndpointNoATH(t *testing.T) {
	key := generateTestKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dpopHeader := r.Header.Get("DPoP")
		if dpopHeader == "" {
			t.Error("DPoP header not present")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		publicKey, err := key.PublicKey()
		if err != nil {
			t.Fatalf("failed to get public key: %v", err)
		}

		token := parseDPoPProof(t, dpopHeader, publicKey)

		// Token endpoint requests should NOT have ath claim
		if _, ok := token.Get("ath"); ok {
			t.Error("token endpoint request should not have ath claim")
		}

		// Should not have Authorization header for token endpoint
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("token endpoint should not have Authorization header, got %q", auth)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &DPoPTransport{
		Base:          http.DefaultTransport,
		DPoPKey:       key,
		TokenSource:   &mockTokenSource{token: "test-token"},
		TokenEndpoint: server.URL,
	}

	client := &http.Client{Transport: transport}
	req, err := http.NewRequest(http.MethodPost, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
}

func mustReq(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	return req
}

// TestNormalizeURI exercises the RFC 9449 HTTP URI normalization directly so that
// default-port stripping, scheme/host lowercasing, and query/fragment removal are
// each asserted (the integration test only checks the path substring).
func TestNormalizeURI(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"https default port stripped", "https://example.com:443/path", "https://example.com/path"},
		{"http default port stripped", "http://example.com:80/path", "http://example.com/path"},
		{"https non-default port kept", "https://example.com:8443/path", "https://example.com:8443/path"},
		{"http non-default port kept", "http://example.com:8080/path", "http://example.com:8080/path"},
		{"scheme and host lowercased, path preserved", "HTTPS://EXAMPLE.COM/Path", "https://example.com/Path"},
		{"query and fragment dropped", "https://example.com/p?a=b#frag", "https://example.com/p"},
		{"empty path", "https://example.com", "https://example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.url, err)
			}
			if got := normalizeURI(u); got != tt.want {
				t.Errorf("normalizeURI(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

// TestDPoPTransport_TokenSourceErrorAborts verifies that a token-fetch failure
// aborts the request with an error and never reaches the network — DPoP auth must
// fail closed rather than send a proof bound to no access token.
func TestDPoPTransport_TokenSourceErrorAborts(t *testing.T) {
	key := generateTestKey(t)
	ts := &mockTokenSource{err: errors.New("token fetch failed")}

	var called int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&called, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &DPoPTransport{Base: http.DefaultTransport, DPoPKey: key, TokenSource: ts}
	client := &http.Client{Transport: transport}

	resp, err := client.Do(mustReq(t, server.URL))
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected error when token source fails, got nil")
	}
	if got := atomic.LoadInt32(&called); got != 0 {
		t.Errorf("server should not be called when token fetch fails, got %d calls", got)
	}
}

// TestDPoPTransport_NoRetryOnPlain401 verifies that a 401 without a DPoP-Nonce
// header (a genuine auth failure) is propagated unchanged and not retried.
func TestDPoPTransport_NoRetryOnPlain401(t *testing.T) {
	key := generateTestKey(t)
	var callCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	transport := &DPoPTransport{Base: http.DefaultTransport, DPoPKey: key, TokenSource: &mockTokenSource{token: "t"}}
	client := &http.Client{Transport: transport}

	resp, err := client.Do(mustReq(t, server.URL))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("expected exactly 1 call (no retry), got %d", got)
	}
}

// TestDPoPTransport_NoRetryWhenNonceUnchanged verifies the loop-prevention guard:
// when the server returns a 401 echoing the nonce the client already sent, the
// transport does not retry.
func TestDPoPTransport_NoRetryWhenNonceUnchanged(t *testing.T) {
	key := generateTestKey(t)
	const nonce = "stable-nonce"
	var callCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		w.Header().Set("DPoP-Nonce", nonce)
		if n == 1 {
			// Prime the client's nonce cache via a successful response.
			w.WriteHeader(http.StatusOK)
			return
		}
		// Second request already carries this nonce; returning it again must not retry.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	transport := &DPoPTransport{Base: http.DefaultTransport, DPoPKey: key, TokenSource: &mockTokenSource{token: "t"}}
	client := &http.Client{Transport: transport}

	resp1, err := client.Do(mustReq(t, server.URL))
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	resp1.Body.Close()

	resp2, err := client.Do(mustReq(t, server.URL))
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp2.StatusCode)
	}
	if got := atomic.LoadInt32(&callCount); got != 2 {
		t.Errorf("expected 2 calls (no retry on unchanged nonce), got %d", got)
	}
}

// TestDPoPTransport_RetryOnRotatedNonce verifies that when the server rotates its
// nonce (returns a 401 with a nonce different from the cached one), the transport
// retries with the fresh nonce — the RFC 9449 §8 case the original guard missed.
func TestDPoPTransport_RetryOnRotatedNonce(t *testing.T) {
	key := generateTestKey(t)
	const (
		nonce1 = "nonce-1"
		nonce2 = "nonce-2"
	)
	var callCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch atomic.AddInt32(&callCount, 1) {
		case 1:
			w.Header().Set("DPoP-Nonce", nonce1) // prime cache via success
			w.WriteHeader(http.StatusOK)
		case 2:
			w.Header().Set("DPoP-Nonce", nonce2) // rotate with a challenge
			w.WriteHeader(http.StatusUnauthorized)
		default:
			pub, err := key.PublicKey()
			if err != nil {
				t.Errorf("public key: %v", err)
			}
			tok := parseDPoPProof(t, r.Header.Get("DPoP"), pub)
			if got, _ := tok.Get("nonce"); got != nonce2 {
				t.Errorf("retry nonce = %v, want %q", got, nonce2)
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	transport := &DPoPTransport{Base: http.DefaultTransport, DPoPKey: key, TokenSource: &mockTokenSource{token: "t"}}
	client := &http.Client{Transport: transport}

	resp1, err := client.Do(mustReq(t, server.URL))
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	resp1.Body.Close()

	resp2, err := client.Do(mustReq(t, server.URL))
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 after rotated-nonce retry", resp2.StatusCode)
	}
	if got := atomic.LoadInt32(&callCount); got != 3 {
		t.Errorf("expected 3 calls (prime + challenge + retry), got %d", got)
	}
}

// TestDPoPTransport_ConcurrentRequests drives many requests through one shared
// transport so the race detector covers the lazy nonce-map init and nonce cache.
func TestDPoPTransport_ConcurrentRequests(t *testing.T) {
	key := generateTestKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DPoP") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("DPoP-Nonce", "rotating")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &DPoPTransport{Base: http.DefaultTransport, DPoPKey: key, TokenSource: &mockTokenSource{token: "t"}}
	client := &http.Client{Transport: transport}

	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			resp, err := client.Do(mustReq(t, server.URL))
			if err != nil {
				errs <- err
				return
			}
			resp.Body.Close()
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent request failed: %v", err)
	}
}
