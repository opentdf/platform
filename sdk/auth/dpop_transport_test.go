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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "failed to generate RSA key")

	key, err := jwk.FromRaw(rawKey)
	require.NoError(t, err, "failed to create JWK")

	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.RS256), "failed to set algorithm")

	return key
}

func parseDPoPProof(t *testing.T, proofStr string, key jwk.Key) jwt.Token {
	t.Helper()

	token, err := jwt.Parse([]byte(proofStr), jwt.WithKey(jwa.RS256, key))
	require.NoError(t, err, "failed to parse DPoP proof")

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
		if !assert.NotEmpty(t, dpopHeader, "DPoP header not present") {
			return
		}

		// Verify Authorization header
		authHeader := r.Header.Get("Authorization")
		assert.True(t, strings.HasPrefix(authHeader, "DPoP "), "Authorization header = %q, want prefix 'DPoP '", authHeader)

		// Parse and verify the proof
		publicKey, err := key.PublicKey()
		if !assert.NoError(t, err, "failed to get public key") {
			return
		}

		token := parseDPoPProof(t, dpopHeader, publicKey)

		// Check htm claim
		htm, ok := token.Get("htm")
		assert.True(t, ok && htm == "GET", "htm claim = %v, want 'GET'", htm)

		// Check htu claim (should be normalized)
		htu, ok := token.Get("htu")
		if assert.True(t, ok, "htu claim missing") {
			htuStr, isStr := htu.(string)
			assert.True(t, isStr, "htu claim not a string: %v", htu)
			assert.NotEmpty(t, htuStr, "htu claim is empty")
		}

		// Check ath claim (access token hash)
		if ath, athOK := token.Get("ath"); assert.True(t, athOK, "ath claim missing") {
			expectedHash := sha256.Sum256([]byte("test-access-token"))
			expectedATH := base64.RawURLEncoding.EncodeToString(expectedHash[:])
			assert.Equal(t, expectedATH, ath, "ath claim")
		}

		// Check jti claim
		jti, jtiOK := token.Get("jti")
		assert.True(t, jtiOK && jti != "", "jti claim missing or empty")

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
	require.NoError(t, err, "failed to create request")

	resp, err := client.Do(req)
	require.NoError(t, err, "request failed")
	defer resp.Body.Close()

	assert.True(t, called, "server handler was not called")
}

func TestDPoPTransport_NonceRetry(t *testing.T) {
	key := generateTestKey(t)
	ts := &mockTokenSource{token: "test-token"}

	callCount := 0
	nonce := "test-nonce-12345"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		dpopHeader := r.Header.Get("DPoP")
		if !assert.NotEmpty(t, dpopHeader, "DPoP header not present") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		publicKey, err := key.PublicKey()
		if !assert.NoError(t, err, "failed to get public key") {
			return
		}

		token := parseDPoPProof(t, dpopHeader, publicKey)

		if callCount == 1 {
			// First request should not have nonce
			_, ok := token.Get("nonce")
			assert.False(t, ok, "first request should not have nonce claim")

			// Send 401 with nonce challenge
			w.Header().Set("DPoP-Nonce", nonce)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Second request should have the nonce
		if nonceVal, ok := token.Get("nonce"); assert.True(t, ok, "second request missing nonce claim") {
			assert.Equal(t, nonce, nonceVal, "nonce claim")
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
	require.NoError(t, err, "failed to create request")

	resp, err := client.Do(req)
	require.NoError(t, err, "request failed")
	defer resp.Body.Close()

	assert.Equal(t, 2, callCount, "expected 2 calls (initial + retry)")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "final status")
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
		if !assert.NoError(t, err, "call %d: read body", len(receivedBodies)+1) {
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
	require.NoError(t, err, "create request")
	bodyBytes := []byte(expectedBody)
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))
	// GetBody intentionally NOT set — mirrors ConnectRPC/gRPC generated clients.

	resp, err := client.Do(req)
	require.NoError(t, err, "request failed")
	defer resp.Body.Close()

	require.Len(t, receivedBodies, 2, "expected 2 calls (initial + retry)")
	for i, got := range receivedBodies {
		assert.JSONEqf(t, expectedBody, got, "call %d body", i+1)
	}
	assert.Equal(t, http.StatusOK, resp.StatusCode, "final status")
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
		if !assert.NoError(t, err, "read body") {
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
	require.NoError(t, err, "unary call failed")
	require.NotNil(t, resp, "nil response")

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, receivedBodies, 2, "expected 2 calls (initial + retry)")
	require.NotEmpty(t, receivedBodies[0], "first call body was empty — Connect-go did not send a payload")
	assert.Equal(t, receivedBodies[0], receivedBodies[1], "retry body differs from initial body")
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
				if !assert.NoError(t, err, "failed to get public key") {
					return
				}

				token := parseDPoPProof(t, dpopHeader, publicKey)

				htu, ok := token.Get("htu")
				if !assert.True(t, ok, "htu claim missing") {
					return
				}

				// The htu should have normalized the URL
				htuStr, isStr := htu.(string)
				if !assert.Truef(t, isStr, "htu claim is not a string: %T", htu) {
					return
				}
				assert.Contains(t, htuStr, "/path", "htu = %s, want to contain normalized path", htuStr)

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
			require.NoError(t, err, "failed to create request")

			resp, err := client.Do(req)
			require.NoError(t, err, "request failed")
			resp.Body.Close()
		})
	}
}

func TestDPoPTransport_TokenEndpointNoATH(t *testing.T) {
	key := generateTestKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dpopHeader := r.Header.Get("DPoP")
		if !assert.NotEmpty(t, dpopHeader, "DPoP header not present") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		publicKey, err := key.PublicKey()
		if !assert.NoError(t, err, "failed to get public key") {
			return
		}

		token := parseDPoPProof(t, dpopHeader, publicKey)

		// Token endpoint requests should NOT have ath claim
		_, ok := token.Get("ath")
		assert.False(t, ok, "token endpoint request should not have ath claim")

		// Should not have Authorization header for token endpoint
		assert.Empty(t, r.Header.Get("Authorization"), "token endpoint should not have Authorization header")

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
	require.NoError(t, err, "failed to create request")

	resp, err := client.Do(req)
	require.NoError(t, err, "request failed")
	defer resp.Body.Close()
}

func mustReq(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err, "create request")
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
		{"escaped reserved path preserved", "https://example.com/a%2Fb", "https://example.com/a%2Fb"},
		{"query and fragment dropped", "https://example.com/p?a=b#frag", "https://example.com/p"},
		{"empty path", "https://example.com", "https://example.com"},
		{"uppercase host with default port", "HTTPS://EXAMPLE.COM:443/Path", "https://example.com/Path"},
		{"ipv6 default port stripped", "https://[::1]:443/path", "https://[::1]/path"},
		{"ipv6 non-default port kept", "https://[::1]:8443/path", "https://[::1]:8443/path"},
		{"ipv6 literal ending in 443 kept", "https://[fe80::443]/path", "https://[fe80::443]/path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoErrorf(t, err, "parse %q", tt.url)
			assert.Equalf(t, tt.want, normalizeURI(u), "normalizeURI(%q)", tt.url)
		})
	}
}

// TestGetOrigin exercises origin extraction, ensuring default ports are stripped
// (so a URL with an explicit :443 shares a nonce-cache key with one without) and
// IPv6 literals keep their brackets.
func TestGetOrigin(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"no port", "https://example.com/path", "https://example.com"},
		{"default https port stripped", "https://example.com:443/path", "https://example.com"},
		{"default http port stripped", "http://example.com:80/path", "http://example.com"},
		{"non-default port kept", "https://example.com:8443/path", "https://example.com:8443"},
		{"scheme and host lowercased", "HTTPS://EXAMPLE.COM:443/p", "https://example.com"},
		{"ipv6 default port stripped", "https://[::1]:443/path", "https://[::1]"},
		{"ipv6 non-default port kept", "https://[::1]:8443/path", "https://[::1]:8443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoErrorf(t, err, "parse %q", tt.url)
			assert.Equalf(t, tt.want, getOrigin(u), "getOrigin(%q)", tt.url)
		})
	}
}

// TestIsTokenEndpointRequest_PortNormalization confirms token-endpoint detection
// treats an explicit default port as equivalent to no port.
func TestIsTokenEndpointRequest_PortNormalization(t *testing.T) {
	transport := &DPoPTransport{TokenEndpoint: "https://example.com/token"}

	withPort, err := url.Parse("https://example.com:443/token")
	require.NoError(t, err, "parse url with port")
	assert.True(t, transport.isTokenEndpointRequest(withPort), "explicit :443 should match configured endpoint")

	other, err := url.Parse("https://example.com/other")
	require.NoError(t, err, "parse url with different path")
	assert.False(t, transport.isTokenEndpointRequest(other), "different path should not match")
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
		require.Fail(t, "expected error when token source fails, got nil")
	}
	assert.Zero(t, atomic.LoadInt32(&called), "server should not be called when token fetch fails")
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
	require.NoError(t, err, "request failed")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "status")
	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount), "expected exactly 1 call (no retry)")
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
	require.NoError(t, err, "first request failed")
	resp1.Body.Close()

	resp2, err := client.Do(mustReq(t, server.URL))
	require.NoError(t, err, "second request failed")
	resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode, "status")
	assert.Equal(t, int32(2), atomic.LoadInt32(&callCount), "expected 2 calls (no retry on unchanged nonce)")
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
			assert.NoError(t, err, "public key")
			tok := parseDPoPProof(t, r.Header.Get("DPoP"), pub)
			got, _ := tok.Get("nonce")
			assert.Equalf(t, nonce2, got, "retry nonce")
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	transport := &DPoPTransport{Base: http.DefaultTransport, DPoPKey: key, TokenSource: &mockTokenSource{token: "t"}}
	client := &http.Client{Transport: transport}

	resp1, err := client.Do(mustReq(t, server.URL))
	require.NoError(t, err, "first request failed")
	resp1.Body.Close()

	resp2, err := client.Do(mustReq(t, server.URL))
	require.NoError(t, err, "second request failed")
	resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "status after rotated-nonce retry")
	assert.Equal(t, int32(3), atomic.LoadInt32(&callCount), "expected 3 calls (prime + challenge + retry)")
}

// TestDPoPTransport_CachesNonceFromRetrySuccess verifies that a nonce the server
// rotates onto the successful *retry* response is cached and reused by the next
// request. An early return on the retry path would drop it, forcing a fresh
// 401/retry round-trip every time.
func TestDPoPTransport_CachesNonceFromRetrySuccess(t *testing.T) {
	key := generateTestKey(t)
	const (
		challengeNonce = "challenge-nonce"
		rotatedNonce   = "rotated-on-success"
	)
	nonceOf := func(r *http.Request) string {
		pub, err := key.PublicKey()
		// assert (not require) because this runs on the httptest server goroutine,
		// where t.FailNow via require is unsafe.
		assert.NoError(t, err, "public key") //nolint:testifylint // require unsafe off the test goroutine
		tok := parseDPoPProof(t, r.Header.Get("DPoP"), pub)
		got, _ := tok.Get("nonce")
		s, _ := got.(string)
		return s
	}
	var callCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch atomic.AddInt32(&callCount, 1) {
		case 1:
			// Initial request carries no nonce; challenge for one.
			w.Header().Set("DPoP-Nonce", challengeNonce)
			w.WriteHeader(http.StatusUnauthorized)
		case 2:
			// Retry carries the challenge nonce; succeed but rotate the nonce.
			assert.Equal(t, challengeNonce, nonceOf(r), "retry nonce")
			w.Header().Set("DPoP-Nonce", rotatedNonce)
			w.WriteHeader(http.StatusOK)
		default:
			// Next request must reuse the nonce rotated on the successful retry.
			assert.Equal(t, rotatedNonce, nonceOf(r), "next-request nonce")
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	transport := &DPoPTransport{Base: http.DefaultTransport, DPoPKey: key, TokenSource: &mockTokenSource{token: "t"}}
	client := &http.Client{Transport: transport}

	resp1, err := client.Do(mustReq(t, server.URL))
	require.NoError(t, err, "first request failed")
	resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode, "status after challenge retry")

	resp2, err := client.Do(mustReq(t, server.URL))
	require.NoError(t, err, "second request failed")
	resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "status")
	assert.Equal(t, int32(3), atomic.LoadInt32(&callCount), "expected 3 calls (challenge + retry + reuse)")
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
		assert.NoError(t, err, "concurrent request failed")
	}
}
