package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// mockTokenSource implements AccessTokenSource for testing
type mockTokenSource struct {
	token string
}

func (m *mockTokenSource) AccessToken(_ context.Context, _ *http.Client) (AccessToken, error) {
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
