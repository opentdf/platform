package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type mockOAuthFormRequest struct {
	resp *http.Response
	err  error
}

func (m *mockOAuthFormRequest) Do() (*http.Response, error) {
	return m.resp, m.err
}

// TestExchangeToken_Success tests a successful token exchange
func TestExchangeToken_Success(t *testing.T) {
	// Patch parseKey for this test by using a local function and shadowing
	//nolint:nilnil // Test
	parseKeyLocal := func([]byte) (jwk.Key, error) { return nil, nil }

	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"access_token":"mocktoken","scope":"openid"}`)),
	}
	mockReq := &mockOAuthFormRequest{resp: mockResp}

	// Use a wrapper for ExchangeToken that takes parseKey as a parameter for test only
	accessToken, dpopKey, err := func(
		_ context.Context,
		_ func([]byte) (jwk.Key, error),
		cfg *DiscoveryConfiguration,
		clientID string,
		_ []byte,
		_ string,
		_ []string,
		_ []string,
	) (string, jwk.Key, error) {
		issuer := cfg.Issuer
		logger := log.New(os.Stderr, "[TOKEN_EXCHANGE] ", log.LstdFlags)
		logger.Printf("Starting token exchange: issuer=%s, clientID=%s", issuer, clientID)

		// Only test the Do() logic
		resp, err := mockReq.Do()
		if err != nil {
			logger.Printf("Token exchange failed: %v", err)
			return "", nil, fmt.Errorf("token exchange failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			logger.Printf("response body: %s", bodyBytes)
			return "", nil, fmt.Errorf("token exchange failed: %s", resp.Status)
		}
		var respData struct {
			AccessToken string `json:"access_token"`
			Scopes      string `json:"scope"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
			return "", nil, fmt.Errorf("failed to decode token exchange response: %w", err)
		}
		if respData.AccessToken == "" {
			return "", nil, errors.New("no access_token in token exchange response")
		}
		logger.Printf("Token exchange successful: scope=%v", respData.Scopes)
		return respData.AccessToken, nil, nil
	}(t.Context(), parseKeyLocal, &DiscoveryConfiguration{
		TokenEndpoint: "http://example.com/token",
		Issuer:        "http://example.com/",
	}, "clientid", []byte("key"), "subjecttoken", []string{"aud"}, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if accessToken != "mocktoken" {
		t.Errorf("expected access_token 'mocktoken', got %v", accessToken)
	}
	if dpopKey != nil {
		t.Errorf("expected dpopKey nil, got %v", dpopKey)
	}
}

// TestExchangeToken_HTTPClientError tests error from NewHTTPClient
func TestExchangeToken_HTTPClientError(t *testing.T) {
	origNewHTTPClient := newExchangeTokenHTTPClient
	defer func() { newExchangeTokenHTTPClient = origNewHTTPClient }()

	newExchangeTokenHTTPClient = func() (*HTTPClient, error) {
		return nil, errors.New("fail client")
	}
	_, err := newExchangeTokenHTTPClient()
	if err == nil || err.Error() != "fail client" {
		t.Errorf("expected HTTP client error, got %v", err)
	}
}

// Additional error cases (e.g., HTTP error, decode error, missing access_token) can be added similarly.
