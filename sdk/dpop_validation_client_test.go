package sdk

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewDPoPValidationHTTPClient verifies the helper otdfctl uses to make a
// DPoP-bound token-endpoint request during credential validation: the request
// carries a DPoP proof header whether or not a key is explicitly configured,
// matching the DPoP-on default the credentialed SDK client applies.
func TestNewDPoPValidationHTTPClient(t *testing.T) {
	assertAddsDPoPProof := func(t *testing.T, opts ...Option) {
		t.Helper()
		var gotDPoP, gotAuthz string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotDPoP = r.Header.Get("DPoP")
			gotAuthz = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewDPoPValidationHTTPClient(http.DefaultClient, opts...)
		require.NoError(t, err, "NewDPoPValidationHTTPClient")

		resp, err := client.Do(mustGet(t, server.URL))
		require.NoError(t, err, "request failed")
		resp.Body.Close()

		assert.NotEmpty(t, gotDPoP, "expected a DPoP proof header on the token request")
		// Token-endpoint requests bind via htu only: no ath claim / Authorization header.
		assert.Empty(t, gotAuthz, "token-endpoint request must not carry an Authorization header")
	}

	t.Run("adds DPoP proof when algorithm configured", func(t *testing.T) {
		assertAddsDPoPProof(t, WithDPoPAlgorithm(ES256))
	})

	t.Run("adds DPoP proof by default when no DPoP configured", func(t *testing.T) {
		assertAddsDPoPProof(t)
	})

	t.Run("propagates invalid key configuration as an error", func(t *testing.T) {
		_, err := NewDPoPValidationHTTPClient(http.DefaultClient, WithDPoPKeyPEM([]byte("not a pem")))
		assert.Error(t, err, "expected error for invalid DPoP key PEM")
	})
}

func mustGet(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err, "new request")
	return req
}
