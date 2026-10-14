package sdk_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func Test_SDK_TokenExpirationBuffer_RenewsConcurrently(t *testing.T) {
	sessionKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	modes := []struct {
		name      string
		grantType string
		options   []sdk.Option
	}{
		{name: "ClientCredentials", grantType: "client_credentials"},
		{
			name:      "TokenExchange",
			grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
			options:   []sdk.Option{sdk.WithTokenExchange("subject-token", nil)},
		},
		{
			name:      "CertificateExchange",
			grantType: "password",
			options:   []sdk.Option{sdk.WithTLSCredentials(nil, nil)},
		},
	}
	tests := []struct {
		name             string
		expiresIn        int64
		options          []sdk.Option
		expectedRequests int64
	}{
		{name: "DefaultCachesValidToken", expiresIn: 60, expectedRequests: 1},
		{name: "DefaultRenewsWithinTenSeconds", expiresIn: 5, expectedRequests: 2},
		{
			name:             "CustomRenewsWithinNinetySeconds",
			expiresIn:        60,
			options:          []sdk.Option{sdk.WithTokenExpirationBuffer(90 * time.Second)},
			expectedRequests: 2,
		},
		{
			name:             "CustomCachesOutsideWindow",
			expiresIn:        180,
			options:          []sdk.Option{sdk.WithTokenExpirationBuffer(90 * time.Second)},
			expectedRequests: 1,
		},
		{
			name:             "ZeroDisablesEarlyRenewal",
			expiresIn:        5,
			options:          []sdk.Option{sdk.WithTokenExpirationBuffer(0)},
			expectedRequests: 1,
		},
		{
			name:             "MissingExpiryStaysCached",
			options:          []sdk.Option{sdk.WithTokenExpirationBuffer(90 * time.Second)},
			expectedRequests: 1,
		},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					var requests atomic.Int64
					server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
						assert.NoError(t, request.ParseForm())
						assert.Equal(t, mode.grantType, request.Form.Get("grant_type"))
						number := requests.Add(1)
						expiresIn := test.expiresIn
						if number > 1 {
							expiresIn = 3600
						}
						responseWriter.Header().Set("Content-Type", "application/json")
						_, writeErr := fmt.Fprintf(responseWriter, `{"access_token":"token-%d","token_type":"Bearer","expires_in":%d}`, number, expiresIn)
						assert.NoError(t, writeErr)
					}))
					t.Cleanup(server.Close)
					options := []sdk.Option{
						sdk.WithPlatformConfiguration(sdk.PlatformConfiguration{}),
						sdk.WithTokenEndpoint(server.URL),
						sdk.WithClientCredentials("client-id", "client-secret", nil),
						sdk.WithSessionEncryptionRSA(sessionKey),
					}
					options = append(options, mode.options...)
					options = append(options, test.options...)
					client, initErr := sdk.New(server.URL, options...)
					require.NoError(t, initErr)
					t.Cleanup(func() { assert.NoError(t, client.Close()) })
					token, tokenErr := client.Auth().AccessToken(t.Context())
					require.NoError(t, tokenErr)
					assert.Equal(t, auth.AccessToken("token-1"), token)

					var workers sync.WaitGroup
					for range 10 {
						workers.Go(func() {
							concurrentToken, concurrentErr := client.Auth().AccessToken(t.Context())
							if concurrentErr != nil {
								t.Errorf("AccessToken: %v", concurrentErr)
								return
							}
							assert.Equal(t, auth.AccessToken(fmt.Sprintf("token-%d", test.expectedRequests)), concurrentToken)
						})
					}
					workers.Wait()
					assert.Equal(t, test.expectedRequests, requests.Load())
				})
			}
		})
	}
}

func Test_SDK_TokenExpirationBuffer_RejectsNegative_Fails(t *testing.T) {
	client, err := sdk.New("", sdk.WithTokenExpirationBuffer(-time.Second))
	require.ErrorContains(t, err, "token expiration buffer must not be negative")
	assert.Nil(t, client)
}

func Test_SDK_TokenExpirationBuffer_PreservesCustomOAuthSource(t *testing.T) {
	client, err := sdk.New("http://localhost:8080",
		sdk.WithPlatformConfiguration(sdk.PlatformConfiguration{}),
		sdk.WithTokenExpirationBuffer(90*time.Second),
		sdk.WithOAuthAccessTokenSource(oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: "custom-token",
			Expiry:      time.Now().Add(time.Minute),
		})),
	)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })
	for range 2 {
		token, tokenErr := client.Auth().AccessToken(t.Context())
		require.NoError(t, tokenErr)
		assert.Equal(t, auth.AccessToken("custom-token"), token)
	}
}
