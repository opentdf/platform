package sdk_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func Test_SDK_TokenExpirationBuffer_RenewsBeforeExpiry(t *testing.T) {
	tests := []struct {
		name             string
		expiresIn        int64
		options          []sdk.Option
		expectedRequests int64
	}{
		{name: "DefaultCachesValidToken", expiresIn: 60, expectedRequests: 1},
		{
			name:             "CustomRenewsWithinNinetySeconds",
			expiresIn:        60,
			options:          []sdk.Option{sdk.WithTokenExpirationBuffer(90 * time.Second)},
			expectedRequests: 2,
		},
		{
			name:             "ZeroDisablesEarlyRenewal",
			expiresIn:        5,
			options:          []sdk.Option{sdk.WithTokenExpirationBuffer(0)},
			expectedRequests: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				responseWriter.Header().Set("Content-Type", "application/json")
				_, writeErr := fmt.Fprintf(responseWriter, `{"access_token":"test-token","token_type":"Bearer","expires_in":%d}`, test.expiresIn)
				assert.NoError(t, writeErr)
			}))
			t.Cleanup(server.Close)
			options := []sdk.Option{
				sdk.WithPlatformConfiguration(sdk.PlatformConfiguration{}),
				sdk.WithTokenEndpoint(server.URL),
				sdk.WithClientCredentials("client-id", "client-secret", nil),
			}
			options = append(options, test.options...)
			client, err := sdk.New(server.URL, options...)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, client.Close()) })
			for range 2 {
				token, tokenErr := client.Auth().AccessToken(t.Context())
				require.NoError(t, tokenErr)
				assert.Equal(t, auth.AccessToken("test-token"), token)
			}
			assert.Equal(t, test.expectedRequests, requests.Load())
		})
	}
}

func Test_SDK_TokenExpirationBuffer_RejectsNegative_Fails(t *testing.T) {
	client, err := sdk.New("", sdk.WithTokenExpirationBuffer(-time.Second))
	require.ErrorIs(t, err, sdk.ErrTokenExpirationBufferInvalid)
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
