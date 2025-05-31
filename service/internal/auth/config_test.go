package auth

import (
	"testing"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAuthNConfig(t *testing.T) {
	// Skip client credentials validation during tests
	oidc.SetSkipValidationForTest(true)
	defer oidc.SetSkipValidationForTest(false)

	testLogger, err := logger.NewLogger(logger.Config{
		Output: "stdout",
		Level:  "debug",
		Type:   "json",
	})
	require.NoError(t, err, "Failed to create logger")

	tests := []struct {
		name        string
		config      AuthNConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with enrichUserInfo true",
			config: AuthNConfig{
				EnrichUserInfo: true,
				Issuer:         "https://keycloak.example.com/realms/test",
				Audience:       "test-client",
				ClientID:       "platform-client",
				ClientSecret:   "platform-secret",
			},
			expectError: false,
		},
		{
			name: "valid config with enrichUserInfo false",
			config: AuthNConfig{
				EnrichUserInfo: false,
				Issuer:         "https://keycloak.example.com/realms/test",
				Audience:       "test-client",
				// ClientId and ClientSecret are not required when enrichUserInfo is false
			},
			expectError: false,
		},
		{
			name: "invalid config with enrichUserInfo true and missing clientId",
			config: AuthNConfig{
				EnrichUserInfo: true,
				Issuer:         "https://keycloak.example.com/realms/test",
				Audience:       "test-client",
				// Missing ClientId
				ClientSecret: "platform-secret",
			},
			expectError: true,
			errorMsg:    "config Auth.ClientID is required for token exchange to fetch userinfo",
		},
		{
			name: "invalid config with enrichUserInfo true and missing clientSecret",
			config: AuthNConfig{
				EnrichUserInfo: true,
				Issuer:         "https://keycloak.example.com/realms/test",
				Audience:       "test-client",
				ClientID:       "platform-client",
				// Missing ClientSecret
			},
			expectError: true,
			errorMsg:    "config Auth.ClientSecret is required for token exchange to fetch userinfo",
		},
		{
			name: "invalid config with missing issuer",
			config: AuthNConfig{
				EnrichUserInfo: true,
				// Missing Issuer
				Audience:     "test-client",
				ClientID:     "platform-client",
				ClientSecret: "platform-secret",
			},
			expectError: true,
			errorMsg:    "config Auth.Issuer is required",
		},
		{
			name: "invalid config with missing audience",
			config: AuthNConfig{
				EnrichUserInfo: true,
				Issuer:         "https://keycloak.example.com/realms/test",
				// Missing Audience
				ClientID:     "platform-client",
				ClientSecret: "platform-secret",
			},
			expectError: true,
			errorMsg:    "config Auth.Audience is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validateAuthNConfig(testLogger)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Equal(t, tt.errorMsg, err.Error())
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
