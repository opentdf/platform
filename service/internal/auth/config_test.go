package auth

import (
	"testing"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/oidc"
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

	keyPath := "./testdata/client-credentials-private.jwk"
	// Save original readFileFunc and restore after test
	origReadFileFunc := readConfigFile
	defer func() { readConfigFile = origReadFileFunc }()
	readConfigFile = func(path string) ([]byte, error) {
		if path == keyPath {
			return []byte(`{"kty":"RSA","n":"testn","e":"AQAB","d":"testd"}`), nil
		}
		return origReadFileFunc(path)
	}

	tests := []struct {
		name        string
		config      AuthNConfig
		expectError bool
		errorVal    error
	}{
		{
			name: "valid config with enrichUserInfo true",
			config: AuthNConfig{
				EnrichUserInfo:       true,
				Issuer:               "https://keycloak.example.com/realms/test",
				Audience:             "test-client",
				ClientID:             "platform-client",
				ClientPrivateKeyPath: keyPath,
			},
			expectError: false,
		},
		{
			name: "valid config with enrichUserInfo false",
			config: AuthNConfig{
				EnrichUserInfo: false,
				Issuer:         "https://keycloak.example.com/realms/test",
				Audience:       "test-client",
				// ClientId are not required when enrichUserInfo is false
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
				ClientPrivateKeyPath: keyPath,
			},
			expectError: true,
			errorVal:    errClientIDRequired,
		},
		{
			name: "invalid config with missing issuer",
			config: AuthNConfig{
				EnrichUserInfo: true,
				// Missing Issuer
				Audience:             "test-client",
				ClientID:             "platform-client",
				ClientPrivateKeyPath: keyPath,
			},
			expectError: true,
			errorVal:    errIssuerRequired,
		},
		{
			name: "invalid config with missing audience",
			config: AuthNConfig{
				EnrichUserInfo: true,
				Issuer:         "https://keycloak.example.com/realms/test",
				// Missing Audience
				ClientID:             "platform-client",
				ClientPrivateKeyPath: keyPath,
			},
			expectError: true,
			errorVal:    errAudienceRequired,
		},
		{
			name: "valid config with enrichUserInfo true and clientPrivateKey (private_key_jwt inline)",
			config: AuthNConfig{
				EnrichUserInfo:   true,
				Issuer:           "https://keycloak.example.com/realms/test",
				Audience:         "test-client",
				ClientID:         "platform-client",
				ClientPrivateKey: "{\"kty\":\"RSA\",\"d\":\"abc\"}",
			},
			expectError: false,
		},
		{
			name: "valid config with enrichUserInfo true and clientPrivateKeyPath (private_key_jwt path)",
			config: AuthNConfig{
				EnrichUserInfo:       true,
				Issuer:               "https://keycloak.example.com/realms/test",
				Audience:             "test-client",
				ClientID:             "platform-client",
				ClientPrivateKeyPath: keyPath,
			},
			expectError: false,
		},
		{
			name: "invalid config with enrichUserInfo true and missing clientId (private_key_jwt path)",
			config: AuthNConfig{
				EnrichUserInfo:       true,
				Issuer:               "https://keycloak.example.com/realms/test",
				Audience:             "test-client",
				ClientPrivateKeyPath: keyPath,
			},
			expectError: true,
			errorVal:    errClientIDRequired,
		},
		{
			name: "invalid config with enrichUserInfo true and missing clientPrivateKey and clientPrivateKeyPath",
			config: AuthNConfig{
				EnrichUserInfo: true,
				Issuer:         "https://keycloak.example.com/realms/test",
				Audience:       "test-client",
				ClientID:       "platform-client",
			},
			expectError: true,
			errorVal:    errPrivateKeyRequired,
		},
		{
			name: "invalid config with unreadable clientPrivateKeyPath",
			config: AuthNConfig{
				EnrichUserInfo:       true,
				Issuer:               "https://keycloak.example.com/realms/test",
				Audience:             "test-client",
				ClientID:             "platform-client",
				ClientPrivateKeyPath: "/tmp/does-not-exist-12345.jwk",
			},
			expectError: true,
			// We expect an error containing 'failed to read client private key from path:'
			// but not a specific error value, so we will check for error presence only.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validateAuthNConfig(testLogger)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorVal != nil {
					require.ErrorIs(t, err, tt.errorVal)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
