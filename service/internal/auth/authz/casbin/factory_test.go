package casbin

import (
	"testing"

	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthorizerDispatchesVersions(t *testing.T) {
	log := logger.CreateTestLogger()

	tests := []struct {
		name          string
		version       string
		expectVersion string
	}{
		{
			name:          "empty version defaults to v1",
			version:       "",
			expectVersion: "v1",
		},
		{
			name:          "explicit v1",
			version:       "v1",
			expectVersion: "v1",
		},
		{
			name:          "explicit v2",
			version:       "v2",
			expectVersion: "v2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			authorizer, err := NewAuthorizer(authz.Config{
				PolicyConfig: authz.PolicyConfig{
					Version:     tc.version,
					GroupsClaim: "realm_access.roles",
				},
				Logger: log,
			})
			require.NoError(t, err)
			require.NotNil(t, authorizer)
			assert.Equal(t, tc.expectVersion, authorizer.Version())
		})
	}
}

func TestAuthzNewUsesRegisteredFactoryAndPolicyVersion(t *testing.T) {
	log := logger.CreateTestLogger()

	authorizer, err := authz.New(authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
		},
		Logger: log,
	})
	require.NoError(t, err)
	require.NotNil(t, authorizer)
	assert.Equal(t, "v2", authorizer.Version())
}

func TestNewAuthorizerRequiresLogger(t *testing.T) {
	authorizer, err := NewAuthorizer(authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v1",
			GroupsClaim: "realm_access.roles",
		},
	})
	require.Error(t, err)
	assert.Nil(t, authorizer)
	assert.Contains(t, err.Error(), "logger is required")
}
