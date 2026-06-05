package auth

import (
	"context"
	"testing"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"
	"github.com/stretchr/testify/require"
)

func TestResolveRoleProviderDefault(t *testing.T) {
	logger := logger.CreateTestLogger()
	cfg := Config{}
	provider, err := resolveRoleProvider(context.Background(), cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, provider)
	require.IsType(t, &jwtClaimsRoleProvider{}, provider)
}

func TestResolveRoleProviderNamed(t *testing.T) {
	logger := logger.CreateTestLogger()
	cfg := Config{
		AuthNConfig: AuthNConfig{
			Policy: PolicyConfig{
				RolesProvider: RolesProviderConfig{
					Name: "mock",
				},
			},
		},
		RoleProviderFactories: map[string]authz.RoleProviderFactory{
			"mock": func(_ context.Context, _ authz.ProviderConfig) (authz.RoleProvider, error) {
				return staticProvider{roles: []string{"role:admin"}}, nil
			},
		},
	}
	provider, err := resolveRoleProvider(context.Background(), cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, provider)
}

func TestResolveRoleProviderMissingName(t *testing.T) {
	logger := logger.CreateTestLogger()
	cfg := Config{
		AuthNConfig: AuthNConfig{
			Policy: PolicyConfig{
				RolesProvider: RolesProviderConfig{
					Name: "missing",
				},
			},
		},
	}
	provider, err := resolveRoleProvider(context.Background(), cfg, logger)
	require.Error(t, err)
	require.Nil(t, provider)
}
