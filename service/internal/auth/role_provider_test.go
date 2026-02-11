package auth

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"
	"github.com/stretchr/testify/require"
)

type staticRoleProvider struct {
	roles []string
	err   error
}

func (s staticRoleProvider) Roles(_ context.Context, _ jwt.Token, _ authz.RoleRequest) ([]string, error) {
	return s.roles, s.err
}

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
				RolesProvider: "mock",
			},
		},
		RoleProviderFactories: map[string]authz.RoleProviderFactory{
			"mock": func(_ context.Context) (authz.RoleProvider, error) {
				return staticRoleProvider{roles: []string{"role:admin"}}, nil
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
				RolesProvider: "missing",
			},
		},
	}
	provider, err := resolveRoleProvider(context.Background(), cfg, logger)
	require.Error(t, err)
	require.Nil(t, provider)
}
