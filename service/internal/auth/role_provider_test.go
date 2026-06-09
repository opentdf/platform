package auth

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
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

func TestRolesFromConfiguredClaim(t *testing.T) {
	tests := []struct {
		name        string
		groupsClaim string
		claims      map[string]any
		want        []string
	}{
		{
			name:        "string claim",
			groupsClaim: "roles",
			claims: map[string]any{
				"roles": "role:admin",
			},
			want: []string{"role:admin"},
		},
		{
			name:        "array claim",
			groupsClaim: "roles",
			claims: map[string]any{
				"roles": []any{"role:admin", "role:standard", 7},
			},
			want: []string{"role:admin", "role:standard"},
		},
		{
			name:        "dotted nested claim",
			groupsClaim: "realm_access.roles",
			claims: map[string]any{
				"realm_access": map[string]any{
					"roles": []any{"role:admin"},
				},
			},
			want: []string{"role:admin"},
		},
		{
			name:        "missing claim",
			groupsClaim: "roles",
			claims:      map[string]any{},
		},
		{
			name:        "non-map dotted claim",
			groupsClaim: "realm_access.roles",
			claims: map[string]any{
				"realm_access": "role:admin",
			},
		},
		{
			name:        "unsupported claim type",
			groupsClaim: "roles",
			claims: map[string]any{
				"roles": 7,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := jwt.New()
			for k, v := range tt.claims {
				require.NoError(t, token.Set(k, v))
			}

			require.Equal(t, tt.want, rolesFromConfiguredClaim(token, tt.groupsClaim, logger.CreateTestLogger()))
		})
	}
}
