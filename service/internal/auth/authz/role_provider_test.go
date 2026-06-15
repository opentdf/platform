package authz

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
	"github.com/stretchr/testify/require"
)

func TestJWTClaimsRoleProviderSupportsStringSlices(t *testing.T) {
	provider := NewJWTClaimsRoleProvider("realm_access.roles", nil)
	token := jwt.New()
	require.NoError(t, token.Set("realm_access", map[string]any{
		"roles": []string{"opentdf-admin"},
	}))

	roles, err := provider.Roles(context.Background(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"opentdf-admin"}, roles)
}
