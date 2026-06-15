package authz

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
	"github.com/stretchr/testify/require"
)

type staticRoleProvider struct {
	roles []string
}

func (p staticRoleProvider) Roles(_ context.Context, _ jwt.Token, _ platformauthz.RoleRequest) ([]string, error) {
	return p.roles, nil
}

func TestSubjectExtractorGroupsClaimSupportsStringSlices(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("azp", "test-client"))
	require.NoError(t, token.Set("preferred_username", "alice"))
	require.NoError(t, token.Set("realm_access", map[string]any{
		"roles": []string{"opentdf-admin", "opentdf-standard"},
	}))

	extractor := SubjectExtractor{
		UserNameClaim: "preferred_username",
		ClientIDClaim: "azp",
		RoleProvider:  NewJWTClaimsRoleProvider("realm_access.roles", nil),
	}

	subjects, roles, err := extractor.BuildSubjectFromToken(context.Background(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"test-client", "opentdf-admin", "opentdf-standard", "alice"}, subjects)
	require.Equal(t, []string{"opentdf-admin", "opentdf-standard"}, roles)
}

func TestSubjectExtractorCanPrefixSubjects(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("azp", "test-client"))
	require.NoError(t, token.Set("preferred_username", "alice"))

	extractor := SubjectExtractor{
		UserNameClaim: "preferred_username",
		ClientIDClaim: "azp",
		RoleProvider:  staticRoleProvider{roles: []string{"admin", ""}},
		UsePrefix:     true,
	}

	subjects, roles, err := extractor.BuildSubjectFromToken(context.Background(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"client:test-client", "role:admin", "alice"}, subjects)
	require.Equal(t, []string{"role:admin"}, roles)
}

func TestSubjectExtractorDoesNotAppendEmptyUsername(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("preferred_username", ""))

	extractor := SubjectExtractor{
		UserNameClaim: "preferred_username",
		RoleProvider:  staticRoleProvider{roles: []string{"role:admin"}},
	}

	subjects, roles, err := extractor.BuildSubjectFromToken(context.Background(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"role:admin"}, subjects)
	require.Equal(t, []string{"role:admin"}, roles)
}

func TestSubjectExtractorIgnoresUsernameWithReservedRolePrefix(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("preferred_username", "role:admin"))

	extractor := SubjectExtractor{
		UserNameClaim: "preferred_username",
		RoleProvider:  staticRoleProvider{roles: []string{"role:admin"}},
	}

	subjects, roles, err := extractor.BuildSubjectFromToken(context.Background(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"role:admin"}, subjects)
	require.Equal(t, []string{"role:admin"}, roles)
}
