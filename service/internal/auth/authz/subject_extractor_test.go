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

	subjects, roles, err := extractor.BuildSubjectFromToken(t.Context(), token, platformauthz.RoleRequest{}, false)
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
	}

	subjects, roles, err := extractor.BuildSubjectFromToken(t.Context(), token, platformauthz.RoleRequest{}, true)
	require.NoError(t, err)
	require.Equal(t, []string{"client:test-client", "role:admin", "alice"}, subjects)
	require.Equal(t, []string{"role:admin"}, roles)
}

func TestSubjectExtractorFiltersEmptyRolesWithoutPrefix(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("preferred_username", "alice"))

	extractor := SubjectExtractor{
		UserNameClaim: "preferred_username",
		RoleProvider:  staticRoleProvider{roles: []string{"admin", "", "viewer"}},
	}

	subjects, roles, err := extractor.BuildSubjectFromToken(t.Context(), token, platformauthz.RoleRequest{}, false)
	require.NoError(t, err)
	require.Equal(t, []string{"admin", "viewer", "alice"}, subjects)
	require.Equal(t, []string{"admin", "viewer"}, roles)
}

func TestSubjectExtractorRequiresTokenWhenClaimsAreNotCached(t *testing.T) {
	extractor := SubjectExtractor{
		UserNameClaim: "preferred_username",
		ClientIDClaim: "azp",
		RoleProvider:  staticRoleProvider{roles: []string{"admin"}},
	}

	subjects, roles, err := extractor.BuildSubjectFromToken(t.Context(), nil, platformauthz.RoleRequest{}, true)

	require.ErrorIs(t, err, ErrTokenRequired)
	require.Nil(t, subjects)
	require.Nil(t, roles)
}

func TestSubjectExtractorClientIDFromNilToken(t *testing.T) {
	extractor := SubjectExtractor{ClientIDClaim: "azp"}

	got, err := extractor.ClientIDFromToken(t.Context(), nil)

	require.Empty(t, got)
	require.ErrorIs(t, err, ErrTokenRequired)
}

func TestSubjectExtractorClientIDFromToken(t *testing.T) {
	tests := []struct {
		name        string
		claims      map[string]any
		claim       string
		want        string
		wantErr     error
		expectError bool
	}{
		{
			name:   "top level client id claim",
			claims: map[string]any{"azp": "client-123"},
			claim:  "azp",
			want:   "client-123",
		},
		{
			name: "nested client id claim",
			claims: map[string]any{
				"client": map[string]any{"id": "nested-client"},
			},
			claim: "client.id",
			want:  "nested-client",
		},
		{
			name:        "claim not configured",
			claims:      map[string]any{"azp": "client-123"},
			wantErr:     ErrClientIDClaimNotConfigured,
			expectError: true,
		},
		{
			name:        "claim missing",
			claims:      map[string]any{"sub": "alice"},
			claim:       "azp",
			wantErr:     ErrClientIDClaimNotFound,
			expectError: true,
		},
		{
			name:        "claim not string",
			claims:      map[string]any{"azp": []string{"client-123"}},
			claim:       "azp",
			wantErr:     ErrClientIDClaimNotString,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := jwt.New()
			for k, v := range tt.claims {
				require.NoError(t, token.Set(k, v))
			}

			extractor := SubjectExtractor{ClientIDClaim: tt.claim}
			got, err := extractor.ClientIDFromToken(t.Context(), token)

			require.Equal(t, tt.want, got)
			if tt.expectError {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSubjectExtractorDoesNotAppendEmptyUsername(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("preferred_username", ""))

	extractor := SubjectExtractor{
		UserNameClaim: "preferred_username",
		RoleProvider:  staticRoleProvider{roles: []string{"role:admin"}},
	}

	subjects, roles, err := extractor.BuildSubjectFromToken(t.Context(), token, platformauthz.RoleRequest{}, false)
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

	subjects, roles, err := extractor.BuildSubjectFromToken(t.Context(), token, platformauthz.RoleRequest{}, false)
	require.NoError(t, err)
	require.Equal(t, []string{"role:admin"}, subjects)
	require.Equal(t, []string{"role:admin"}, roles)
}

func TestSubjectExtractorIgnoresUsernameWithReservedClientPrefix(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("preferred_username", "client:kas-a"))

	extractor := SubjectExtractor{
		UserNameClaim: "preferred_username",
		RoleProvider:  staticRoleProvider{roles: []string{"role:admin"}},
	}

	subjects, roles, err := extractor.BuildSubjectFromToken(t.Context(), token, platformauthz.RoleRequest{}, false)
	require.NoError(t, err)
	// username "client:kas-a" must not appear in subjects because it uses the reserved client: prefix
	require.Equal(t, []string{"role:admin"}, subjects)
	require.Equal(t, []string{"role:admin"}, roles)
	for _, s := range subjects {
		require.NotEqual(t, "client:kas-a", s, "username with reserved client prefix must not be included in subjects")
	}
}
