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

	subjects, roles, err := extractor.BuildSubjectFromToken(t.Context(), token, platformauthz.RoleRequest{})
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

	subjects, roles, err := extractor.BuildSubjectFromToken(t.Context(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"client:test-client", "role:admin", "alice"}, subjects)
	require.Equal(t, []string{"role:admin"}, roles)
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

	subjects, roles, err := extractor.BuildSubjectFromToken(t.Context(), token, platformauthz.RoleRequest{})
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

	subjects, roles, err := extractor.BuildSubjectFromToken(t.Context(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"role:admin"}, subjects)
	require.Equal(t, []string{"role:admin"}, roles)
}
