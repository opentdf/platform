package authz

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
	"github.com/stretchr/testify/require"
)

type staticRoleProvider struct {
	roles []string
}

func (p staticRoleProvider) Roles(_ context.Context, _ jwt.Token, _ platformauthz.RoleRequest) ([]string, error) {
	return p.roles, nil
}

func newTestSubjectExtractor(t *testing.T, userNameClaim, clientIDClaim string, roleProvider platformauthz.RoleProvider) SubjectExtractor {
	t.Helper()

	extractor, err := NewSubjectExtractor(userNameClaim, clientIDClaim, roleProvider, logger.CreateTestLogger())
	require.NoError(t, err)
	return extractor
}

func TestNewSubjectExtractorRequiresLogger(t *testing.T) {
	extractor, err := NewSubjectExtractor("preferred_username", "azp", staticRoleProvider{}, nil)

	require.ErrorIs(t, err, ErrSubjectExtractorLogger)
	require.Zero(t, extractor)
}

func TestNewSubjectExtractorRequiresRoleProvider(t *testing.T) {
	extractor, err := NewSubjectExtractor("preferred_username", "azp", nil, logger.CreateTestLogger())

	require.ErrorIs(t, err, ErrSubjectExtractorRoles)
	require.Zero(t, extractor)
}

func TestSubjectExtractorGroupsClaimSupportsStringSlices(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("azp", "test-client"))
	require.NoError(t, token.Set("preferred_username", "alice"))
	require.NoError(t, token.Set("realm_access", map[string]any{
		"roles": []string{"opentdf-admin", "opentdf-standard"},
	}))

	log := logger.CreateTestLogger()
	extractor, err := NewSubjectExtractor("preferred_username", "azp", NewJWTClaimsRoleProvider("realm_access.roles", log), log)
	require.NoError(t, err)

	subjects, roles, err := extractor.BuildV1SubjectsFromToken(t.Context(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"opentdf-admin", "opentdf-standard", "alice"}, subjects)
	require.Equal(t, []string{"opentdf-admin", "opentdf-standard"}, roles)
}

func TestSubjectExtractorDoesNotAppendClientIDForV1(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("azp", "test-client"))
	require.NoError(t, token.Set("preferred_username", "alice"))

	extractor := newTestSubjectExtractor(t, "preferred_username", "azp", staticRoleProvider{roles: []string{"admin"}})

	subjects, roles, err := extractor.BuildV1SubjectsFromToken(t.Context(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"admin", "alice"}, subjects)
	require.Equal(t, []string{"admin"}, roles)
	require.NotContains(t, subjects, "test-client")
}

func TestSubjectExtractorBuildsV2TypedSubjects(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("azp", "test-client"))
	require.NoError(t, token.Set("preferred_username", "alice"))

	extractor := newTestSubjectExtractor(t, "preferred_username", "azp", staticRoleProvider{roles: []string{"admin", ""}})

	subjects, roles, err := extractor.BuildV2SubjectsFromToken(t.Context(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"client:test-client", "role:admin", "alice"}, subjects)
	require.Equal(t, []string{"role:admin"}, roles)
}

func TestSubjectExtractorPreservesEmptyRolesForV1(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("preferred_username", "alice"))

	extractor := newTestSubjectExtractor(t, "preferred_username", "", staticRoleProvider{roles: []string{"admin", "", "viewer"}})

	subjects, roles, err := extractor.BuildV1SubjectsFromToken(t.Context(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"admin", "", "viewer", "alice"}, subjects)
	require.Equal(t, []string{"admin", "", "viewer"}, roles)
}

func TestSubjectExtractorRequiresTokenWhenClaimsAreNotCached(t *testing.T) {
	extractor := newTestSubjectExtractor(t, "preferred_username", "azp", staticRoleProvider{roles: []string{"admin"}})

	subjects, roles, err := extractor.BuildV2SubjectsFromToken(t.Context(), nil, platformauthz.RoleRequest{})

	require.ErrorIs(t, err, ErrTokenRequired)
	require.Nil(t, subjects)
	require.Nil(t, roles)
}

func TestSubjectExtractorClientIDFromNilToken(t *testing.T) {
	extractor := newTestSubjectExtractor(t, "", "azp", staticRoleProvider{})

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

			extractor := newTestSubjectExtractor(t, "", tt.claim, staticRoleProvider{})
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

func TestSubjectExtractorPreservesEmptyUsernameForV1(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("preferred_username", ""))

	extractor := newTestSubjectExtractor(t, "preferred_username", "", staticRoleProvider{roles: []string{"role:admin"}})

	subjects, roles, err := extractor.BuildV1SubjectsFromToken(t.Context(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"role:admin", ""}, subjects)
	require.Equal(t, []string{"role:admin"}, roles)
}

func TestSubjectExtractorPreservesRolePrefixedUsernameForV1(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("preferred_username", "role:admin"))

	extractor := newTestSubjectExtractor(t, "preferred_username", "", staticRoleProvider{roles: []string{"viewer"}})

	subjects, roles, err := extractor.BuildV1SubjectsFromToken(t.Context(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"viewer", "role:admin"}, subjects)
	require.Equal(t, []string{"viewer"}, roles)
}

func TestSubjectExtractorPreservesClientPrefixedUsernameForV1(t *testing.T) {
	token := jwt.New()
	require.NoError(t, token.Set("preferred_username", "client:kas-a"))

	extractor := newTestSubjectExtractor(t, "preferred_username", "", staticRoleProvider{roles: []string{"admin"}})

	subjects, roles, err := extractor.BuildV1SubjectsFromToken(t.Context(), token, platformauthz.RoleRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"admin", "client:kas-a"}, subjects)
	require.Equal(t, []string{"admin"}, roles)
}

func TestSubjectExtractorSkipsReservedNamespaceUsernameForV2(t *testing.T) {
	tests := []struct {
		name     string
		username string
	}{
		{
			name:     "role prefix",
			username: "role:username-admin",
		},
		{
			name:     "client prefix",
			username: "client:kas-a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := jwt.New()
			require.NoError(t, token.Set("azp", "test-client"))
			require.NoError(t, token.Set("preferred_username", tt.username))

			extractor := newTestSubjectExtractor(t, "preferred_username", "azp", staticRoleProvider{roles: []string{"admin"}})

			subjects, roles, err := extractor.BuildV2SubjectsFromToken(t.Context(), token, platformauthz.RoleRequest{})
			require.NoError(t, err)
			require.Equal(t, []string{"client:test-client", "role:admin"}, subjects)
			require.Equal(t, []string{"role:admin"}, roles)
			require.NotContains(t, subjects, tt.username)
		})
	}
}
