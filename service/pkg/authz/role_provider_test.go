package authz

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func TestRolesFromTokenClaim(t *testing.T) {
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

			require.Equal(t, tt.want, RolesFromTokenClaim(token, tt.groupsClaim))
		})
	}
}
