package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextWithRoles(t *testing.T) {
	roles := []string{"role:admin", "role:standard"}
	ctx := ContextWithClaims(t.Context(), RequestClaims{
		Subject: "user@example.com",
		Roles:   roles,
	})

	roles[0] = "mutated"

	claims, ok := ClaimsFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, "user@example.com", claims.Subject)
	require.Equal(t, []string{"role:admin", "role:standard"}, claims.Roles)

	claims.Roles[0] = "mutated"

	claims, ok = ClaimsFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, []string{"role:admin", "role:standard"}, claims.Roles)

	got, ok := RolesFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, []string{"role:admin", "role:standard"}, got)

	subject, ok := SubjectFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, "user@example.com", subject)

	got[0] = "mutated"

	got, ok = RolesFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, []string{"role:admin", "role:standard"}, got)
}

func TestRolesFromContextMissing(t *testing.T) {
	got, ok := RolesFromContext(t.Context())
	require.False(t, ok)
	require.Nil(t, got)

	subject, ok := SubjectFromContext(t.Context())
	require.False(t, ok)
	require.Empty(t, subject)
}
