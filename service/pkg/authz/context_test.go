package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextWithClaims(t *testing.T) {
	roles := []string{"role:admin", "role:standard"}
	ctx := ContextWithClaims(t.Context(), RequestClaims{
		Subject:  "user@example.com",
		Roles:    roles,
		ClientID: "client-123",
	})

	roles[0] = "mutated"

	claims, ok := ClaimsFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, "user@example.com", claims.Subject)
	require.Equal(t, []string{"role:admin", "role:standard"}, claims.Roles)
	require.Equal(t, "client-123", claims.ClientID)

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

	clientID, ok := ClientIDFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, "client-123", clientID)

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

	clientID, ok := ClientIDFromContext(t.Context())
	require.False(t, ok)
	require.Empty(t, clientID)
}

func TestContextWithClientIDPreservesExistingClaims(t *testing.T) {
	ctx := ContextWithClaims(t.Context(), RequestClaims{
		Subject: "user@example.com",
		Roles:   []string{"role:admin"},
	})

	ctx = ContextWithClientID(ctx, "client-123")

	claims, ok := ClaimsFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, "user@example.com", claims.Subject)
	require.Equal(t, []string{"role:admin"}, claims.Roles)
	require.Equal(t, "client-123", claims.ClientID)
}
