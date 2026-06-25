package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextWithClaims(t *testing.T) {
	groups := []string{"role:admin", "role:standard"}
	ctx := ContextWithClaims(t.Context(), RequestClaims{
		Subject:  "user@example.com",
		Groups:   groups,
		ClientID: "client-123",
	})

	groups[0] = "mutated"

	claims, ok := ClaimsFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, "user@example.com", claims.Subject)
	require.Equal(t, []string{"role:admin", "role:standard"}, claims.Groups)
	require.Equal(t, "client-123", claims.ClientID)

	claims.Groups[0] = "mutated"

	claims, ok = ClaimsFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, []string{"role:admin", "role:standard"}, claims.Groups)

	got, ok := GroupsFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, []string{"role:admin", "role:standard"}, got)

	subject, ok := SubjectFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, "user@example.com", subject)

	clientID, ok := ClientIDFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, "client-123", clientID)

	got[0] = "mutated"

	got, ok = GroupsFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, []string{"role:admin", "role:standard"}, got)
}

func TestGroupsFromContextMissing(t *testing.T) {
	got, ok := GroupsFromContext(t.Context())
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
		Groups:  []string{"role:admin"},
	})

	ctx = ContextWithClientID(ctx, "client-123")

	claims, ok := ClaimsFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, "user@example.com", claims.Subject)
	require.Equal(t, []string{"role:admin"}, claims.Groups)
	require.Equal(t, "client-123", claims.ClientID)
}
