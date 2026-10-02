package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextWithActorIDWithoutInterceptor(t *testing.T) {
	ctx := ContextWithActorID(t.Context(), "test-actor-id")
	require.Equal(t, "test-actor-id", GetAuditDataFromContext(ctx).ActorID)
}

func TestContextWithActorIDDoesNotMutateAttribution(t *testing.T) {
	data := ContextData{ActorID: "existing-actor-id"}
	parent := context.WithValue(t.Context(), contextKey{}, data)
	child := ContextWithActorID(parent, "new-actor-id")
	require.Equal(t, "existing-actor-id", GetAuditDataFromContext(parent).ActorID)
	require.Equal(t, "new-actor-id", GetAuditDataFromContext(child).ActorID)
}
