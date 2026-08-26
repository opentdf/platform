package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextWithActorIDSupportsBufferedAuditEvents(t *testing.T) {
	ctx := ContextWithActorID(t.Context(), "test-actor-id")

	require.NotPanics(t, func() {
		LogAuditEvent(ctx, VerbDecision, &EventObject{})
	})

	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	require.True(t, ok)
	require.Equal(t, "test-actor-id", tx.ActorID)
	require.Len(t, tx.events, 1)
}

func TestContextWithActorIDDoesNotMutateExistingTransaction(t *testing.T) {
	tx := &auditTransaction{
		ContextData: ContextData{ActorID: "existing-actor-id"},
		events:      make([]pendingEvent, 0),
	}
	ctx := context.WithValue(t.Context(), contextKey{}, tx)

	ctx = ContextWithActorID(ctx, "new-actor-id")

	require.Equal(t, "existing-actor-id", tx.ActorID)
	require.Equal(t, "new-actor-id", GetAuditDataFromContext(ctx).ActorID)
}
