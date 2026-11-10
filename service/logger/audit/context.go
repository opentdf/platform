package audit

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// Context key type for audit context
type contextKey struct{}

// auditTransaction holds pending audit events to be logged on completion
type auditTransaction struct {
	ContextData
	events []pendingEvent
	mu     sync.Mutex
}

func ContextWithActorID(ctx context.Context, actorID string) context.Context {
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	if !ok || tx == nil {
		tx = &auditTransaction{
			ContextData: ContextData{
				RequestID: uuid.Nil,
				UserAgent: defaultNone,
				RequestIP: defaultNone,
			},
			events: make([]pendingEvent, 0),
		}
		ctx = context.WithValue(ctx, contextKey{}, tx)
	}

	tx.ActorID = actorID
	return ctx
}
