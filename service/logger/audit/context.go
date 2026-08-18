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
	events   []pendingEvent
	mu       sync.Mutex
	detached bool // true only when created by Detach; required by LogPolicyCRUD
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

// Detach returns a context with an independent copy of the current request's
// audit attribution. It does not copy pending audit events or alter the parent
// context's cancellation behavior.
func (a *Logger) Detach(ctx context.Context) context.Context {
	tx := &auditTransaction{
		ContextData: GetAuditDataFromContext(ctx),
		events:      make([]pendingEvent, 0),
		detached:    true,
	}

	return context.WithValue(ctx, contextKey{}, tx)
}
