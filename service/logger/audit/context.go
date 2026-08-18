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
	detached bool // true only when created by Clone; required by LogPolicyCRUD
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

// Clone returns a non-canceling context with an independent copy of the current
// request's audit attribution. It does not copy pending audit events.
// Should be used by services that require auditing outside of the RPC lifecycle (Ex: asynch job worker)
func (a *Logger) Clone(ctx context.Context) context.Context {
	tx := &auditTransaction{
		ContextData: GetAuditDataFromContext(ctx),
		events:      make([]pendingEvent, 0),
		detached:    true,
	}

	return context.WithValue(context.WithoutCancel(ctx), contextKey{}, tx)
}
