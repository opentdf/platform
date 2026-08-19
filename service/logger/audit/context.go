package audit

import (
	"context"
	"sync"
)

// Context key type for audit context
type (
	contextKey      struct{}
	actorContextKey struct{}
)

// auditTransaction holds pending audit events to be logged on completion
type auditTransaction struct {
	ContextData
	events   []pendingEvent
	mu       sync.Mutex
	detached bool // true only when created by Detach; required by LogPolicyCRUD
}

func ContextWithActorID(ctx context.Context, actorID string) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actorID)
}

// Detach returns a non-canceling context with an independent copy of the current
// request's audit attribution. It does not copy pending audit events. Consumers
// can add cancellation appropriate to the detached work's lifecycle. Detached
// audit transactions must log policy events with LogPolicyCRUD; buffered audit
// methods are only valid for interceptor-owned transactions.
func (a *Logger) Detach(ctx context.Context) context.Context {
	tx := &auditTransaction{
		ContextData: GetAuditDataFromContext(ctx),
		events:      make([]pendingEvent, 0),
		detached:    true,
	}

	return context.WithValue(context.WithoutCancel(ctx), contextKey{}, tx)
}
