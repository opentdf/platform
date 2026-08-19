package audit

import "context"

// Context key type for audit context
type (
	contextKey      struct{}
	actorContextKey struct{}
)

type auditContext struct {
	data   ContextData
	logger *Logger
}

func ContextWithActorID(ctx context.Context, actorID string) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actorID)
}

// Detach returns a non-canceling context carrying the current request values.
//
// Deprecated: Record detaches audit handoff from request cancellation.
func (a *Logger) Detach(ctx context.Context) context.Context {
	return context.WithoutCancel(ctx)
}
