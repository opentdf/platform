package audit

import "context"

type (
	contextKey      struct{}
	actorContextKey struct{}
)

func ContextWithActorID(ctx context.Context, actorID string) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actorID)
}
