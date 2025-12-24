package db

import "context"

type contextKey int

const (
	// contextKeyForcePrimary forces queries to use the primary database connection
	// even if read replicas are configured. This is useful for:
	// - Read-after-write scenarios where replication lag matters
	// - Transactions that need all operations on the same connection
	// - Critical reads that must see the latest data
	contextKeyForcePrimary contextKey = iota
)

// WithForcePrimary returns a context that forces database queries to use
// the primary connection instead of read replicas.
//
// Example:
//
//	// Write something
//	db.Exec(ctx, "INSERT INTO users ...")
//
//	// Immediately read it back (avoid replication lag)
//	ctx = db.WithForcePrimary(ctx)
//	row, _ := db.QueryRow(ctx, "SELECT * FROM users WHERE id = $1", []interface{}{id})
func WithForcePrimary(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyForcePrimary, true)
}

// shouldForcePrimary checks if the context requests primary-only routing
func shouldForcePrimary(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	val, ok := ctx.Value(contextKeyForcePrimary).(bool)
	return ok && val
}
