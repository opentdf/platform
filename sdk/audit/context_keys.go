package audit

type AuditContextKey string

const (
	RequestIDContextKey AuditContextKey = "request-id"
	UserAgentContextKey AuditContextKey = "user-agent"
	ActorIDContextKey   AuditContextKey = "actor-id"
)
