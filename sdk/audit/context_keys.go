package audit

type AuditContextKey string

const (
	RequestIDContextKey AuditContextKey = "request-id"
	RequestIPContextKey AuditContextKey = "request-ip"
	UserAgentContextKey AuditContextKey = "user-agent"
	ActorIDContextKey   AuditContextKey = "actor-id"
)
