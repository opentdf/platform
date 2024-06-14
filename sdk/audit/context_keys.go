package audit

type AuditContextKey string

const (
	RequestIDContextKey AuditContextKey = "request-id"
	RequestIPContextKey AuditContextKey = "request-ip"
	UserAgentContextKey AuditContextKey = "user-agent"
	ActorIDContextKey   AuditContextKey = "actor-id"
)

type RequestHeader string

const (
	UserAgentHeaderKey RequestHeader = "user-agent"
	RequestIDHeaderKey RequestHeader = "x-request-id"
	RequestIPHeaderKey RequestHeader = "x-forwarded-request-ip"
	ActorIDHeaderKey   RequestHeader = "x-forwarded-actor-id"
)
