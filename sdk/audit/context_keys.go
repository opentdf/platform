package audit

type ContextKey string

const (
	RequestIDContextKey ContextKey = "request-id"
	RequestIPContextKey ContextKey = "request-ip"
	UserAgentContextKey ContextKey = "user-agent"
	ActorIDContextKey   ContextKey = "actor-id"
)

type RequestHeader string

const (
	UserAgentHeaderKey RequestHeader = "user-agent"
	RequestIDHeaderKey RequestHeader = "x-request-id"
	RequestIPHeaderKey RequestHeader = "x-forwarded-request-ip"
	ActorIDHeaderKey   RequestHeader = "x-forwarded-actor-id"
)
