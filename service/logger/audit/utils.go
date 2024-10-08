package audit

import (
	"context"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
)

// Common Strings
const (
	defaultNone = "None"
)

// event
type EventObject struct {
	Object        auditEventObject `json:"object"`
	Action        eventAction      `json:"action"`
	Actor         auditEventActor  `json:"actor"`
	EventMetaData interface{}      `json:"eventMetaData"`
	ClientInfo    eventClientInfo  `json:"clientInfo"`
	Request       eventRequest     `json:"request"`

	Original  map[string]interface{} `json:"original,omitempty"`
	Updated   map[string]interface{} `json:"updated,omitempty"`
	Timestamp string                 `json:"timestamp"`
}

// event.object
type auditEventObject struct {
	Type       ObjectType            `json:"type"`
	ID         string                `json:"id"`
	Name       string                `json:"name,omitempty"`
	Attributes eventObjectAttributes `json:"attributes,omitempty"`
}

// event.object.attributes
type eventObjectAttributes struct {
	Assertions  []string `json:"assertions,omitempty"`
	Attrs       []string `json:"attrs,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// event.action
type eventAction struct {
	Type   ActionType   `json:"type"`
	Result ActionResult `json:"result"`
}

// event.actor
type auditEventActor struct {
	ID         string        `json:"id"`
	Attributes []interface{} `json:"attributes"`
}

// event.clientInfo
type eventClientInfo struct {
	UserAgent string `json:"userAgent"`
	Platform  string `json:"platform"`
	RequestIP string `json:"requestIp"`
}

type eventRequest struct {
	ID       uuid.UUID `json:"id"`
	Resource string    `json:"resource"`
}

type ContextData struct {
	RequestID       uuid.UUID
	UserAgent       string
	RequestIP       string
	ActorID         string
	RequestResource string
}

// Gets relevant audit data from the context object.
func GetAuditDataFromContext(ctx context.Context) ContextData {
	// Extract the request ID from context

	requestIDString, _ := ctx.Value(sdkAudit.RequestIDContextKey).(string)

	requestID, err := uuid.Parse(requestIDString)
	if err != nil {
		requestID = uuid.Nil
	}

	return ContextData{
		RequestID:       requestID,
		UserAgent:       getContextValue(ctx, sdkAudit.UserAgentContextKey),
		RequestIP:       getRequestIPFromContext(ctx),
		ActorID:         getContextValue(ctx, sdkAudit.ActorIDContextKey),
		RequestResource: getContextValue(ctx, sdkAudit.RequestResourceContextKey),
	}
}

// Gets a value from the context. If the value is not present or is an empty
// string, it returns the default value.
func getContextValue(ctx context.Context, key sdkAudit.ContextKey) string {
	value, ok := ctx.Value(key).(string)
	if !ok || value == "" {
		return defaultNone
	}
	return value
}

// Gets the request IP from the context. It first checks the context key, as we
// can pass the custom X-Forwarded-Request-IP header for internal requests. If
// that is not present, it falls back to the realip package.
func getRequestIPFromContext(ctx context.Context) string {
	requestIPFromContextKey, isOK := ctx.Value(sdkAudit.RequestIPContextKey).(string)
	if isOK {
		return requestIPFromContextKey
	}

	requestIPFromRealip, ipOK := realip.FromContext(ctx)
	if ipOK {
		return requestIPFromRealip.String()
	}

	return defaultNone
}
