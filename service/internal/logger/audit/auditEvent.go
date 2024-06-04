package audit

import (
	"context"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
)

const (
	// Metadata Keys
	UserAgentHeaderKey  = "user-agent"
	UserAgentContextKey = "user-agent"
	RequestIDContextKey = "request-id"
	ActorIdContextKey   = "actor-id"

	// Action Types
	ActionTypeCreate = "create"
	ActionTypeUpdate = "update"
	ActionTypeDelete = "delete"

	// Action Results
	ActionResultSuccess = "success"
	ActionResultError   = "error"
)

// event
type AuditEvent struct {
	Object        auditEventObject     `json:"object"`
	Action        auditEventAction     `json:"action"`
	Owner         auditEventOwner      `json:"owner"`
	Actor         auditEventActor      `json:"actor"`
	EventMetaData map[string]string    `json:"eventMetaData"`
	ClientInfo    auditEventClientInfo `json:"clientInfo"`

	Diff      interface{} `json:"diff"`
	RequestID uuid.UUID   `json:"requestId"`
	Timestamp string      `json:"timestamp"`
}

// event.object
type auditEventObject struct {
	Type       string                     `json:"type"`
	ID         string                     `json:"id"`
	Name       string                     `json:"name"`
	Attributes auditEventObjectAttributes `json:"attributes"`
}

// event.object.attributes
type auditEventObjectAttributes struct {
	Assertions  []string `json:"assertions"`
	Attrs       []string `json:"attrs"`
	Permissions []string `json:"permissions"`
}

// event.action
type auditEventAction struct {
	Type   string `json:"type"`
	Result string `json:"result"`
}

// event.owner
type auditEventOwner struct {
	ID    uuid.UUID `json:"id"`
	OrgID uuid.UUID `json:"orgId"`
}

// event.actor
type auditEventActor struct {
	ID         string            `json:"id"`
	Attributes map[string]string `json:"attributes"`
}

// event.clientInfo
type auditEventClientInfo struct {
	UserAgent string `json:"userAgent"`
	Platform  string `json:"platform"`
	RequestIP string `json:"requestIp"`
}

type AuditDataFromContext struct {
	RequestID uuid.UUID
	UserAgent string
	RequestIP string
	ActorID   string
}

func GetAuditDataFromContext(ctx context.Context) AuditDataFromContext {
	// Extract the request ID from context
	requestID, requestIDOk := ctx.Value(RequestIDContextKey).(uuid.UUID)
	if !requestIDOk {
		requestID = uuid.Nil
	}

	// Extract user agent from context
	userAgent, userAgentOK := ctx.Value(UserAgentContextKey).(string)
	if !userAgentOK {
		userAgent = "None"
	}

	// Extract actor ID from context
	actorID, actorIDOK := ctx.Value(ActorIdContextKey).(string)
	if !actorIDOK || actorID == "" {
		actorID = "None"
	}

	// Extract request IP from context
	requestIPString := "None"
	requestIP, ipOK := realip.FromContext(ctx)
	if ipOK {
		requestIPString = requestIP.String()
	}

	return AuditDataFromContext{
		RequestID: requestID,
		UserAgent: userAgent,
		RequestIP: requestIPString,
		ActorID:   actorID,
	}
}

// Audit requires an "owner" field but that doesn't apply in the context of the
// platform. Therefore we just create a "nil" owner which has nil UUID fields.
func CreateNilOwner() auditEventOwner {
	return auditEventOwner{
		ID:    uuid.Nil,
		OrgID: uuid.Nil,
	}
}
