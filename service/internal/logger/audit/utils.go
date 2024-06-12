package audit

import (
	"context"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	"github.com/wI2L/jsondiff"
)

type auditContextKey string

// Header Values
const (
	UserAgentHeaderKey = "user-agent"
)

// Context Keys
const (
	UserAgentContextKey auditContextKey = "user-agent"
	RequestIDContextKey auditContextKey = "request-id"
	ActorIDContextKey   auditContextKey = "actor-id"
)

// Common Strings
const (
	DefaultNone = "None"
)

// event
type EventObject struct {
	Object        auditEventObject `json:"object"`
	Action        eventAction      `json:"action"`
	Owner         EventOwner       `json:"owner"`
	Actor         auditEventActor  `json:"actor"`
	EventMetaData interface{}      `json:"eventMetaData"`
	ClientInfo    eventClientInfo  `json:"clientInfo"`

	Diff      []DiffEntry `json:"diff,omitempty"`
	RequestID uuid.UUID   `json:"requestId"`
	Timestamp string      `json:"timestamp"`
}

// event.object
type auditEventObject struct {
	Type       ObjectType            `json:"type"`
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Attributes eventObjectAttributes `json:"attributes"`
}

// event.object.attributes
type eventObjectAttributes struct {
	Assertions  []string `json:"assertions"`
	Attrs       []string `json:"attrs"`
	Permissions []string `json:"permissions"`
}

// event.action
type eventAction struct {
	Type   ActionType   `json:"type"`
	Result ActionResult `json:"result"`
}

// event.owner
type EventOwner struct {
	ID    uuid.UUID `json:"id"`
	OrgID uuid.UUID `json:"orgId"`
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

type ContextData struct {
	RequestID uuid.UUID
	UserAgent string
	RequestIP string
	ActorID   string
}

func GetAuditDataFromContext(ctx context.Context) ContextData {
	// Extract the request ID from context
	requestID, requestIDOk := ctx.Value(RequestIDContextKey).(uuid.UUID)
	if !requestIDOk {
		requestID = uuid.Nil
	}

	// Extract user agent from context
	userAgent, userAgentOK := ctx.Value(UserAgentContextKey).(string)
	if !userAgentOK {
		userAgent = DefaultNone
	}

	// Extract actor ID from context
	actorID, actorIDOK := ctx.Value(ActorIDContextKey).(string)
	if !actorIDOK || actorID == "" {
		actorID = DefaultNone
	}

	// Extract request IP from context
	requestIPString := DefaultNone
	requestIP, ipOK := realip.FromContext(ctx)
	if ipOK {
		requestIPString = requestIP.String()
	}

	return ContextData{
		RequestID: requestID,
		UserAgent: userAgent,
		RequestIP: requestIPString,
		ActorID:   actorID,
	}
}

// Audit requires an "owner" field but that doesn't apply in the context of the
// platform. Therefore we just create a "nil" owner which has nil UUID fields.
func CreateNilOwner() EventOwner {
	return EventOwner{
		ID:    uuid.Nil,
		OrgID: uuid.Nil,
	}
}

type DiffEntry struct {
	Type  string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func createJSONPatchDiff(original []byte, target []byte) ([]DiffEntry, error) {
	patch, err := jsondiff.CompareJSON(original, target, jsondiff.Invertible())
	diffArray := make([]DiffEntry, len(patch))
	if err != nil {
		return nil, err
	}

	for i, item := range patch {
		diffArray[i] = DiffEntry{
			Type:  item.Type,
			Path:  item.Path,
			Value: item.Value,
		}
	}

	return diffArray, nil
}
