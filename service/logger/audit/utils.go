package audit

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

// Common Strings
const (
	defaultNone = "None"
)

// Public event DTOs are intentionally separate from internal log types.
// This keeps downstream consumers decoupled from internal logging behavior (e.g. LogValue),
// while still allowing them to construct events via NewEvent.
type EventMetaData map[string]any

// Internal log type uses the same shape as public metadata.
type auditEventMetadata = EventMetaData

// --- Public event DTOs (for downstream consumers) ---

type EventObjectObject struct {
	Type       ObjectType            `json:"type"`
	ID         string                `json:"id"`
	Name       string                `json:"name,omitempty"`
	Attributes EventObjectAttributes `json:"attributes,omitempty"`
}

type EventObjectAttributes struct {
	Assertions  []string `json:"assertions,omitempty"`
	Attrs       []string `json:"attrs,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type EventObjectAction struct {
	Type   ActionType   `json:"type"`
	Result ActionResult `json:"result"`
}

type EventObjectActor struct {
	ID         string `json:"id"`
	Attributes []any  `json:"attributes"`
}

type EventClientInfo struct {
	UserAgent string `json:"userAgent"`
	Platform  string `json:"platform"`
	RequestIP string `json:"requestIp"`
}

type EventObjectParams struct {
	Object        EventObjectObject
	Action        EventObjectAction
	Actor         EventObjectActor
	EventMetaData EventMetaData
	ClientInfo    EventClientInfo
	Original      map[string]any
	Updated       map[string]any
	RequestID     uuid.UUID
	Timestamp     string
}

// --- Internal log types (used by logger/audit) ---

// event
type EventObject struct {
	Object        auditEventObject   `json:"object"`
	Action        eventAction        `json:"action"`
	Actor         auditEventActor    `json:"actor"`
	EventMetaData auditEventMetadata `json:"eventMetaData"`
	ClientInfo    eventClientInfo    `json:"clientInfo"`

	Original  map[string]any `json:"original,omitempty"`
	Updated   map[string]any `json:"updated,omitempty"`
	RequestID uuid.UUID      `json:"requestId"`
	Timestamp string         `json:"timestamp"`
}

// NewEvent converts public DTOs into the internal log event type.
func NewEvent(params EventObjectParams) *EventObject {
	return &EventObject{
		Object: auditEventObject{
			Type: params.Object.Type,
			ID:   params.Object.ID,
			Name: params.Object.Name,
			Attributes: eventObjectAttributes{
				EventObjectAttributes: params.Object.Attributes,
			},
		},
		Action: eventAction{
			EventObjectAction: params.Action,
		},
		Actor: auditEventActor{
			EventObjectActor: params.Actor,
		},
		EventMetaData: params.EventMetaData,
		ClientInfo: eventClientInfo{
			EventClientInfo: params.ClientInfo,
		},
		Original:  params.Original,
		Updated:   params.Updated,
		RequestID: params.RequestID,
		Timestamp: params.Timestamp,
	}
}

func (e EventObject) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("object", e.Object),
		slog.Any("action", e.Action),
		slog.Any("actor", e.Actor),
		slog.Any("eventMetaData", e.EventMetaData),
		slog.Any("clientInfo", e.ClientInfo),
		slog.Any("original", e.Original),
		slog.Any("updated", e.Updated),
		slog.String("requestID", e.RequestID.String()),
		slog.String("timestamp", e.Timestamp))
}

// event.object
type auditEventObject struct {
	Type       ObjectType            `json:"type"`
	ID         string                `json:"id"`
	Name       string                `json:"name,omitempty"`
	Attributes eventObjectAttributes `json:"attributes,omitempty"`
}

func (e auditEventObject) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("type", e.Type.String()),
		slog.String("id", e.ID),
		slog.String("name", e.Name),
		slog.Any("attributes", e.Attributes))
}

// event.object.attributes
type eventObjectAttributes struct {
	EventObjectAttributes
}

func (e eventObjectAttributes) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("assertions", e.Assertions),
		slog.Any("attrs", e.Attrs),
		slog.Any("permissions", e.Permissions))
}

// event.action
type eventAction struct {
	EventObjectAction
}

func (e eventAction) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("type", e.Type.String()),
		slog.String("result", e.Result.String()))
}

// event.actor
type auditEventActor struct {
	EventObjectActor
}

func (e auditEventActor) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.Any("attributes", e.Attributes))
}

// event.clientInfo
type eventClientInfo struct {
	EventClientInfo
}

func (e eventClientInfo) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("userAgent", e.UserAgent),
		slog.String("platform", e.Platform),
		slog.String("requestIP", e.RequestIP))
}

type ContextData struct {
	RequestID uuid.UUID
	UserAgent string
	RequestIP string
	ActorID   string
}

func (c ContextData) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("requestID", c.RequestID.String()),
		slog.String("userAgent", c.UserAgent),
		slog.String("requestIP", c.RequestIP),
		slog.String("actorID", c.ActorID))
}

// GetAuditDataFromContext gets relevant audit data from the context object
func GetAuditDataFromContext(ctx context.Context) ContextData {
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	if ok {
		return tx.ContextData
	}
	return ContextData{
		RequestID: uuid.Nil,
		UserAgent: defaultNone,
		RequestIP: defaultNone,
		ActorID:   defaultNone,
	}
}
