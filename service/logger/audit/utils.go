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

type auditEventMetadata map[string]any

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
	Assertions  []string `json:"assertions,omitempty"`
	Attrs       []string `json:"attrs,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

func (e eventObjectAttributes) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("assertions", e.Assertions),
		slog.Any("attrs", e.Attrs),
		slog.Any("permissions", e.Permissions))
}

// event.action
type eventAction struct {
	Type   ActionType   `json:"type"`
	Result ActionResult `json:"result"`
}

func (e eventAction) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("type", e.Type.String()),
		slog.String("result", e.Result.String()))
}

// event.actor
type auditEventActor struct {
	ID         string `json:"id"`
	Attributes []any  `json:"attributes"`
}

func (e auditEventActor) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.Any("attributes", e.Attributes))
}

// event.clientInfo
type eventClientInfo struct {
	UserAgent string `json:"userAgent"`
	Platform  string `json:"platform"`
	RequestIP string `json:"requestIp"`
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
