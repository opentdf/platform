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
	EventMetaData auditEventMetadata `json:"eventMetaData" audit:"extensible"`
	ClientInfo    eventClientInfo    `json:"clientInfo"`

	Original  map[string]any `json:"original,omitempty" audit:"extensible"`
	Updated   map[string]any `json:"updated,omitempty" audit:"extensible"`
	RequestID uuid.UUID      `json:"requestID" audit:"reserved"`
	Timestamp string         `json:"timestamp" audit:"reserved"`
}

func (e EventObject) LogValue() slog.Value {
	return slog.AnyValue(e.emittedPayloadMap())
}

func (e EventObject) emittedPayloadMap() map[string]any {
	entry, ok := normalizeAuditValue(e).(map[string]any)
	if !ok {
		panic("normalized audit payload must be a map")
	}
	return entry
}

// event.object
type auditEventObject struct {
	Type       ObjectType            `json:"type" audit:"reserved"`
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
	Type   ActionType   `json:"type" audit:"reserved"`
	Result ActionResult `json:"result" audit:"reserved"`
}

func (e eventAction) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("type", e.Type.String()),
		slog.String("result", e.Result.String()))
}

// event.actor
type auditEventActor struct {
	ID         string `json:"id" audit:"reserved"`
	Attributes []any  `json:"attributes"`
}

func (e auditEventActor) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.Any("attributes", e.Attributes))
}

// event.clientInfo
type eventClientInfo struct {
	UserAgent string `json:"userAgent" audit:"reserved"`
	Platform  string `json:"platform" audit:"reserved"`
	RequestIP string `json:"requestIP" audit:"reserved"`
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
