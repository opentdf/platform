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
	Object        auditEventObject   `json:"object" audit:"object"`
	Action        eventAction        `json:"action" audit:"action"`
	Actor         auditEventActor    `json:"actor" audit:"actor"`
	EventMetaData auditEventMetadata `json:"eventMetaData" audit:"eventMetaData,extensible"`
	ClientInfo    eventClientInfo    `json:"clientInfo" audit:"clientInfo"`

	Original  map[string]any `json:"original,omitempty" audit:"original,extensible"`
	Updated   map[string]any `json:"updated,omitempty" audit:"updated,extensible"`
	RequestID uuid.UUID      `json:"requestId" audit:"requestID,reserved"`
	Timestamp string         `json:"timestamp" audit:"timestamp,reserved"`
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

func (e EventObject) logMap() map[string]any {
	return map[string]any{
		"object": map[string]any{
			"type": e.Object.Type.String(),
			"id":   e.Object.ID,
			"name": e.Object.Name,
			"attributes": map[string]any{
				"assertions":  e.Object.Attributes.Assertions,
				"attrs":       e.Object.Attributes.Attrs,
				"permissions": e.Object.Attributes.Permissions,
			},
		},
		"action": map[string]any{
			"type":   e.Action.Type.String(),
			"result": e.Action.Result.String(),
		},
		"actor": map[string]any{
			"id":         e.Actor.ID,
			"attributes": e.Actor.Attributes,
		},
		"eventMetaData": normalizeAuditValue(e.EventMetaData),
		"clientInfo": map[string]any{
			"userAgent": e.ClientInfo.UserAgent,
			"platform":  e.ClientInfo.Platform,
			"requestIP": e.ClientInfo.RequestIP,
		},
		"original":  normalizeAuditValue(e.Original),
		"updated":   normalizeAuditValue(e.Updated),
		"requestID": e.RequestID.String(),
		"timestamp": e.Timestamp,
	}
}

// event.object
type auditEventObject struct {
	Type       ObjectType            `json:"type" audit:"type,reserved"`
	ID         string                `json:"id" audit:"id"`
	Name       string                `json:"name,omitempty" audit:"name"`
	Attributes eventObjectAttributes `json:"attributes,omitempty" audit:"attributes"`
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
	Type   ActionType   `json:"type" audit:"type,reserved"`
	Result ActionResult `json:"result" audit:"result,reserved"`
}

func (e eventAction) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("type", e.Type.String()),
		slog.String("result", e.Result.String()))
}

// event.actor
type auditEventActor struct {
	ID         string `json:"id" audit:"id,reserved"`
	Attributes []any  `json:"attributes" audit:"attributes"`
}

func (e auditEventActor) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.Any("attributes", e.Attributes))
}

// event.clientInfo
type eventClientInfo struct {
	UserAgent string `json:"userAgent" audit:"userAgent,reserved"`
	Platform  string `json:"platform" audit:"platform,reserved"`
	RequestIP string `json:"requestIp" audit:"requestIP,reserved"`
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
