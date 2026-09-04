package audit

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
)

// Common Strings
const (
	defaultNone = "None"
)

type EventMetaData map[string]any

type auditEventMetadata = EventMetaData

// EventObjectInfo describes the object an audited action was performed on.
type EventObjectInfo struct {
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
	Type   ActionType   `json:"type" audit:"reserved"`
	Result ActionResult `json:"result" audit:"reserved"`
}

type EventObjectActor struct {
	ID         string `json:"id" audit:"reserved"`
	Attributes []any  `json:"attributes"`
}

type EventClientInfo struct {
	UserAgent string `json:"userAgent" audit:"reserved"`
	Platform  string `json:"platform" audit:"reserved"`
	RequestIP string `json:"requestIP" audit:"reserved"`
}

type EventObjectParams struct {
	Object        EventObjectInfo
	Action        EventObjectAction
	Actor         EventObjectActor
	EventMetaData EventMetaData
	ClientInfo    EventClientInfo
	Original      map[string]any
	Updated       map[string]any
	RequestID     uuid.UUID
	Timestamp     string
}

// Phase identifies an event's position in an append-only operation lifecycle.
type Phase string

const (
	PhaseAttempted Phase = "attempted"
	PhaseCompleted Phase = "completed"
)

// Event is the canonical audit event passed to a Processor. Recorder metadata
// is excluded from the existing OpenTDF log payload.
type Event struct {
	Verb      Verb              `json:"-" audit:"-"`
	ID        uuid.UUID         `json:"-" audit:"-"`
	Phase     Phase             `json:"-" audit:"-"`
	Principal ctxAuth.Principal `json:"-" audit:"-"`

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

// EventObject is retained for compatibility with existing audit constructors.
type EventObject = Event

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

func (e Event) LogValue() slog.Value {
	return slog.AnyValue(e.emittedPayloadMap())
}

func (e Event) emittedPayloadMap() map[string]any {
	entry, ok := normalizeAuditValue(e).(map[string]any)
	if !ok {
		panic("normalized audit payload must be a map")
	}
	return entry
}

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

type eventObjectAttributes struct {
	EventObjectAttributes
}

func (e eventObjectAttributes) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("assertions", e.Assertions),
		slog.Any("attrs", e.Attrs),
		slog.Any("permissions", e.Permissions))
}

type eventAction struct {
	EventObjectAction
}

func (e eventAction) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("type", e.Type.String()),
		slog.String("result", e.Result.String()))
}

type auditEventActor struct {
	EventObjectActor
}

func (e auditEventActor) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.Any("attributes", e.Attributes))
}

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
	actorID, _ := ctx.Value(actorContextKey{}).(string)
	if principal, ok := ctxAuth.PrincipalFromContext(ctx); ok {
		actorID = principal.Subject
	}

	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	if ok && tx != nil {
		data := tx.ContextData
		if actorID != "" {
			data.ActorID = actorID
		}
		return data
	}
	return ContextData{
		RequestID: uuid.Nil,
		UserAgent: defaultNone,
		RequestIP: defaultNone,
		ActorID:   actorID,
	}
}
