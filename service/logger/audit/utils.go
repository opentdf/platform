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

// Event is the canonical, externally constructible audit event. Verb, ID,
// Phase, and Principal are recorder metadata; the compatibility encoder keeps
// them out of the existing OpenTDF wire payload.
type Event struct {
	Verb          Verb              `json:"-"`
	ID            uuid.UUID         `json:"-"`
	Phase         Phase             `json:"-"`
	Principal     ctxAuth.Principal `json:"-"`
	Object        Object            `json:"object"`
	Action        Action            `json:"action"`
	Actor         Actor             `json:"actor"`
	EventMetaData EventMetadata     `json:"eventMetaData" audit:"extensible"`
	ClientInfo    ClientInfo        `json:"clientInfo"`

	Original  map[string]any `json:"original,omitempty" audit:"extensible"`
	Updated   map[string]any `json:"updated,omitempty" audit:"extensible"`
	RequestID uuid.UUID      `json:"requestID" audit:"reserved"`
	Timestamp string         `json:"timestamp" audit:"reserved"`
}

// EventObject is retained as an alias for source compatibility.
//
// Deprecated: use Event.
type EventObject = Event

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

// Object identifies the resource affected by an audit action.
type Object struct {
	Type       string           `json:"type" audit:"reserved"`
	ID         string           `json:"id"`
	Name       string           `json:"name,omitempty"`
	Attributes ObjectAttributes `json:"attributes,omitempty"`
}

type auditEventObject = Object

func (e Object) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("type", e.Type),
		slog.String("id", e.ID),
		slog.String("name", e.Name),
		slog.Any("attributes", e.Attributes))
}

// ObjectAttributes contains optional policy attributes for a resource.
type ObjectAttributes struct {
	Assertions  []string `json:"assertions"`
	Attrs       []string `json:"attrs"`
	Permissions []string `json:"permissions"`
}

type eventObjectAttributes = ObjectAttributes

func (e ObjectAttributes) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("assertions", e.Assertions),
		slog.Any("attrs", e.Attrs),
		slog.Any("permissions", e.Permissions))
}

// Action describes the operation and its result.
type Action struct {
	Type   string `json:"type" audit:"reserved"`
	Result string `json:"result" audit:"reserved"`
}

type eventAction = Action

func (e Action) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("type", e.Type),
		slog.String("result", e.Result))
}

// Actor identifies the subject of the audited action. For authorization
// decisions this may differ from the authenticated requester in Principal.
type Actor struct {
	ID         string `json:"id" audit:"reserved"`
	Attributes []any  `json:"attributes"`
}

type auditEventActor = Actor

func (e Actor) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.Any("attributes", e.Attributes))
}

// ClientInfo describes the client and service recording the event.
type ClientInfo struct {
	UserAgent string `json:"userAgent" audit:"reserved"`
	Platform  string `json:"platform" audit:"reserved"`
	RequestIP string `json:"requestIP" audit:"reserved"`
}

type eventClientInfo = ClientInfo

func (e ClientInfo) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("userAgent", e.UserAgent),
		slog.String("platform", e.Platform),
		slog.String("requestIP", e.RequestIP))
}

// EventMetadata contains service-specific audit details.
type EventMetadata map[string]any

type auditEventMetadata = EventMetadata

// Phase identifies an append-only event's lifecycle position.
type Phase string

const (
	PhaseAttempted Phase = "attempted"
	PhaseCompleted Phase = "completed"
)

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

	auditCtx, ok := ctx.Value(contextKey{}).(auditContext)
	if ok {
		data := auditCtx.data
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
