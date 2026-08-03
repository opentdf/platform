package audit

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

var (
	// ErrNoTransaction indicates that the context is not managed by the audit interceptor.
	ErrNoTransaction = errors.New("audit transaction missing from context")
	// ErrTransactionClosed indicates that the request audit lifecycle has already completed.
	ErrTransactionClosed = errors.New("audit transaction already closed")
	// ErrInvalidEvent indicates that a recorded event is not valid.
	ErrInvalidEvent = errors.New("invalid audit event")
)

// RecordedEvent is the generic, externally constructible audit event recorded by
// injected services. String-valued types keep the upstream contract independent
// of service-specific object and action taxonomies.
type RecordedEvent struct {
	Object        RecordedObject     `json:"object"`
	Action        RecordedAction     `json:"action"`
	Actor         RecordedActor      `json:"actor"`
	EventMetaData map[string]any     `json:"eventMetaData" audit:"extensible"`
	ClientInfo    RecordedClientInfo `json:"clientInfo"`
	Original      map[string]any     `json:"original,omitempty" audit:"extensible"`
	Updated       map[string]any     `json:"updated,omitempty" audit:"extensible"`
	RequestID     uuid.UUID          `json:"requestID" audit:"reserved"`
	Timestamp     string             `json:"timestamp" audit:"reserved"`
}

type RecordedObject struct {
	Type       string                   `json:"type" audit:"reserved"`
	ID         string                   `json:"id"`
	Name       string                   `json:"name,omitempty"`
	Attributes RecordedObjectAttributes `json:"attributes,omitempty"`
}

type RecordedObjectAttributes struct {
	Assertions  []string `json:"assertions,omitempty"`
	Attrs       []string `json:"attrs,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type RecordedAction struct {
	Type   string `json:"type" audit:"reserved"`
	Result string `json:"result" audit:"reserved"`
}

type RecordedActor struct {
	ID         string `json:"id" audit:"reserved"`
	Attributes []any  `json:"attributes"`
}

type RecordedClientInfo struct {
	UserAgent string `json:"userAgent" audit:"reserved"`
	Platform  string `json:"platform" audit:"reserved"`
	RequestIP string `json:"requestIP" audit:"reserved"`
}

// Recorder records audit events in the current request transaction.
type Recorder interface {
	Record(context.Context, Verb, RecordedEvent) error
}

func cloneRecordedEvent(event RecordedEvent) RecordedEvent {
	cloned, ok := normalizeAuditValue(event).(map[string]any)
	if !ok {
		panic("normalized recorded audit event must be a map")
	}
	return recordedEventFromMap(cloned)
}

func recordedEventFromMap(event map[string]any) RecordedEvent {
	return RecordedEvent{
		Object: RecordedObject{
			Type:       nestedString(event, "object", "type"),
			ID:         nestedString(event, "object", "id"),
			Name:       nestedString(event, "object", "name"),
			Attributes: recordedObjectAttributesFromMap(nestedMap(event, "object", "attributes")),
		},
		Action: RecordedAction{
			Type:   nestedString(event, "action", "type"),
			Result: nestedString(event, "action", "result"),
		},
		Actor: RecordedActor{
			ID:         nestedString(event, "actor", "id"),
			Attributes: nestedAnySlice(event, "actor", "attributes"),
		},
		EventMetaData: nestedMap(event, "eventMetaData"),
		ClientInfo: RecordedClientInfo{
			UserAgent: nestedString(event, "clientInfo", "userAgent"),
			Platform:  nestedString(event, "clientInfo", "platform"),
			RequestIP: nestedString(event, "clientInfo", "requestIP"),
		},
		Original:  nestedMap(event, "original"),
		Updated:   nestedMap(event, "updated"),
		RequestID: nestedUUID(event, "requestID"),
		Timestamp: nestedString(event, "timestamp"),
	}
}

func recordedObjectAttributesFromMap(attributes map[string]any) RecordedObjectAttributes {
	return RecordedObjectAttributes{
		Assertions:  stringSlice(attributes["assertions"]),
		Attrs:       stringSlice(attributes["attrs"]),
		Permissions: stringSlice(attributes["permissions"]),
	}
}

func nestedMap(root map[string]any, path ...string) map[string]any {
	var current any = root
	for _, part := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	object, _ := current.(map[string]any)
	return object
}

func nestedString(root map[string]any, path ...string) string {
	var current any = root
	for _, part := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = object[part]
	}
	value, _ := current.(string)
	return value
}

func nestedAnySlice(root map[string]any, path ...string) []any {
	var current any = root
	for _, part := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	value, _ := current.([]any)
	return value
}

func nestedUUID(root map[string]any, path ...string) uuid.UUID {
	value := nestedString(root, path...)
	parsed, _ := uuid.Parse(value)
	return parsed
}

func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		if strings, stringsOK := value.([]string); stringsOK {
			return strings
		}
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if stringItem, stringOK := item.(string); stringOK {
			result = append(result, stringItem)
		}
	}
	return result
}

func recordedEventFromLegacy(event EventObject) RecordedEvent {
	return RecordedEvent{
		Object: RecordedObject{
			Type: event.Object.Type.String(),
			ID:   event.Object.ID,
			Name: event.Object.Name,
			Attributes: RecordedObjectAttributes{
				Assertions:  event.Object.Attributes.Assertions,
				Attrs:       event.Object.Attributes.Attrs,
				Permissions: event.Object.Attributes.Permissions,
			},
		},
		Action: RecordedAction{
			Type:   event.Action.Type.String(),
			Result: event.Action.Result.String(),
		},
		Actor: RecordedActor{
			ID:         event.Actor.ID,
			Attributes: event.Actor.Attributes,
		},
		EventMetaData: event.EventMetaData,
		ClientInfo: RecordedClientInfo{
			UserAgent: event.ClientInfo.UserAgent,
			Platform:  event.ClientInfo.Platform,
			RequestIP: event.ClientInfo.RequestIP,
		},
		Original:  event.Original,
		Updated:   event.Updated,
		RequestID: event.RequestID,
		Timestamp: event.Timestamp,
	}
}
