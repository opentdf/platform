package logger

import (
	"github.com/google/uuid"
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
