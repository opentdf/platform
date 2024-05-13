package logger

import (
	"time"

	"github.com/google/uuid"
)

type auditLogAttributes struct {
	Attrs       map[string]interface{} `json:"attrs"`
	Dissem      map[string]interface{} `json:"dissem"`
	Permissions map[string]interface{} `json:"permissions"`
}

type auditLogObject struct {
	Type       string             `json:"type"`
	ID         string             `json:"id"`
	Attributes auditLogAttributes `json:"attributes"`
}

type auditLogAction struct {
	Type   string `json:"type"`
	Result string `json:"result"`
}

type auditLogActor struct {
	ID         string             `json:"id"`
	Attributes auditLogAttributes `json:"attributes"`
}

type auditLogClientInfo struct {
	UserAgent string `json:"userAgent"`
	Platform  string `json:"platform"`
	RequestIP string `json:"requestIp"`
}

type AuditLog struct {
	ID            string                 `json:"id"`
	Object        auditLogObject         `json:"object"`
	Action        auditLogAction         `json:"action"`
	Actor         auditLogActor          `json:"actor"`
	EventMetaData map[string]interface{} `json:"eventMetaData"`
	ClientInfo    auditLogClientInfo     `json:"clientInfo"`
	Diff          map[string]interface{} `json:"diff"`
	Timestamp     string                 `json:"timestamp"`
}

func NewAuditLog() AuditLog {
	return AuditLog{
		ID: uuid.NewString(),
		Object: auditLogObject{
			Type: "data_object",
			// ID: policyId?
			Attributes: auditLogAttributes{},
		},
		Action: auditLogAction{
			Type:   "read",
			Result: "success",
		},
		Actor: auditLogActor{
			// ID: "??"
			Attributes: auditLogAttributes{},
		},
		EventMetaData: map[string]interface{}{},
		ClientInfo: auditLogClientInfo{
			UserAgent: "",
			Platform:  "kas",
			RequestIP: "",
		},
		Diff:      map[string]interface{}{},
		Timestamp: time.Now().Format(time.RFC3339),
	}
}
