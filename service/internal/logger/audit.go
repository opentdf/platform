package logger

import (
	"time"

	"github.com/google/uuid"
)

type PolicyLog struct {
	UUID uuid.UUID  `json:"uuid"`
	Body PolicyBody `json:"body"`
}

type PolicyBody struct {
	DataAttributes []SimpleAttribute `json:"dataAttributes"`
	Dissem         []string          `json:"dissem"`
}

type SimpleAttribute struct {
	URI string `json:"attribute"`
}

type auditLogAttributes struct {
	Attrs       []string `json:"attrs"`
	Dissem      []string `json:"dissem"`
	Permissions []string `json:"permissions"` // only for user objects
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

func createAuditLogBase(isSuccess bool) AuditLog {
	actionResult := "success"
	if !isSuccess {
		actionResult = "failure"
	}

	return AuditLog{
		ID: uuid.NewString(),
		Object: auditLogObject{
			Type: "data_object",
			// ID: added from policy object
			Attributes: auditLogAttributes{},
		},
		Action: auditLogAction{
			Type:   "read",
			Result: actionResult,
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

func CreateRewrapAuditLog(policy PolicyLog, isSuccess bool) AuditLog {
	auditLog := createAuditLogBase(isSuccess)
	auditLog.Object.ID = policy.UUID.String()
	for _, value := range policy.Body.DataAttributes {
		auditLog.Object.Attributes.Attrs = append(auditLog.Object.Attributes.Attrs, value.URI)
	}
	auditLog.Object.Attributes.Dissem = policy.Body.Dissem
	return auditLog
}
