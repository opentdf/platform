package logger

import (
	"time"

	"github.com/google/uuid"
)

type AuditPolicy struct {
	UUID uuid.UUID       `json:"uuid"`
	Body AuditPolicyBody `json:"body"`
}

type AuditPolicyBody struct {
	DataAttributes []AuditPolicySimpleAttribute `json:"dataAttributes"`
	Dissem         []string                     `json:"dissem"`
}

type AuditPolicySimpleAttribute struct {
	URI string `json:"attribute"`
}

type auditPolicyAttributes struct {
	Attrs       []string `json:"attrs"`
	Dissem      []string `json:"dissem"`
	Permissions []string `json:"permissions"` // only for user objects
}

type auditPolicyObject struct {
	Type       string                `json:"type"`
	ID         string                `json:"id"`
	Attributes auditPolicyAttributes `json:"attributes"`
}

type auditPolicyAction struct {
	Type   string `json:"type"`
	Result string `json:"result"`
}

type auditLogActor struct {
	ID         string                `json:"id"`
	Attributes auditPolicyAttributes `json:"attributes"`
}

type auditLogClientInfo struct {
	UserAgent string `json:"userAgent"`
	Platform  string `json:"platform"`
	RequestIP string `json:"requestIp"`
}

type AuditLog struct {
	ID            string                 `json:"id"`
	Object        auditPolicyObject      `json:"object"`
	Action        auditPolicyAction      `json:"action"`
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
		Object: auditPolicyObject{
			Type: "data_object",
			// ID: added from policy object
			Attributes: auditPolicyAttributes{},
		},
		Action: auditPolicyAction{
			Type:   "read",
			Result: actionResult,
		},
		Actor: auditLogActor{
			// ID: "??"
			Attributes: auditPolicyAttributes{},
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
