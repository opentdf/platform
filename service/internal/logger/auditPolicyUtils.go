package logger

import (
	"context"
	"time"
)

type PolicyAttributeAuditEventParams struct {
	ActionType  string
	IsSuccess   bool
	AttributeID string
}

func CreatePolicyAttributeAuditEvent(ctx context.Context, params PolicyAttributeAuditEventParams) (*AuditEvent, error) {
	auditDataFromContext := GetAuditDataFromContext(ctx)

	auditEventActionResult := ActionResultError
	if params.IsSuccess {
		auditEventActionResult = ActionResultSuccess
	}

	return &AuditEvent{
		Object: auditEventObject{
			Type: "attribute_definition",
			ID:   params.AttributeID,
		},
		Action: auditEventAction{
			Type:   params.ActionType,
			Result: auditEventActionResult,
		},
		Actor: auditEventActor{
			ID:         auditDataFromContext.ActorID,
			Attributes: map[string]string{},
		},
		Owner: CreateNilOwner(),

		ClientInfo: auditEventClientInfo{
			Platform:  "policy",
			UserAgent: auditDataFromContext.UserAgent,
			RequestIP: auditDataFromContext.RequestIP,
		},
		RequestID: auditDataFromContext.RequestID,
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}
