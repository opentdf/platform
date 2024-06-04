package audit

import (
	"context"
	"time"
)

type PolicyAttributeAuditEventParams struct {
	ActionType  string
	IsSuccess   bool
	AttributeID string
}

func CreatePolicyAttributeAuditEvent(ctx context.Context, params PolicyAttributeAuditEventParams) (*EventObject, error) {
	auditDataFromContext := GetAuditDataFromContext(ctx)

	auditEventActionResult := ActionResultError
	if params.IsSuccess {
		auditEventActionResult = ActionResultSuccess
	}

	return &EventObject{
		Object: auditEventObject{
			Type: "attribute_definition",
			ID:   params.AttributeID,
		},
		Action: eventAction{
			Type:   params.ActionType,
			Result: auditEventActionResult,
		},
		Actor: auditEventActor{
			ID:         auditDataFromContext.ActorID,
			Attributes: map[string]string{},
		},
		Owner: CreateNilOwner(),

		ClientInfo: eventClientInfo{
			Platform:  "policy",
			UserAgent: auditDataFromContext.UserAgent,
			RequestIP: auditDataFromContext.RequestIP,
		},
		RequestID: auditDataFromContext.RequestID,
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}
