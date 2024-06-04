package audit

import (
	"context"
	"time"
)

// Object Types for Policies
const (
	ObjectTypeSubjectMapping         = "subject_mapping"
	ObjectTypeResourceMapping        = "resource_mapping"
	ObjectTypeAttributeDefinition    = "attribute_definition"
	ObjectTypeAttributeValue         = "attribute_value"
	ObjectTypeNamespace              = "namespace"
	ObjectTypeConditionSet           = "condition_set"
	ObjectTypeKasRegistry            = "kas_registry"
	ObjectTypeKasAttributeAssignment = "kas_attribute_assignment"
)

type PolicyEventParams struct {
	ActionType string
	ObjectID   string
	ObjectType string
}

func CreatePolicyEvent(ctx context.Context, isSuccess bool, params PolicyEventParams) (*EventObject, error) {
	auditDataFromContext := GetAuditDataFromContext(ctx)

	auditEventActionResult := ActionResultError
	if isSuccess {
		auditEventActionResult = ActionResultSuccess
	}

	return &EventObject{
		Object: auditEventObject{
			Type: params.ObjectType,
			ID:   params.ObjectID,
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
