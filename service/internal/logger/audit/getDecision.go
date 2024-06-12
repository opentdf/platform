package audit

import (
	"context"
	"fmt"
	"time"
)

type DecisionResult int

const (
	GetDecisionResultPermit DecisionResult = iota
	GetDecisionResultDeny
)

func (dr DecisionResult) String() string {
	return [...]string{
		"permit",
		"deny",
	}[dr]
}

type EntityChainEntitlement struct {
	EntityID                 string   `json:"entityId"`
	AttributeValueReferences []string `json:"attributeValueReferences"`
}

type GetDecisionEventParams struct {
	Decision                DecisionResult
	EntityChainId           string
	ResourceAttributeId     string
	EntityChainEntitlements []EntityChainEntitlement
}

func CreateGetDecisionEvent(ctx context.Context, params GetDecisionEventParams) (*EventObject, error) {
	auditDataFromContext := GetAuditDataFromContext(ctx)

	// Get result from decision
	result := ActionResultSuccess
	if params.Decision == GetDecisionResultDeny {
		result = ActionResultFailure
	}

	// Build the actor attributes for the event based off of the entity chain entitlements
	actorAttributes := make([]interface{}, len(params.EntityChainEntitlements))
	for i, v := range params.EntityChainEntitlements {
		actorAttributes[i] = struct {
			EntityID                 string   `json:"entityId"`
			AttributeValueReferences []string `json:"attributeValueReferences"`
		}{
			EntityID:                 v.EntityID,
			AttributeValueReferences: v.AttributeValueReferences,
		}
	}

	return &EventObject{
		Object: auditEventObject{
			Type: ObjectTypeEntityObject,
			ID:   fmt.Sprintf("%s-%s", params.EntityChainId, params.ResourceAttributeId),
		},
		Action: eventAction{
			Type:   ActionTypeRead,
			Result: result,
		},
		Actor: auditEventActor{
			ID:         params.EntityChainId,
			Attributes: actorAttributes,
		},
		// TODO: EventMetadata
		EventMetaData: map[string]string{},
		Owner:         CreateNilOwner(),
		ClientInfo: eventClientInfo{
			Platform:  "authorization",
			UserAgent: auditDataFromContext.UserAgent,
			RequestIP: auditDataFromContext.RequestIP,
		},
		RequestID: auditDataFromContext.RequestID,
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}
