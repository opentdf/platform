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

type EntityDecision struct {
	EntityID     string   `json:"id"`
	Decision     string   `json:"decision"`
	Entitlements []string `json:"entitlements"`
}

type GetDecisionEventParams struct {
	Decision                DecisionResult
	EntityChainEntitlements []EntityChainEntitlement
	EntityChainId           string
	EntityDecisions         []EntityDecision
	ResourceAttributeId     string
}

func CreateGetDecisionEvent(ctx context.Context, params GetDecisionEventParams) (*EventObject, error) {
	auditDataFromContext := GetAuditDataFromContext(ctx)

	// Get result from decision
	result := ActionResultSuccess
	if params.Decision == GetDecisionResultDeny {
		result = ActionResultFailure
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
			Attributes: buildActorAttributes(params.EntityChainEntitlements),
		},
		EventMetaData: buildEventMetadata(params.EntityDecisions),
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

func buildActorAttributes(entityChainEntitlements []EntityChainEntitlement) []interface{} {
	actorAttributes := make([]interface{}, len(entityChainEntitlements))
	for i, v := range entityChainEntitlements {
		actorAttributes[i] = struct {
			EntityID                 string   `json:"entityId"`
			AttributeValueReferences []string `json:"attributeValueReferences"`
		}{
			EntityID:                 v.EntityID,
			AttributeValueReferences: v.AttributeValueReferences,
		}
	}
	return actorAttributes
}

func buildEventMetadata(entityDecisions []EntityDecision) interface{} {
	eventMetadata := struct {
		Entities []interface{} `json:"entities"`
	}{
		Entities: make([]interface{}, len(entityDecisions)),
	}

	for i, v := range entityDecisions {
		eventMetadata.Entities[i] = struct {
			EntityID     string   `json:"id"`
			Decision     string   `json:"decision"`
			Entitlements []string `json:"entitlements"`
		}{
			EntityID:     v.EntityID,
			Decision:     v.Decision,
			Entitlements: v.Entitlements,
		}
	}

	return eventMetadata
}
