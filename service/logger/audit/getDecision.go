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
	EntityCatagory           string   `json:"entityCatagory"`
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
	EntityChainID           string
	EntityDecisions         []EntityDecision
	ResourceAttributeID     string
	FQNs                    []string
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
			ID:   fmt.Sprintf("%s-%s", params.EntityChainID, params.ResourceAttributeID),
			Attributes: eventObjectAttributes{
				Attrs: params.FQNs,
			},
		},
		Action: eventAction{
			Type:   ActionTypeRead,
			Result: result,
		},
		Actor: auditEventActor{
			ID:         params.EntityChainID,
			Attributes: buildActorAttributes(params.EntityChainEntitlements),
		},
		EventMetaData: buildEventMetadata(params.EntityDecisions),
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
			EntityCategory           string   `json:"entityCategory"`
			AttributeValueReferences []string `json:"attributeValueReferences"`
		}{
			EntityID:                 v.EntityID,
			EntityCategory:           v.EntityCatagory,
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
