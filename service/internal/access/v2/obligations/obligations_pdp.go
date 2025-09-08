package obligations

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/logger"
)

type ObligationsPolicyDecisionPoint struct {
	logger                        *logger.Logger
	attributesByValueFQN          map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
	registeredResourceValuesByFQN map[string]*policy.RegisteredResourceValue
	obligationValuesByFQN         map[string]*policy.ObligationValue
}

func NewObligationsPolicyDecisionPoint(
	ctx context.Context,
	l *logger.Logger,
	attributesByValueFQN map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	registeredResourceValuesByFQN map[string]*policy.RegisteredResourceValue,
	allObligations []*policy.Obligation,
) (*ObligationsPolicyDecisionPoint, error) {
	pdp := &ObligationsPolicyDecisionPoint{
		logger:                        l,
		attributesByValueFQN:          attributesByValueFQN,
		registeredResourceValuesByFQN: registeredResourceValuesByFQN,
	}

	for _, definition := range allObligations {
		for _, value := range definition.GetValues() {
			pdp.obligationValuesByFQN[value.GetValue()] = value
		}
	}

	return pdp, nil
}
