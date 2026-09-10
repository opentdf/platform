package access

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/logger"
)

type hierarchyEntitlement struct {
	ranks   map[string]int
	highest int
}

func hierarchyRanks(definition *policy.Attribute) map[string]int {
	ranks := make(map[string]int, len(definition.GetValues()))
	for i, value := range definition.GetValues() {
		ranks[value.GetFqn()] = i
	}
	return ranks
}

func newHierarchyEntitlement(ctx context.Context, l *logger.Logger, definition *policy.Attribute, entitlements subjectmappingbuiltin.AttributeValueFQNsToActions, action *policy.Action, namespace string, namespaced bool, ranks map[string]int) *hierarchyEntitlement {
	if ranks == nil {
		ranks = hierarchyRanks(definition)
	}
	prepared := &hierarchyEntitlement{ranks: ranks, highest: len(definition.GetValues())}
	for fqn, actions := range entitlements {
		rank, found := ranks[fqn]
		if !found || rank >= prepared.highest {
			continue
		}
		for _, entitledAction := range actions {
			if isRequestedActionMatch(ctx, l, action, namespace, entitledAction, namespaced) {
				prepared.highest = rank
				break
			}
		}
	}
	return prepared
}

func (p *PolicyDecisionPoint) prepareHierarchyEntitlements(ctx context.Context, decisionable map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue, entitlements subjectmappingbuiltin.AttributeValueFQNsToActions, action *policy.Action) map[string]*hierarchyEntitlement {
	var prepared map[string]*hierarchyEntitlement
	for _, pair := range decisionable {
		definition := pair.GetAttribute()
		if definition.GetRule() != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
			continue
		}
		fqn := definition.GetFqn()
		if _, exists := prepared[fqn]; exists {
			continue
		}
		if prepared == nil {
			prepared = make(map[string]*hierarchyEntitlement)
		}
		prepared[fqn] = newHierarchyEntitlement(ctx, p.logger, definition, entitlements, action, definition.GetNamespace().GetFqn(), p.namespacedPolicy, p.hierarchyRanksByDefinition[fqn])
	}
	return prepared
}
