package obligations

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/logger"
)

// A graph of action names to attribute value FQNs to lists of obligation value FQNs
// i.e. read : https://example.org/attr/attr1/value/val1 : [https://example.org/obl/some_obligation/value/some_value]
type obligationValuesByActionOnAnAttributeValue map[string]map[string][]string

type ObligationsPolicyDecisionPoint struct {
	logger                        *logger.Logger
	attributesByValueFQN          map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
	registeredResourceValuesByFQN map[string]*policy.RegisteredResourceValue
	obligationValuesByFQN         map[string]*policy.ObligationValue
	// When resolving triggered obligations, there are multiple trigger paths:
	// 1. actions on attributes
	// 2. actions on attributes within the request context of a specific PEP, driven by PEP idP clientID
	//
	// Both are able to be pre-computed from policy into a graph data structure so an actual PDP
	// trigger check can traverse in fastest possible time complexity.
	//
	// read : attrValFQN : []string{obl1}
	simpleTriggerActionsToAttributes obligationValuesByActionOnAnAttributeValue
	// pep-client : read : attrValFQN : []string{obl2}
	// other-pep-client : read : attrValFQN : []string{obl2,obl3}
	clientIDScopedTriggerActionsToAttributes map[string]obligationValuesByActionOnAnAttributeValue
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
		obligationValuesByFQN:         make(map[string]*policy.ObligationValue),
	}

	simpleTriggered := make(obligationValuesByActionOnAnAttributeValue)
	clientScopedTriggered := make(map[string]obligationValuesByActionOnAnAttributeValue)

	for _, definition := range allObligations {
		for _, obligationValue := range definition.GetValues() {
			pdp.obligationValuesByFQN[obligationValue.GetFqn()] = obligationValue

			for _, trigger := range obligationValue.GetTriggers() {
				attrValFqn := trigger.GetAttributeValue().GetFqn()
				actionName := trigger.GetAction().GetName()
				optionalPepClientID := "mock-client-id"
				// optionalPepClientID := trigger.GetContext().GetPep().GetClientId()

				// If the request context PEP client ID was provided to scope an obligation value to a PEP, populate that lookup graph
				if optionalPepClientID != "" {
					if _, ok := clientScopedTriggered[optionalPepClientID]; !ok {
						clientScopedTriggered[optionalPepClientID] = make(obligationValuesByActionOnAnAttributeValue)
					}
					if _, ok := clientScopedTriggered[optionalPepClientID][actionName]; !ok {
						clientScopedTriggered[optionalPepClientID][actionName] = make(map[string][]string)
					}
					clientScopedTriggered[optionalPepClientID][actionName][attrValFqn] = append(clientScopedTriggered[optionalPepClientID][actionName][attrValFqn], obligationValue.GetFqn())
				} else {
					// Otherwise, populate unscoped lookup graph with just actions and attributes alone
					if _, ok := simpleTriggered[actionName]; !ok {
						simpleTriggered[actionName] = make(map[string][]string)
					}
					simpleTriggered[actionName][attrValFqn] = append(simpleTriggered[actionName][attrValFqn], obligationValue.GetFqn())
				}
			}
		}
	}

	// Store lookup resolution graphs in state for the duration of the PDP
	pdp.clientIDScopedTriggerActionsToAttributes = clientScopedTriggered
	pdp.simpleTriggerActionsToAttributes = simpleTriggered

	pdp.logger.DebugContext(
		ctx,
		"created obligations policy decision point",
		slog.Int("obligation_values_count", len(pdp.obligationValuesByFQN)),
	)

	return pdp, nil
}

// GetRequiredObligations takes in an action and multiple resources subject to decisioning.
//
// It drills into the resources to find all triggered obligations on each combination of:
//  1. action
//  2. attribute value
//  3. decision request context (at present, strictly any scoped PEP clientID)
//
// In response, it returns the obligations required per each input resource index and the entire list of deduplicated required obligations
func (p *ObligationsPolicyDecisionPoint) GetRequiredObligations(
	ctx context.Context,
	action *policy.Action,
	resources []*authz.Resource,
	decisionRequestContext *mockDecisionRequestContext,
) ([][]string, []string, error) {
	// Required obligations per resource of a given index
	requiredOblValueFQNsPerResource := make([][]string, len(resources))
	// Set of required obligations across all resources
	allRequiredOblValueFQNs := make([]string, 0)
	allOblValFQNsSeen := make(map[string]struct{})

	pepClientID := decisionRequestContext.PEP.clientID

	l := p.logger.
		With("action", action.GetName()).
		With("pep_client_id", pepClientID).
		With("resources_count", strconv.Itoa(len(resources)))

	// Short-circuit if the requested action and optional scoping clientID are not found within any obligation triggers
	attrValueFQNsToObligations, triggersOnActionExist := p.simpleTriggerActionsToAttributes[action.GetName()]
	clientScoped, triggersOnClientIDExist := p.clientIDScopedTriggerActionsToAttributes[pepClientID]
	if triggersOnClientIDExist {
		_, triggersOnClientIDExist = clientScoped[action.GetName()]
	}
	if !triggersOnActionExist && !triggersOnClientIDExist {
		l.DebugContext(ctx, "no triggered obligations found for action")
		return nil, nil, nil
	}

	// Traverse trigger lookup graphs to resolve required obligations
	for i, resource := range resources {
		// For each type of resource, drill down within to collect the attribute value FQNs relevant to this action
		attrValueFQNs := []string{}
		switch resource.GetResource().(type) {
		case *authz.Resource_RegisteredResourceValueFqn:
			regResValFQN := resource.GetRegisteredResourceValueFqn()
			regResValue, ok := p.registeredResourceValuesByFQN[regResValFQN]
			if !ok {
				return nil, nil, fmt.Errorf("unknown registered resource value: %s", regResValFQN)
			}

			// Check the action-attribute-values associated with a Registered Resource Value for a match to the request action
			for _, aav := range regResValue.GetActionAttributeValues() {
				actionName := aav.GetAction().GetName()
				attrValFQN := aav.GetAttributeValue().GetFqn()
				if actionName != action.GetName() {
					continue
				}
				attrValueFQNs = append(attrValueFQNs, attrValFQN)
			}

		case *authz.Resource_AttributeValues_:
			attrValueFQNs = append(attrValueFQNs, resource.GetAttributeValues().GetFqns()...)

		default:
			return nil, nil, fmt.Errorf("unsupported resource type: %T", resource)
		}

		// With list of attribute values for the resource, traverse each lookup graph to resolve the Set of required obligations
		seenThisResource := make(map[string]struct{})
		resourceRequiredOblValueFQNsSet := make([]string, 0)
		for _, attrValFQN := range attrValueFQNs {
			if triggered, ok := attrValueFQNsToObligations[attrValFQN]; ok {
				for _, oblValFQN := range triggered {
					if _, ok := seenThisResource[oblValFQN]; ok {
						continue
					}
					// Update set of obligations triggered for this specific resource
					seenThisResource[oblValFQN] = struct{}{}
					resourceRequiredOblValueFQNsSet = append(resourceRequiredOblValueFQNsSet, oblValFQN)

					// Update global set tracking those triggered across all resources
					if _, seen := allOblValFQNsSeen[oblValFQN]; !seen {
						allOblValFQNsSeen[oblValFQN] = struct{}{}
						allRequiredOblValueFQNs = append(allRequiredOblValueFQNs, oblValFQN)
					}
				}
			}

			if triggered, ok := p.clientIDScopedTriggerActionsToAttributes[pepClientID][action.GetName()][attrValFQN]; ok {
				for _, oblValFQN := range triggered {
					if _, ok := seenThisResource[oblValFQN]; ok {
						continue
					}
					// Update set of obligations triggered for this specific resource
					seenThisResource[oblValFQN] = struct{}{}
					resourceRequiredOblValueFQNsSet = append(resourceRequiredOblValueFQNsSet, oblValFQN)

					// Update global set tracking those triggered across all resources
					if _, seen := allOblValFQNsSeen[oblValFQN]; !seen {
						allOblValFQNsSeen[oblValFQN] = struct{}{}
						allRequiredOblValueFQNs = append(allRequiredOblValueFQNs, oblValFQN)
					}
				}
			}
		}
		requiredOblValueFQNsPerResource[i] = resourceRequiredOblValueFQNsSet
	}

	l.DebugContext(
		ctx,
		"found required obligations",
		slog.Any("required_obl_values_per_resource", requiredOblValueFQNsPerResource),
		slog.Any("required_obligations_across_all_resources", allRequiredOblValueFQNs),
	)

	return requiredOblValueFQNsPerResource, allRequiredOblValueFQNs, nil
}

// TODO: pdp.GetObligationsFulfilled?
