package obligations

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/logger"
)

var (
	ErrEmptyPEPClientID               = errors.New("trigger request context is optional but must contain PEP client ID")
	ErrUnknownRegisteredResourceValue = errors.New("unknown registered resource value")
	ErrUnsupportedResourceType        = errors.New("unsupported resource type")
)

// A graph of action names to attribute value FQNs to lists of obligation value FQNs
// i.e. read : https://example.org/attr/attr1/value/val1 : [https://example.org/obl/some_obligation/value/some_value]
type obligationValuesByActionOnAnAttributeValue map[string]map[string][]string

//nolint:revive // There are a growing number of PDP types, so keep the naming verbose
type ObligationsPolicyDecisionPoint struct {
	logger                        *logger.Logger
	attributesByValueFQN          map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
	registeredResourceValuesByFQN map[string]*policy.RegisteredResourceValue

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

type PerResourceDecision struct {
	// Whether or not all obligations triggered for the resource can be fulfilled by the caller
	ObligationsSatisfied bool
	// The Set of obligations required on this indexed resource
	RequiredObligationValueFQNs []string
}

type ObligationPolicyDecision struct {
	// Whether or not all the obligations that were triggered can be fulfilled by the caller
	AllObligationsSatisfied bool
	// The Set of obligations required across all resources in the decision
	RequiredObligationValueFQNs []string
	// The Set of obligations required on each indexed resource
	RequiredObligationValueFQNsPerResource []PerResourceDecision
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

	simpleTriggered := make(obligationValuesByActionOnAnAttributeValue)
	clientScopedTriggered := make(map[string]obligationValuesByActionOnAnAttributeValue)

	// For every trigger on every value on every obligation definition
	for _, definition := range allObligations {
		for _, obligationValue := range definition.GetValues() {
			for _, trigger := range obligationValue.GetTriggers() {
				attrValFqn := trigger.GetAttributeValue().GetFqn()
				actionName := trigger.GetAction().GetName()

				// Populate unscoped lookup graph with just actions and attributes alone
				if len(trigger.GetContext()) == 0 {
					if _, ok := simpleTriggered[actionName]; !ok {
						simpleTriggered[actionName] = make(map[string][]string)
					}
					simpleTriggered[actionName][attrValFqn] = append(simpleTriggered[actionName][attrValFqn], obligationValue.GetFqn())
				}

				// If trigger has a request context specified, PEP clientID will scope the obligation value to a specific PEP
				for _, optionalRequestContext := range trigger.GetContext() {
					requiredPEPClientID := optionalRequestContext.GetPep().GetClientId()

					if requiredPEPClientID == "" {
						return nil, ErrEmptyPEPClientID
					}
					if _, ok := clientScopedTriggered[requiredPEPClientID]; !ok {
						clientScopedTriggered[requiredPEPClientID] = make(obligationValuesByActionOnAnAttributeValue)
					}
					if _, ok := clientScopedTriggered[requiredPEPClientID][actionName]; !ok {
						clientScopedTriggered[requiredPEPClientID][actionName] = make(map[string][]string)
					}
					clientScopedTriggered[requiredPEPClientID][actionName][attrValFqn] = append(clientScopedTriggered[requiredPEPClientID][actionName][attrValFqn], obligationValue.GetFqn())
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
	)

	pdp.logger.TraceContext(
		ctx,
		"trigger relationships",
		slog.Any("simple", simpleTriggered),
		slog.Any("client_scoped", clientScopedTriggered),
	)

	return pdp, nil
}

// GetAllTriggeredObligationsAreFulfilled takes in:
//
// 1. resources
// 2. an action being taken
// 3. a decision request context
// 4. the obligation value FQNs a PEP is capable of fulfilling (self-reported)
//
// It will check the action, resources, and decision request context for the obligation values triggered,
// then compare the PEP fulfillable obligations against those that have been triggered as required.
func (p *ObligationsPolicyDecisionPoint) GetAllTriggeredObligationsAreFulfilled(
	ctx context.Context,
	resources []*authz.Resource,
	action *policy.Action,
	decisionRequestContext *policy.RequestContext,
	pepFulfillableObligationValueFQNs []string,
) (ObligationPolicyDecision, error) {
	perResourceTriggered, allTriggered, err := p.getTriggeredObligations(ctx, action, resources, decisionRequestContext)
	if err != nil {
		return ObligationPolicyDecision{}, err
	}

	perResourceDecisions, allFulfilled := p.rollupResourceObligationDecisions(ctx, action, perResourceTriggered, pepFulfillableObligationValueFQNs, decisionRequestContext)
	return ObligationPolicyDecision{
		AllObligationsSatisfied:                allFulfilled,
		RequiredObligationValueFQNs:            allTriggered,
		RequiredObligationValueFQNsPerResource: perResourceDecisions,
	}, nil
}

// rollupResourceObligationDecisions checks the per-resource list of triggered obligations against the PEP
// self-reported fulfillable obligations to validate the PEP can fulfill those triggered on each resource
//
// While this is a simple check now, enhancements in types of obligations and the fulfillment source of truth
// (such as a PEP registration or centralized config) will add complexity to this validation. The RequestContext
// itself may sometimes contain information that may fulfill the obligation in the future.
func (p *ObligationsPolicyDecisionPoint) rollupResourceObligationDecisions(
	ctx context.Context,
	action *policy.Action,
	perResourceTriggeredObligationValueFQNs [][]string,
	pepFulfillableObligationValueFQNs []string,
	decisionRequestContext *policy.RequestContext,
) ([]PerResourceDecision, bool) {
	log := loggerWithAttributes(p.logger, strings.ToLower(action.GetName()), decisionRequestContext.GetPep().GetClientId())

	fulfillable := make(map[string]struct{})
	for _, obligation := range pepFulfillableObligationValueFQNs {
		obligation = strings.ToLower(obligation)
		fulfillable[obligation] = struct{}{}
	}

	unfulfilledSeen := make(map[string]struct{})
	var unfulfilled []string
	results := make([]PerResourceDecision, len(perResourceTriggeredObligationValueFQNs))
	for i, resourceTriggeredObligations := range perResourceTriggeredObligationValueFQNs {
		allSatisfied := true
		for _, triggered := range resourceTriggeredObligations {
			triggered = strings.ToLower(triggered)
			if _, ok := fulfillable[triggered]; !ok {
				if _, seen := unfulfilledSeen[triggered]; !seen {
					unfulfilledSeen[triggered] = struct{}{}
					unfulfilled = append(unfulfilled, triggered)
				}
				allSatisfied = false
			}
		}
		results[i] = PerResourceDecision{
			ObligationsSatisfied:        allSatisfied,
			RequiredObligationValueFQNs: resourceTriggeredObligations,
		}
	}

	if len(unfulfilled) > 0 {
		log.DebugContext(
			ctx,
			"found triggered obligations not reported as fulfillable",
			slog.Any("unfulfilled_obligations", unfulfilled),
		)
		return results, false
	}

	log.DebugContext(
		ctx,
		"all triggered obligations reported as fulfillable",
	)

	return results, true
}

// getTriggeredObligations takes in an action and multiple resources subject to decisioning.
//
// It drills into the resources to find all triggered obligations on each combination of:
//  1. action
//  2. attribute value
//  3. decision request context (at present, strictly any scoped PEP clientID)
//
// In response, it returns the obligations required per each input resource index and the entire list of deduplicated required obligations
func (p *ObligationsPolicyDecisionPoint) getTriggeredObligations(
	ctx context.Context,
	action *policy.Action,
	resources []*authz.Resource,
	decisionRequestContext *policy.RequestContext,
) ([][]string, []string, error) {
	// Required obligations per resource of a given index
	requiredOblValueFQNsPerResource := make([][]string, len(resources))
	// Set of required obligations across all resources
	var allRequiredOblValueFQNs []string
	allOblValFQNsSeen := make(map[string]struct{})

	pepClientID := decisionRequestContext.GetPep().GetClientId()
	actionName := strings.ToLower(action.GetName())
	log := loggerWithAttributes(p.logger, actionName, pepClientID)

	// Short-circuit if the requested action and optional scoping clientID are not found within any obligation triggers
	attrValueFQNsToObligations, triggersOnActionExist := p.simpleTriggerActionsToAttributes[actionName]
	clientScoped, triggersOnClientIDExist := p.clientIDScopedTriggerActionsToAttributes[pepClientID]
	if triggersOnClientIDExist {
		_, triggersOnClientIDExist = clientScoped[actionName]
	}
	if !triggersOnActionExist && !triggersOnClientIDExist {
		log.DebugContext(
			ctx,
			"no triggered obligations found",
			slog.Int("resources_count", len(resources)),
		)
		return requiredOblValueFQNsPerResource, nil, nil
	}

	// Traverse trigger lookup graphs to resolve required obligations
	for i, resource := range resources {
		// For each type of resource, drill down within to collect the attribute value FQNs relevant to this action
		var attrValueFQNs []string
		switch resource.GetResource().(type) {
		case *authz.Resource_RegisteredResourceValueFqn:
			regResValFQN := strings.ToLower(resource.GetRegisteredResourceValueFqn())
			regResValue, ok := p.registeredResourceValuesByFQN[regResValFQN]
			if !ok {
				return nil, nil, fmt.Errorf("%w: %s", ErrUnknownRegisteredResourceValue, regResValFQN)
			}

			// Check the action-attribute-values associated with a Registered Resource Value for a match to the request action
			for _, aav := range regResValue.GetActionAttributeValues() {
				aavActionName := aav.GetAction().GetName()
				attrValFQN := aav.GetAttributeValue().GetFqn()
				if aavActionName != actionName {
					continue
				}
				attrValueFQNs = append(attrValueFQNs, attrValFQN)
			}

		case *authz.Resource_AttributeValues_:
			attrValueFQNs = append(attrValueFQNs, resource.GetAttributeValues().GetFqns()...)

		default:
			return nil, nil, fmt.Errorf("%w: %T", ErrUnsupportedResourceType, resource)
		}

		// With list of attribute values for the resource, traverse each lookup graph to resolve the Set of required obligations
		seenThisResource := make(map[string]struct{})
		resourceRequiredOblValueFQNsSet := make([]string, 0)
		for _, attrValFQN := range attrValueFQNs {
			attrValFQN = strings.ToLower(attrValFQN)

			if triggeredObligations, someTriggered := attrValueFQNsToObligations[attrValFQN]; someTriggered {
				for _, oblValFQN := range triggeredObligations {
					if _, seen := seenThisResource[oblValFQN]; seen {
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

			if !triggersOnClientIDExist {
				continue
			}

			if triggeredObligations, someTriggered := clientScoped[actionName][attrValFQN]; someTriggered {
				for _, oblValFQN := range triggeredObligations {
					if _, seen := seenThisResource[oblValFQN]; seen {
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

	log.DebugContext(
		ctx,
		"found required obligations",
		slog.Any("deduplicated_request_obligations_across_all_resources", allRequiredOblValueFQNs),
	)
	log.TraceContext(
		ctx,
		"obligations per resource",
		slog.Any("required_obligations_per_resource", requiredOblValueFQNsPerResource),
	)

	return requiredOblValueFQNsPerResource, allRequiredOblValueFQNs, nil
}

func loggerWithAttributes(log *logger.Logger, actionName, pepClientID string) *logger.Logger {
	if pepClientID != "" {
		log = log.With("pep_client_id", pepClientID)
	}
	return log.With("action", strings.ToLower(actionName))
}
