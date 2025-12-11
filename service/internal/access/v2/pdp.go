package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"

	"github.com/opentdf/platform/lib/identifier"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/logger"
)

// Decision represents the overall access decision for an entity.
type Decision struct {
	// AllPermitted means all entities requesting to take the action on the resource(s) were entitled
	// and that any triggered obligations were satisfied by those reported as fulfillable.
	// The struct tag remains 'access' for backwards compatibility within audit records.
	AllPermitted bool `json:"access" example:"false"`
	Results      []ResourceDecision
}

// ResourceDecision represents the result of evaluating the action on one resource for an entity.
type ResourceDecision struct {
	// An overall result representing a roll-up of ObligationsSatisfied && Entitled
	Passed bool `json:"passed" example:"false"`
	// FulfillableObligations >= TriggeredObligations
	ObligationsSatisfied        bool             `json:"obligations_satisfied" example:"false"`
	Entitled                    bool             `json:"entitled" example:"false"`
	ResourceID                  string           `json:"resource_id,omitempty"`
	ResourceName                string           `json:"resource_name,omitempty"`
	DataRuleResults             []DataRuleResult `json:"data_rule_results"`
	RequiredObligationValueFQNs []string         `json:"required_obligation_value_fqns"`
}

// DataRuleResult represents the result of evaluating one rule for an entity.
type DataRuleResult struct {
	Passed              bool                 `json:"passed" example:"false"`
	ResourceValueFQNs   []string             `json:"resource_value_fqns"`
	Attribute           *policy.Attribute    `json:"attribute"`
	EntitlementFailures []EntitlementFailure `json:"entitlement_failures"`
}

// EntitlementFailure represents a failure to satisfy an entitlement of the action on the attribute value.
type EntitlementFailure struct {
	AttributeValueFQN string `json:"attribute_value"`
	ActionName        string `json:"action"`
}

// PolicyDecisionPoint represents the Policy Decision Point component with all of policy passed in by the caller.
// All decisions and entitlements are evaluated against the in-memory policy.
type PolicyDecisionPoint struct {
	logger                             *logger.Logger
	allEntitleableAttributesByValueFQN map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
	allRegisteredResourceValuesByFQN   map[string]*policy.RegisteredResourceValue
	allAttributesByDefinitionFQN       map[string]*policy.Attribute
	allowDirectEntitlements            bool
}

var (
	defaultFallbackLoggerConfig = logger.Config{
		Level:  "info",
		Type:   "json",
		Output: "stdout",
	}
	ErrMissingRequiredPolicy = errors.New("access: both attribute definitions and subject mappings must be provided or neither")
)

// NewPolicyDecisionPoint creates a new Policy Decision Point instance.
// It is presumed that all Attribute Definitions and Subject Mappings are valid and contain the entirety of entitlement policy.
// Attribute Values without Subject Mappings will be ignored in decisioning.
func NewPolicyDecisionPoint(
	ctx context.Context,
	l *logger.Logger,
	allAttributeDefinitions []*policy.Attribute,
	allSubjectMappings []*policy.SubjectMapping,
	allRegisteredResources []*policy.RegisteredResource,
	allowDirectEntitlements bool,
) (*PolicyDecisionPoint, error) {
	var err error

	if l == nil {
		l, err = logger.NewLogger(defaultFallbackLoggerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize new PDP logger and none was provided: %w", err)
		}
	}

	if allAttributeDefinitions == nil || allSubjectMappings == nil {
		return nil, fmt.Errorf("invalid arguments: %w", ErrMissingRequiredPolicy)
	}

	// Build lookup maps to in-memory policy
	allAttributesByDefinitionFQN := make(map[string]*policy.Attribute)
	allEntitleableAttributesByValueFQN := make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	for _, attr := range allAttributeDefinitions {
		if err := validateAttribute(attr); err != nil {
			return nil, fmt.Errorf("invalid attribute definition: %w", err)
		}
		allAttributesByDefinitionFQN[attr.GetFqn()] = attr

		// Not every value may have a subject mapping and be entitleable, but a lookup must still be possible
		for _, value := range attr.GetValues() {
			mapped := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				Value:     value,
				Attribute: attr,
			}
			allEntitleableAttributesByValueFQN[value.GetFqn()] = mapped
		}
	}

	for _, sm := range allSubjectMappings {
		if err := validateSubjectMapping(sm); err != nil {
			l.WarnContext(ctx,
				"invalid subject mapping - skipping",
				slog.Any("subject_mapping", sm),
				slog.Any("error", err),
			)
			continue
		}
		mappedValue := sm.GetAttributeValue()
		mappedValueFQN := mappedValue.GetFqn()
		if _, ok := allEntitleableAttributesByValueFQN[mappedValueFQN]; ok {
			allEntitleableAttributesByValueFQN[mappedValueFQN].GetValue().SubjectMappings = append(allEntitleableAttributesByValueFQN[mappedValueFQN].GetValue().GetSubjectMappings(), sm)
			continue
		}
		// Take subject mapping's attribute value and its definition from memory
		parentDefinition, err := getDefinition(mappedValueFQN, allAttributesByDefinitionFQN)
		if err != nil {
			return nil, fmt.Errorf("failed to get attribute definition: %w", err)
		}
		mappedValue.SubjectMappings = []*policy.SubjectMapping{sm}
		mapped := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value:     mappedValue,
			Attribute: parentDefinition,
		}
		allEntitleableAttributesByValueFQN[mappedValueFQN] = mapped
	}

	allRegisteredResourceValuesByFQN := make(map[string]*policy.RegisteredResourceValue)
	for _, rr := range allRegisteredResources {
		if err := validateRegisteredResource(rr); err != nil {
			return nil, fmt.Errorf("invalid registered resource: %w", err)
		}
		rrName := rr.GetName()

		for _, v := range rr.GetValues() {
			if err := validateRegisteredResourceValue(v); err != nil {
				return nil, fmt.Errorf("invalid registered resource value: %w", err)
			}

			fullyQualifiedValue := identifier.FullyQualifiedRegisteredResourceValue{
				Name:  rrName,
				Value: v.GetValue(),
			}
			allRegisteredResourceValuesByFQN[fullyQualifiedValue.FQN()] = v
		}
	}

	pdp := &PolicyDecisionPoint{
		l,
		allEntitleableAttributesByValueFQN,
		allRegisteredResourceValuesByFQN,
		allAttributesByDefinitionFQN,
		allowDirectEntitlements,
	}
	return pdp, nil
}

// GetDecision evaluates the action on the resources for the entity and returns a decision along with entitlements.
func (p *PolicyDecisionPoint) GetDecision(
	ctx context.Context,
	entityRepresentation *entityresolutionV2.EntityRepresentation,
	action *policy.Action,
	resources []*authz.Resource,
) (*Decision, map[string][]*policy.Action, error) {
	l := p.logger.With("entity_id", entityRepresentation.GetOriginalId())
	l = l.With("action", action.GetName())
	l.DebugContext(ctx, "getting decision", slog.Int("resources_count", len(resources)))

	if err := validateGetDecision(entityRepresentation, action, resources); err != nil {
		return nil, nil, err
	}

	// Filter all attributes down to only those that relevant to the entitlement decisioning of these specific resources
	decisionableAttributes, err := getResourceDecisionableAttributes(ctx, l, p.allRegisteredResourceValuesByFQN, p.allEntitleableAttributesByValueFQN, p.allAttributesByDefinitionFQN /* action, */, resources, p.allowDirectEntitlements)
	if err != nil {
		if !errors.Is(err, ErrFQNNotFound) {
			return nil, nil, fmt.Errorf("error getting decisionable attributes: %w", err)
		}
		// Not an error: deny access to individual resources, not the entire request
		l.WarnContext(ctx, "encountered unknown FQN on resource", slog.Any("error", err))
	}
	l.DebugContext(ctx, "filtered to only entitlements relevant to decisioning", slog.Int("decisionable_attribute_values_count", len(decisionableAttributes)))

	// Resolve them to their entitled FQNs and the actions available on each
	entitledFQNsToActions, err := subjectmappingbuiltin.EvaluateSubjectMappingsWithActions(decisionableAttributes, entityRepresentation)
	if err != nil {
		return nil, nil, fmt.Errorf("error evaluating subject mappings for entitlement: %w", err)
	}
	l.DebugContext(ctx, "evaluated subject mappings", slog.Any("entitled_value_fqns_to_actions", entitledFQNsToActions))

	if p.allowDirectEntitlements {
		p.logger.DebugContext(ctx, "setting direct entitlements on entity representation",
			slog.Any("entity_id", entityRepresentation.GetOriginalId()),
		)

		for _, directEntitlement := range entityRepresentation.GetDirectEntitlements() {
			fqn := directEntitlement.GetAttributeValueFqn()
			actionNames := directEntitlement.GetActions()

			actions := make([]*policy.Action, len(actionNames))
			for i, name := range actionNames {
				actions[i] = &policy.Action{Name: name}
			}

			entitledFQNsToActions[fqn] = actions
		}
	}

	decision := &Decision{
		AllPermitted: true,
		Results:      make([]ResourceDecision, len(resources)),
	}

	for idx, resource := range resources {
		resourceDecision, err := getResourceDecision(ctx, l, decisionableAttributes, p.allRegisteredResourceValuesByFQN, entitledFQNsToActions, action, resource)
		if err != nil || resourceDecision == nil {
			return nil, nil, fmt.Errorf("error evaluating a decision on resource [%v]: %w", resource, err)
		}

		if !resourceDecision.Entitled {
			decision.AllPermitted = false
		}

		l.DebugContext(
			ctx,
			"resourceDecision result",
			slog.Bool("entitled", resourceDecision.Entitled),
			slog.String("resource_id", resourceDecision.ResourceID),
			slog.Int("data_rule_results_count", len(resourceDecision.DataRuleResults)),
		)
		decision.Results[idx] = *resourceDecision
	}

	return decision, entitledFQNsToActions, nil
}

func (p *PolicyDecisionPoint) GetDecisionRegisteredResource(
	ctx context.Context,
	entityRegisteredResourceValueFQN string,
	action *policy.Action,
	resources []*authz.Resource,
) (*Decision, map[string][]*policy.Action, error) {
	l := p.logger.With("entity_registered_resource_value_fqn", entityRegisteredResourceValueFQN)
	l = l.With("action", action.GetName())
	l.DebugContext(ctx, "getting decision", slog.Int("resources_count", len(resources)))

	if err := validateGetDecisionRegisteredResource(entityRegisteredResourceValueFQN, action, resources); err != nil {
		return nil, nil, err
	}

	entityRegisteredResourceValue, ok := p.allRegisteredResourceValuesByFQN[entityRegisteredResourceValueFQN]
	if !ok {
		return nil, nil, fmt.Errorf("registered resource value FQN not found in memory [%s]: %w", entityRegisteredResourceValueFQN, ErrInvalidResource)
	}

	// Filter all attributes down to only those that relevant to the entitlement decisioning of these specific resources
	decisionableAttributes, err := getResourceDecisionableAttributes(ctx, l, p.allRegisteredResourceValuesByFQN, p.allEntitleableAttributesByValueFQN, p.allAttributesByDefinitionFQN /*action, */, resources, p.allowDirectEntitlements)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting decisionable attributes: %w", err)
	}
	l.DebugContext(ctx, "filtered to only entitlements relevant to decisioning", slog.Int("decisionable_attribute_values_count", len(decisionableAttributes)))

	entitledFQNsToActions := make(map[string][]*policy.Action)
	for _, aav := range entityRegisteredResourceValue.GetActionAttributeValues() {
		aavAction := aav.GetAction()
		if action.GetName() != aavAction.GetName() {
			l.DebugContext(ctx, "skipping action not matching Decision Request action", slog.String("action_name", aavAction.GetName()))
			continue
		}

		attrVal := aav.GetAttributeValue()
		attrValFQN := attrVal.GetFqn()
		actionsList, actionsAreOK := entitledFQNsToActions[attrValFQN]
		if !actionsAreOK {
			actionsList = make([]*policy.Action, 0)
		}

		if !slices.ContainsFunc(actionsList, func(a *policy.Action) bool {
			return a.GetName() == aavAction.GetName()
		}) {
			actionsList = append(actionsList, aavAction)
		}

		entitledFQNsToActions[attrValFQN] = actionsList
	}

	decision := &Decision{
		AllPermitted: true,
		Results:      make([]ResourceDecision, len(resources)),
	}

	for idx, resource := range resources {
		resourceDecision, err := getResourceDecision(ctx, l, decisionableAttributes, p.allRegisteredResourceValuesByFQN, entitledFQNsToActions, action, resource)
		if err != nil || resourceDecision == nil {
			return nil, nil, fmt.Errorf("error evaluating a decision on resource [%v]: %w", resource, err)
		}
		if !resourceDecision.Entitled {
			decision.AllPermitted = false
		}

		l.DebugContext(
			ctx,
			"resourceDecision result",
			slog.Bool("entitled", resourceDecision.Entitled),
			slog.String("resource_id", resourceDecision.ResourceID),
			slog.Int("data_rule_results_count", len(resourceDecision.DataRuleResults)),
		)
		decision.Results[idx] = *resourceDecision
	}

	return decision, entitledFQNsToActions, nil
}

func (p *PolicyDecisionPoint) GetEntitlements(
	ctx context.Context,
	entityRepresentations []*entityresolutionV2.EntityRepresentation,
	optionalMatchedSubjectMappings []*policy.SubjectMapping,
	withComprehensiveHierarchy bool,
) ([]*authz.EntityEntitlements, error) {
	err := validateEntityRepresentations(entityRepresentations)
	if err != nil {
		return nil, fmt.Errorf("invalid input parameters: %w", err)
	}

	l := p.logger.With("with_comprehensive_hierarchy", strconv.FormatBool(withComprehensiveHierarchy))
	l.DebugContext(ctx, "getting entitlements", slog.Int("entity_representations_count", len(entityRepresentations)))

	var entitleableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue

	// Check entitlement only against the filtered matched subject mappings if provided
	if optionalMatchedSubjectMappings != nil {
		l.DebugContext(ctx, "filtering to provided matched subject mappings", slog.Int("matched_subject_mappings_count", len(optionalMatchedSubjectMappings)))
		entitleableAttributes, err = getFilteredEntitleableAttributes(optionalMatchedSubjectMappings, p.allEntitleableAttributesByValueFQN)
		if err != nil {
			return nil, fmt.Errorf("error filtering entitleable attributes from matched subject mappings: %w", err)
		}
	} else {
		// Otherwise, use all entitleable attributes
		l.DebugContext(ctx, "getting entitlements with all subject mappings (unmatched)")
		entitleableAttributes = p.allEntitleableAttributesByValueFQN
	}

	// Resolve them to their entitled FQNs and the actions available on each
	entityIDsToFQNsToActions, err := subjectmappingbuiltin.EvaluateSubjectMappingMultipleEntitiesWithActions(entitleableAttributes, entityRepresentations)
	if err != nil {
		return nil, fmt.Errorf("error evaluating subject mappings for entitlement: %w", err)
	}
	l.DebugContext(ctx, "evaluated subject mappings", slog.Any("entitlements_by_entity_id", entityIDsToFQNsToActions))

	var result []*authz.EntityEntitlements
	for entityID, fqnsToActions := range entityIDsToFQNsToActions {
		actionsPerAttributeValueFqn := make(map[string]*authz.EntityEntitlements_ActionsList)

		for valueFQN, actions := range fqnsToActions {
			// If already entitled (such as via a higher entitled comprehensive hierarchy attr value), merge with existing
			if alreadyEntitled, ok := actionsPerAttributeValueFqn[valueFQN]; ok {
				actions = mergeDeduplicatedActions(make(map[string]*policy.Action), actions, alreadyEntitled.GetActions())
			}
			entitledActions := &authz.EntityEntitlements_ActionsList{
				Actions: actions,
			}
			// If hierarchy and already entitled, merge with existing
			actionsPerAttributeValueFqn[valueFQN] = entitledActions

			// If comprehensive, populate the lower hierarchy values
			if withComprehensiveHierarchy {
				err = populateLowerValuesIfHierarchy(valueFQN, entitleableAttributes, entitledActions, actionsPerAttributeValueFqn)
				if err != nil {
					return nil, fmt.Errorf("error populating comprehensive lower hierarchy values of valueFQN [%s] for entityID [%s]: %w", valueFQN, entityID, err)
				}
			}
		}

		result = append(result, &authz.EntityEntitlements{
			EphemeralId:                 entityID,
			ActionsPerAttributeValueFqn: actionsPerAttributeValueFqn,
		})
	}
	l.DebugContext(
		ctx,
		"entitlement results",
		slog.Any("entitlements", result),
	)
	return result, nil
}

func (p *PolicyDecisionPoint) GetEntitlementsRegisteredResource(
	ctx context.Context,
	registeredResourceValueFQN string,
	withComprehensiveHierarchy bool,
) ([]*authz.EntityEntitlements, error) {
	l := p.logger.With("with_comprehensive_hierarchy", strconv.FormatBool(withComprehensiveHierarchy))
	l.DebugContext(ctx, "getting entitlements for registered resource value", slog.String("fqn", registeredResourceValueFQN))

	if _, err := identifier.Parse[*identifier.FullyQualifiedRegisteredResourceValue](registeredResourceValueFQN); err != nil {
		return nil, err
	}

	registeredResourceValue, ok := p.allRegisteredResourceValuesByFQN[registeredResourceValueFQN]
	if !ok {
		return nil, fmt.Errorf("registered resource value FQN not found in memory [%s]: %w", registeredResourceValueFQN, ErrInvalidResource)
	}

	actionsPerAttributeValueFqn := make(map[string]*authz.EntityEntitlements_ActionsList)

	for _, aav := range registeredResourceValue.GetActionAttributeValues() {
		action := aav.GetAction()
		attrVal := aav.GetAttributeValue()
		attrValFQN := attrVal.GetFqn()

		actionsList, actionsAreOK := actionsPerAttributeValueFqn[attrValFQN]
		if !actionsAreOK {
			actionsList = &authz.EntityEntitlements_ActionsList{
				Actions: make([]*policy.Action, 0),
			}
		}

		if !slices.ContainsFunc(actionsList.GetActions(), func(a *policy.Action) bool {
			return a.GetName() == action.GetName()
		}) {
			actionsList.Actions = append(actionsList.Actions, action)
		}

		actionsPerAttributeValueFqn[attrValFQN] = actionsList

		if withComprehensiveHierarchy {
			err := populateLowerValuesIfHierarchy(attrValFQN, p.allEntitleableAttributesByValueFQN, actionsList, actionsPerAttributeValueFqn)
			if err != nil {
				return nil, fmt.Errorf("error populating comprehensive lower hierarchy values for registered resource value FQN [%s]: %w", attrValFQN, err)
			}
		}
	}

	result := []*authz.EntityEntitlements{
		{
			EphemeralId:                 registeredResourceValueFQN,
			ActionsPerAttributeValueFqn: actionsPerAttributeValueFqn,
		},
	}
	l.DebugContext(
		ctx,
		"entitlement results for registered resource value",
		slog.Any("entitlements", result),
	)

	return result, nil
}
