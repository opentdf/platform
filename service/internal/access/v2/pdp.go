package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

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
	Access  bool               `json:"access" example:"false"`
	Results []ResourceDecision `json:"entity_rule_result"`
}

// ResourceDecision represents the result of evaluating the action on one resource for an entity.
type ResourceDecision struct {
	Passed          bool             `json:"passed" example:"false"`
	ResourceID      string           `json:"resource_id,omitempty"`
	DataRuleResults []DataRuleResult `json:"data_rule_results"`
}

// DataRuleResult represents the result of evaluating one rule for an entity.
type DataRuleResult struct {
	Passed              bool                 `json:"passed" example:"false"`
	RuleDefinition      *policy.Attribute    `json:"rule_definition"`
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
}

var (
	defaultFallbackLoggerConfig = logger.Config{
		Level:  "info",
		Type:   "json",
		Output: "stdout",
	}
	ErrMissingRequiredPolicy = errors.New("access: both attribute definitions and subject mappings must be provided or neither")
)

// PolicyDecisionPoint creates a new Policy Decision Point instance.
// It is presumed that all Attribute Definitions and Subject Mappings are valid and contain the entirety of entitlement policy.
// Attribute Values without Subject Mappings will be ignored in decisioning.
func NewPolicyDecisionPoint(
	ctx context.Context,
	l *logger.Logger,
	allAttributeDefinitions []*policy.Attribute,
	allSubjectMappings []*policy.SubjectMapping,
	allRegisteredResources []*policy.RegisteredResource,
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
			l.WarnContext(ctx, "invalid subject mapping - skipping", slog.Any("error", err), slog.Any("subject mapping", sm))
			continue
		}
		mappedValue := sm.GetAttributeValue()
		mappedValueFQN := mappedValue.GetFqn()
		if _, ok := allEntitleableAttributesByValueFQN[mappedValueFQN]; ok {
			allEntitleableAttributesByValueFQN[mappedValueFQN].Value.SubjectMappings = append(allEntitleableAttributesByValueFQN[mappedValueFQN].Value.SubjectMappings, sm)
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
	}
	return pdp, nil
}

// GetDecision evaluates the action on the resources for the entity and returns a decision.
func (p *PolicyDecisionPoint) GetDecision(
	ctx context.Context,
	entityRepresentation *entityresolutionV2.EntityRepresentation,
	action *policy.Action,
	resources []*authz.Resource,
) (*Decision, error) {
	l := p.logger.With("entityID", entityRepresentation.GetOriginalId())
	l = l.With("action", action.GetName())
	l.DebugContext(ctx, "getting decision", slog.Int("resourcesCount", len(resources)))

	if err := validateGetDecision(entityRepresentation, action, resources); err != nil {
		return nil, err
	}

	// Filter all attributes down to only those that relevant to the entitlement decisioning of these specific resources
	decisionableAttributes := make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)

	for idx, resource := range resources {
		// Assign indexed ephemeral ID for resource if not already set
		if resource.GetEphemeralId() == "" {
			resource.EphemeralId = "resource-" + strconv.Itoa(idx)
		}

		switch resource.GetResource().(type) {
		// TODO: handle gathering decisionable attributes of registered resources
		case *authz.Resource_RegisteredResourceValueFqn:
			return nil, fmt.Errorf("registered resource value FQN not supported: %w", ErrInvalidResource)

		case *authz.Resource_AttributeValues_:
			for idx, valueFQN := range resource.GetAttributeValues().GetFqns() {
				// lowercase each resource attribute value FQN for case consistent map key lookups
				valueFQN = strings.ToLower(valueFQN)
				resource.GetAttributeValues().Fqns[idx] = valueFQN

				// If same value FQN more than once, skip
				if _, ok := decisionableAttributes[valueFQN]; ok {
					continue
				}

				attributeAndValue, ok := p.allEntitleableAttributesByValueFQN[valueFQN]
				if !ok {
					return nil, fmt.Errorf("resource value FQN not found in memory [%s]: %w", valueFQN, ErrInvalidResource)
				}

				decisionableAttributes[valueFQN] = attributeAndValue
				err := populateHigherValuesIfHierarchy(ctx, p.logger, valueFQN, attributeAndValue.GetAttribute(), p.allEntitleableAttributesByValueFQN, decisionableAttributes)
				if err != nil {
					return nil, fmt.Errorf("error populating higher hierarchy attribute values: %w", err)
				}
			}

		default:
			// default should never happen as we validate above
			return nil, fmt.Errorf("invalid resource type [%T]: %w", resource.GetResource(), ErrInvalidResource)
		}
	}
	l.DebugContext(ctx, "filtered to only entitlements relevant to decisioning", slog.Int("decisionableAttributeValuesCount", len(decisionableAttributes)))

	// Resolve them to their entitled FQNs and the actions available on each
	entitledFQNsToActions, err := subjectmappingbuiltin.EvaluateSubjectMappingsWithActions(decisionableAttributes, entityRepresentation)
	if err != nil {
		return nil, fmt.Errorf("error evaluating subject mappings for entitlement: %w", err)
	}
	l.DebugContext(ctx, "evaluated subject mappings", slog.Any("entitledValueFqnsToActions", entitledFQNsToActions))

	decision := &Decision{
		Access:  true,
		Results: make([]ResourceDecision, len(resources)),
	}

	for idx, resource := range resources {
		resourceDecision, err := getResourceDecision(ctx, p.logger, decisionableAttributes, entitledFQNsToActions, action, resource)
		if err != nil || resourceDecision == nil {
			return nil, fmt.Errorf("error evaluating a decision on resource [%v]: %w", resource, err)
		}

		if !resourceDecision.Passed {
			decision.Access = false
		}

		l.DebugContext(
			ctx,
			"resourceDecision result",
			slog.Bool("passed", resourceDecision.Passed),
			slog.String("resourceID", resourceDecision.ResourceID),
			slog.Int("dataRuleResultsCount", len(resourceDecision.DataRuleResults)),
		)
		decision.Results[idx] = *resourceDecision
	}

	return decision, nil
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

	l := p.logger.With("withComprehensiveHierarchy", strconv.FormatBool(withComprehensiveHierarchy))
	l.DebugContext(ctx, "getting entitlements", slog.Int("entityRepresentationsCount", len(entityRepresentations)))

	var entitleableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue

	// Check entitlement only against the filtered matched subject mappings if provided
	if optionalMatchedSubjectMappings != nil {
		l.DebugContext(ctx, "filtering to provided matched subject mappings", slog.Int("matchedSubjectMappingsCount", len(optionalMatchedSubjectMappings)))
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
	l.DebugContext(ctx, "evaluated subject mappings", slog.Any("entitlementsByEntityID", entityIDsToFQNsToActions))

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
