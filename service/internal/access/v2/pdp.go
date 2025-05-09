package access

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/identifier"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/logger"
)

var defaultFallbackLoggerConfig = logger.Config{
	Level:  "info",
	Type:   "json",
	Output: "stdout",
}

// === Structures ===

// Decision represents the overall access decision for an entity.
type Decision struct {
	Access  bool             `json:"access" example:"false"`
	Results []DataRuleResult `json:"entity_rule_result"`
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

// getDefinition parses the value FQN and uses it to retrieve the definition from the provided definitions canmap
func getDefinition(valueFQN string, allDefinitionsByDefFQN map[string]*policy.Attribute) (*policy.Attribute, error) {
	parsed, err := identifier.Parse[*identifier.FullyQualifiedAttribute](valueFQN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attribute value FQN: %w", err)
	}
	def := &identifier.FullyQualifiedAttribute{
		Namespace: parsed.Namespace,
		Name:      parsed.Name,
	}

	definition, ok := allDefinitionsByDefFQN[def.FQN()]
	if !ok {
		return nil, fmt.Errorf("definition not found: %w", err)
	}
	return definition, nil
}

// getFilteredEntitleableAttributes filters the entitleable attributes to only those that are in the optional matched subject mappings
func getFilteredEntitleableAttributes(
	matchedSubjectMappings []*policy.SubjectMapping,
	allEntitleableAttributesByValueFQN map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
) (map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	filtered := make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue)

	for _, sm := range matchedSubjectMappings {
		mappedValue := sm.GetAttributeValue()
		mappedValueFQN := mappedValue.GetFqn()

		if _, ok := allEntitleableAttributesByValueFQN[mappedValueFQN]; !ok {
			return nil, fmt.Errorf("invalid attribute value FQN in optional matched subject mappings: %w", ErrInvalidSubjectMapping)
		}
		// Take subject mapping's attribute value and its definition from memory
		attributeAndValue, ok := allEntitleableAttributesByValueFQN[mappedValueFQN]
		if !ok {
			return nil, fmt.Errorf("attribute value not found in memory: %s", mappedValueFQN)
		}
		parentDefinition := attributeAndValue.GetAttribute()

		mapped := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value:     mappedValue,
			Attribute: parentDefinition,
		}
		filtered[mappedValueFQN] = mapped
	}

	return filtered, nil
}

// populateLowerValuesIfHierarchy populates the lower values if the attribute is of type hierarchy
func populateLowerValuesIfHierarchy(
	valueFQN string,
	entitleableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	entitledActions *authz.EntityEntitlements_ActionsList,
	entitledActionsPerAttributeValueFqn map[string]*authz.EntityEntitlements_ActionsList,
) error {
	attributeAndValue, ok := entitleableAttributes[valueFQN]
	if !ok {
		return fmt.Errorf("attribute value not found in memory: %s", valueFQN)
	}
	definition := attributeAndValue.GetAttribute()
	if definition == nil {
		return fmt.Errorf("attribute is nil: %w", ErrInvalidAttributeDefinition)
	}
	if definition.GetRule() != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		return nil
	}

	lower := false
	for _, value := range definition.GetValues() {
		if lower {
			entitledActionsPerAttributeValueFqn[value.GetFqn()] = entitledActions
		}
		if value.GetFqn() == valueFQN {
			lower = true
		}
	}

	return nil
}

// populateHigherValuesIfHierarchy sets the higher values if the attribute is of type hierarchy to
// the decisionable attributes map
func populateHigherValuesIfHierarchy(
	valueFQN string,
	definition *policy.Attribute,
	decisionableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
) error {
	if definition == nil {
		return fmt.Errorf("attribute is nil: %w", ErrInvalidAttributeDefinition)
	}
	if definition.GetRule() != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		return nil
	}

	for _, value := range definition.GetValues() {
		if value.GetFqn() == valueFQN {
			break
		}
		decisionableAttributes[value.GetFqn()] = &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value:     value,
			Attribute: definition,
		}
	}

	return nil
}

// getResourceDecision evaluates the access decision for a single resource, driving the flows
// between entitlement checks for the different types of resources
func getResourceDecision(
	ctx context.Context,
	logger *logger.Logger,
	accessibleAttributeValues map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resource *authz.Resource,
) (*Decision, error) {
	if err := validateGetResourceDecision(accessibleAttributeValues, entitlements, action, resource); err != nil {
		return nil, err
	}

	logger.DebugContext(
		ctx,
		"getting decision on one resource",
		slog.Any("resource", resource.GetResource()),
	)

	switch resource.GetResource().(type) {
	case *authz.Resource_RegisteredResourceValueFqn:
		// TODO: handle registered resources
		// return evaluateRegisteredResourceValue(ctx, resource.GetRegisteredResourceValueFqn(), action, entitlements, accessibleAttributeValues)
	case *authz.Resource_AttributeValues_:
		return evaluateResourceAttributeValues(ctx, logger, resource.GetAttributeValues(), action, entitlements, accessibleAttributeValues)

	default:
		return nil, fmt.Errorf("unsupported resource type: %w", ErrInvalidResource)
	}
	return nil, nil
}

// evaluateResourceAttributeValues evaluates a list of attribute values against the action and entitlements
func evaluateResourceAttributeValues(
	ctx context.Context,
	logger *logger.Logger,
	resourceAttributeValues *authz.Resource_AttributeValues,
	action *policy.Action,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	accessibleAttributeValues map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
) (*Decision, error) {
	// Group value FQNs by parent definition
	groupedByDefinition := make(map[string][]string)
	for _, valueFQN := range resourceAttributeValues.GetFqns() {
		attributeAndValue, okvalueFQN := accessibleAttributeValues[valueFQN]
		if !okvalueFQN {
			return nil, fmt.Errorf("attribute value FQN not found in memory: %s", valueFQN)
		}
		definition := attributeAndValue.GetAttribute()
		groupedByDefinition[definition.GetFqn()] = append(groupedByDefinition[definition.GetFqn()], valueFQN)
	}

	// Evaluate each definition by rule, resource attributes, action, and entitlements
	passed := true
	results := make([]DataRuleResult, 0)
	for defFQN, valueFQNs := range groupedByDefinition {
		definition := accessibleAttributeValues[defFQN].GetAttribute()
		if definition == nil {
			return nil, fmt.Errorf("definition not found for FQN: %s", defFQN)
		}

		dataRuleResult, err := evaluateDefinition(ctx, logger, entitlements, action, valueFQNs, definition)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate definition: %w", err)
		}
		if !dataRuleResult.Passed {
			passed = false
		}
		results = append(results, *dataRuleResult)
	}
	return &Decision{
		Access:  passed,
		Results: results,
	}, nil
}

func evaluateDefinition(
	ctx context.Context,
	logger *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
	attrDefinition *policy.Attribute,
) (*DataRuleResult, error) {
	var entitlementFailures []EntitlementFailure

	logger.DebugContext(
		ctx,
		"evaluating definition",
		slog.String("definition rule", attrDefinition.GetRule().String()),
		slog.String("definition FQN", attrDefinition.GetFqn()),
		slog.Any("entitlements", entitlements),
		slog.String("action", action.GetName()),
		slog.Any("resource value FQNs", resourceValueFQNs),
	)

	switch attrDefinition.GetRule() {
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
		entitlementFailures = allOfRule(ctx, logger, entitlements, action, resourceValueFQNs)

	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
		entitlementFailures = anyOfRule(ctx, logger, entitlements, action, resourceValueFQNs)

	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
		entitlementFailures = hierarchyRule(ctx, logger, entitlements, action, resourceValueFQNs, attrDefinition)

	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
		return nil, fmt.Errorf("AttributeDefinition rule cannot be unspecified: %s, rule: %v", attrDefinition.GetFqn(), attrDefinition.GetRule())
	default:
		return nil, fmt.Errorf("unrecognized AttributeDefinition rule: %s", attrDefinition.GetRule())
	}

	result := &DataRuleResult{
		Passed:         len(entitlementFailures) == 0,
		RuleDefinition: attrDefinition,
	}
	if len(entitlementFailures) > 0 {
		result.EntitlementFailures = entitlementFailures
	}
	return result, nil
}

// Must be entitled to the specified action on every resource attribute value FQN
func allOfRule(
	ctx context.Context,
	logger *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
) []EntitlementFailure {
	actionName := action.GetName()
	failures := make([]EntitlementFailure, 0, len(resourceValueFQNs)) // Pre-allocate for efficiency

	// Single loop through all resource value FQNs
	for _, valueFQN := range resourceValueFQNs {
		hasEntitlement := false

		// Check if this FQN has the entitled action
		if entitledActions, ok := entitlements[valueFQN]; ok {
			for _, entitledAction := range entitledActions {
				if entitledAction.GetName() == actionName {
					hasEntitlement = true
					break
				}
			}
		}

		// If no entitlement found for this FQN, add to failures immediately
		if !hasEntitlement {
			failures = append(failures, EntitlementFailure{
				AttributeValueFQN: valueFQN,
				ActionName:        actionName,
			})
		}
	}

	return failures
}

// Must be entitled to the specified action on at least one resource attribute value FQN
func anyOfRule(
	ctx context.Context,
	logger *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
) []EntitlementFailure {
	actionName := action.GetName()
	anyEntitlementFound := false
	entitlementFailures := make([]EntitlementFailure, 0, len(resourceValueFQNs))

	// Single loop through all resource value FQNs
	for _, valueFQN := range resourceValueFQNs {
		foundEntitlementForThisFQN := false

		entitledActions, ok := entitlements[valueFQN]
		if ok {
			for _, entitledAction := range entitledActions {
				if entitledAction.GetName() == actionName {
					foundEntitlementForThisFQN = true
					anyEntitlementFound = true
					break
				}
			}
		}

		if !foundEntitlementForThisFQN {
			entitlementFailures = append(entitlementFailures, EntitlementFailure{
				AttributeValueFQN: valueFQN,
				ActionName:        actionName,
			})
		}
	}

	// Rule is satisfied if at least one FQN has the entitled action
	if anyEntitlementFound {
		return nil
	}
	return entitlementFailures

}

// Must be entitled to the specified action on the highest value FQN in the hierarchy
// where highest equates to the resource attribute FQN for the value at the lowest index
// in the hierarchical definition
func hierarchyRule(
	ctx context.Context,
	logger *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
	attrDefinition *policy.Attribute,
) []EntitlementFailure {
	actionName := action.GetName()

	// Constant lookup time
	valueFQNToIndex := make(map[string]int, len(attrDefinition.GetValues()))
	for idx, value := range attrDefinition.GetValues() {
		valueFQNToIndex[value.GetFqn()] = idx
	}

	// Find the lowest indexed value FQN (highest in hierarchy)
	lowestValueFQNIndex := len(attrDefinition.GetValues())
	var highestHierarchyValueFQN string

	for _, valueFQN := range resourceValueFQNs {
		if idx, exists := valueFQNToIndex[valueFQN]; exists && idx < lowestValueFQNIndex {
			lowestValueFQNIndex = idx
			highestHierarchyValueFQN = valueFQN
		}
	}

	// Check if the action is entitled to the highest value FQN
	if entitledActions, ok := entitlements[highestHierarchyValueFQN]; ok {
		for _, entitledAction := range entitledActions {
			if entitledAction.GetName() == actionName {
				return nil // Found it, so no failures
			}
		}
	}

	// The rule was not satisfied - collect failures
	entitlementFailures := make([]EntitlementFailure, 0, len(resourceValueFQNs))

	for _, valueFQN := range resourceValueFQNs {
		foundValue := false
		if entitledActions, ok := entitlements[valueFQN]; ok {
			for _, entitledAction := range entitledActions {
				if entitledAction.GetName() == actionName {
					foundValue = true
					break
				}
			}
		}

		if !foundValue {
			entitlementFailures = append(entitlementFailures, EntitlementFailure{
				AttributeValueFQN: valueFQN,
				ActionName:        actionName,
			})
		}
	}

	return entitlementFailures
}
