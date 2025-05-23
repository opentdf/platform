package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/logger"
)

var (
	ErrInvalidResource              = errors.New("access: invalid resource")
	ErrFQNNotFound                  = errors.New("access: attribute value FQN not found in memory")
	ErrDefinitionNotFound           = errors.New("access: definition not found for FQN")
	ErrFailedEvaluation             = errors.New("access: failed to evaluate definition")
	ErrMissingRequiredSpecifiedRule = errors.New("access: AttributeDefinition rule cannot be unspecified")
	ErrUnrecognizedRule             = errors.New("access: unrecognized AttributeDefinition rule")
)

// getResourceDecision evaluates the access decision for a single resource, driving the flows
// between entitlement checks for the different types of resources
func getResourceDecision(
	ctx context.Context,
	logger *logger.Logger,
	accessibleAttributeValues map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resource *authz.Resource,
) (*ResourceDecision, error) {
	if err := validateGetResourceDecision(accessibleAttributeValues, entitlements, action, resource); err != nil {
		return nil, err
	}

	logger.DebugContext(
		ctx,
		"getting decision on one resource",
		slog.Any("resource", resource.GetResource()),
	)

	switch resource.GetResource().(type) {
	// TODO: handle registered resources
	case *authz.Resource_RegisteredResourceValueFqn:
		return nil, fmt.Errorf("registered resources not supported yet: %w", ErrInvalidResource)
	case *authz.Resource_AttributeValues_:
		return evaluateResourceAttributeValues(ctx, logger, resource.GetAttributeValues(), resource.GetEphemeralId(), action, entitlements, accessibleAttributeValues)

	default:
		return nil, fmt.Errorf("unsupported resource type: %w", ErrInvalidResource)
	}
}

// evaluateResourceAttributeValues evaluates a list of attribute values against the action and entitlements
// and lowercases the FQNs to ensure case-insensitive matching
func evaluateResourceAttributeValues(
	ctx context.Context,
	logger *logger.Logger,
	resourceAttributeValues *authz.Resource_AttributeValues,
	resourceID string,
	action *policy.Action,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	accessibleAttributeValues map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
) (*ResourceDecision, error) {
	// Group value FQNs by parent definition
	definitionFqnToValueFqns := make(map[string][]string)
	definitionsLookup := make(map[string]*policy.Attribute)

	for _, valueFQN := range resourceAttributeValues.GetFqns() {
		attributeAndValue, ok := accessibleAttributeValues[valueFQN]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrFQNNotFound, valueFQN)
		}
		definition := attributeAndValue.GetAttribute()
		definitionFqnToValueFqns[definition.GetFqn()] = append(definitionFqnToValueFqns[definition.GetFqn()], valueFQN)
		definitionsLookup[definition.GetFqn()] = definition
	}

	// Evaluate each definition by rule, resource attributes, action, and entitlements
	passed := true
	dataRuleResults := make([]DataRuleResult, 0)

	for defFQN, resourceValueFQNs := range definitionFqnToValueFqns {
		definition := definitionsLookup[defFQN]
		if definition == nil {
			return nil, fmt.Errorf("%w: %s", ErrDefinitionNotFound, defFQN)
		}

		dataRuleResult, err := evaluateDefinition(ctx, logger, entitlements, action, resourceValueFQNs, definition)
		if err != nil {
			return nil, errors.Join(ErrFailedEvaluation, err)
		}
		if !dataRuleResult.Passed {
			passed = false
		}

		dataRuleResults = append(dataRuleResults, *dataRuleResult)
	}

	// Return results in the appropriate structure
	return &ResourceDecision{
		Passed:          passed,
		ResourceID:      resourceID,
		DataRuleResults: dataRuleResults,
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
		return nil, fmt.Errorf("%w: %s, rule: %s", ErrMissingRequiredSpecifiedRule, attrDefinition.GetFqn(), attrDefinition.GetRule().String())
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnrecognizedRule, attrDefinition.GetRule().String())
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

// allOfRule validates that:
// 1. For each resource attribute value FQN, the action is entitled
// 2. If any FQN is not entitled, or the FQN is missing the requested action, the rule fails
func allOfRule(
	_ context.Context,
	_ *logger.Logger,
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
				if strings.EqualFold(entitledAction.GetName(), actionName) {
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

// anyOfRule validates that:
// 1. At least one resource attribute value FQN has the action entitled
// 2. If none of the FQNs are found the entitlements, the rule fails
// 3. If none of the matching FQNs in the entitlements contain the requested action, the rule fails
func anyOfRule(
	_ context.Context,
	_ *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
) []EntitlementFailure {
	// No resources to check
	if len(resourceValueFQNs) == 0 {
		return nil
	}

	actionName := action.GetName()
	anyEntitlementFound := false
	entitlementFailures := make([]EntitlementFailure, 0, len(resourceValueFQNs))

	// Single loop through all resource value FQNs
	for _, valueFQN := range resourceValueFQNs {
		foundEntitlementForThisFQN := false

		entitledActions, ok := entitlements[valueFQN]
		if ok {
			for _, entitledAction := range entitledActions {
				if strings.EqualFold(entitledAction.GetName(), actionName) {
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

// hierarchyRule validates that:
// 1. The user has entitlement to the specified action on the highest value FQN in the hierarchy or any hierarchically higher value
// 2. The highest value FQN is determined by the lowest index in the hierarchy definition
// 3. If the highest value FQN or any higher value has the required entitlement, the rule passes with no failures
// 4. If no hierarchically relevant FQN has the required entitlement, the rule fails with all missing entitlements
func hierarchyRule(
	_ context.Context,
	_ *logger.Logger,
	entitlements subjectmappingbuiltin.AttributeValueFQNsToActions,
	action *policy.Action,
	resourceValueFQNs []string,
	attrDefinition *policy.Attribute,
) []EntitlementFailure {
	// No resources to check
	if len(resourceValueFQNs) == 0 {
		return nil
	}

	actionName := action.GetName()

	// Create a lookup map for the attribute value indices - O(n) where n is the number of values in the attribute
	valueFQNToIndex := make(map[string]int, len(attrDefinition.GetValues()))
	for idx, value := range attrDefinition.GetValues() {
		valueFQNToIndex[value.GetFqn()] = idx
	}

	// Find the lowest indexed value FQN (highest in hierarchy) - O(m) where m is the number of resource values
	lowestValueFQNIndex := len(attrDefinition.GetValues())
	for _, valueFQN := range resourceValueFQNs {
		if idx, exists := valueFQNToIndex[valueFQN]; exists && idx < lowestValueFQNIndex {
			lowestValueFQNIndex = idx
		}
	}

	// Check if the entitlements contain any values with index <= lowestValueFQNIndex
	// This checks the requested value and any hierarchically higher values in a single pass - O(e) where e is entitlements count
	for entitlementFQN, entitledActions := range entitlements {
		// Check if this entitlement FQN has a valid index in the hierarchy
		if idx, exists := valueFQNToIndex[entitlementFQN]; exists && idx <= lowestValueFQNIndex {
			// Check if the required action is entitled
			for _, entitledAction := range entitledActions {
				if strings.EqualFold(entitledAction.GetName(), actionName) {
					return nil // Found an entitled action at or above the hierarchy level, no failures
				}
			}
		}
	}

	// The rule was not satisfied - collect failures - O(m) where m is the number of resource values
	entitlementFailures := make([]EntitlementFailure, 0, len(resourceValueFQNs))
	for _, valueFQN := range resourceValueFQNs {
		foundValue := false
		if entitledActions, ok := entitlements[valueFQN]; ok {
			for _, entitledAction := range entitledActions {
				if strings.EqualFold(entitledAction.GetName(), actionName) {
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
