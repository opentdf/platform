package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/lib/identifier"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/logger"
)

var (
	ErrInvalidSubjectMapping      = errors.New("access: invalid subject mapping")
	ErrInvalidAttributeDefinition = errors.New("access: invalid attribute definition")
)

// getDefinition parses the value FQN and uses it to retrieve the definition from the provided definitions canmap
func getDefinition(valueFQN string, allDefinitionsByDefFQN map[string]*policy.Attribute) (*policy.Attribute, error) {
	parsed, err := identifier.Parse[*identifier.FullyQualifiedAttribute](valueFQN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attribute value FQN [%s]: %w", valueFQN, err)
	}
	def := &identifier.FullyQualifiedAttribute{
		Namespace: parsed.Namespace,
		Name:      parsed.Name,
	}

	definition, ok := allDefinitionsByDefFQN[def.FQN()]
	if !ok {
		return nil, fmt.Errorf("definition not found for FQN: %s", def.FQN())
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

		// Create a copy of the value with the subject mapping
		valueWithMapping := &policy.Value{
			Fqn:             mappedValue.GetFqn(),
			Value:           mappedValue.GetValue(),
			SubjectMappings: []*policy.SubjectMapping{sm},
		}

		mapped := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value:     valueWithMapping,
			Attribute: parentDefinition,
		}

		// If this value already exists in the filtered map, append the subject mapping
		if existing, exists := filtered[mappedValueFQN]; exists {
			existing.Value.SubjectMappings = append(existing.Value.SubjectMappings, sm)
		} else {
			filtered[mappedValueFQN] = mapped
		}
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
	entitledActionsSet := make(map[string]*policy.Action)
	for _, action := range entitledActions.GetActions() {
		entitledActionsSet[action.GetName()] = action
	}
	for _, value := range definition.GetValues() {
		if lower {
			alreadyEntitledActions, exists := entitledActionsPerAttributeValueFqn[value.GetFqn()]
			if !exists {
				entitledActionsPerAttributeValueFqn[value.GetFqn()] = entitledActions
			} else {
				// Ensure the actions are unique
				mergedActions := mergeDeduplicatedActions(entitledActionsSet, alreadyEntitledActions.GetActions())

				merged := &authz.EntityEntitlements_ActionsList{
					Actions: mergedActions,
				}

				entitledActionsPerAttributeValueFqn[value.GetFqn()] = merged
			}
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
	ctx context.Context,
	l *logger.Logger,
	valueFQN string,
	definition *policy.Attribute,
	allEntitleableAttributesByValueFQN map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
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
		// Pull the value from the lookup store holding subject mappings
		fullValue, ok := allEntitleableAttributesByValueFQN[value.GetFqn()]
		if !ok {
			l.WarnContext(ctx, "value FQN of hierarchy attribute not found available for lookup, may not have had subject mappings associated or provided", slog.String("value FQN", value.GetFqn()))
			continue
		}
		decisionableAttributes[value.GetFqn()] = &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value:     fullValue.GetValue(),
			Attribute: definition,
		}
	}

	return nil
}

// Deduplicate and merge two lists of actions
func mergeDeduplicatedActions(actionsSet map[string]*policy.Action, actionsToMerge ...[]*policy.Action) []*policy.Action {
	// Add or override with actions to merge
	for _, actionList := range actionsToMerge {
		for _, action := range actionList {
			actionsSet[action.GetName()] = action
		}
	}

	// Convert map back to slice
	merged := make([]*policy.Action, 0, len(actionsSet))
	for _, action := range actionsSet {
		merged = append(merged, action)
	}

	return merged
}
