package access

import (
	"fmt"

	"github.com/opentdf/platform/lib/identifier"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
)

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
