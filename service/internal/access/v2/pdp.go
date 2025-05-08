package access

import (
	"fmt"

	"github.com/opentdf/platform/lib/identifier"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
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
	Passed         bool              `json:"passed" example:"false"`
	RuleDefinition *policy.Attribute `json:"rule_definition"`
	ValueFailures  []ValueFailure    `json:"value_failures"`
}

// ValueFailure represents a specific failure when evaluating a data attribute.
type ValueFailure struct {
	DataAttribute *policy.Value `json:"data_attribute"`
	Message       string        `json:"message" example:"Criteria NOT satisfied for entity: {entity_id} - lacked attribute value: {attribute}"`
}

// PDP represents the Policy Decision Point component.
// type PDP interface {
// 	*logger.Logger
// 	GetDecision(context.Context, *authz.EntityChain, *policy.Action, []*authz.Resource) (*Decision, error)
// 	GetEntitlements(ctx context.Context, entities []*authz.Entity, withComprehensiveHierarchy bool) ([]*authz.EntityEntitlements, error)
// }

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
	attributeAndValue *attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue,
	entitledActions *authz.EntityEntitlements_ActionsList,
	actionsPerAttributeValueFqn map[string]*authz.EntityEntitlements_ActionsList,
) error {
	if attributeAndValue == nil {
		return fmt.Errorf("attribute and value is nil: %w", ErrInvalidAttributeDefinition)
	}
	if attributeAndValue.GetAttribute().GetRule() != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		return fmt.Errorf("attribute rule is not hierarchy: %w", ErrInvalidAttributeDefinition)
	}
	definition := attributeAndValue.GetAttribute()
	if definition.GetRule() == policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		lower := false
		for _, value := range definition.GetValues() {
			if lower {
				actionsPerAttributeValueFqn[value.GetFqn()] = entitledActions
			}
			if value.GetFqn() == valueFQN {
				lower = true
			}
		}
	}
	return nil
}
