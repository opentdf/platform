package access

import (
	"errors"
	"testing"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/policy/actions"
	"github.com/stretchr/testify/assert"
)

// Updated assertions to include better validation of the retrieved definition
func TestGetDefinition(t *testing.T) {
	validFQN := "https://example.org/attr/classification/value/public"
	invalidFQN := "invalid-fqn"

	validDefinition := &policy.Attribute{
		Fqn: "https://example.org/attr/classification",
	}

	definitions := map[string]*policy.Attribute{
		"https://example.org/attr/classification": validDefinition,
	}

	tests := []struct {
		name        string
		valueFQN    string
		definitions map[string]*policy.Attribute
		wantErr     bool
	}{
		{
			name:        "Valid FQN",
			valueFQN:    validFQN,
			definitions: definitions,
			wantErr:     false,
		},
		{
			name:        "Valid FQN not found",
			valueFQN:    "https://example.org/attr/unknown/value/unknown",
			definitions: definitions,
			wantErr:     true,
		},
		{
			name:        "Invalid FQN",
			valueFQN:    invalidFQN,
			definitions: definitions,
			wantErr:     true,
		},
		{
			name:        "Empty FQN",
			valueFQN:    "",
			definitions: definitions,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def, err := getDefinition(tt.valueFQN, tt.definitions)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, validDefinition, def, "Expected definition to match")
			}
		})
	}
}

func TestGetFilteredEntitleableAttributes(t *testing.T) {
	// Set up multiple attributes and values to thoroughly test filtering
	classificationFQN := "https://example.org/attr/classification"
	publicFQN := "https://example.org/attr/classification/value/public"
	confidentialFQN := "https://example.org/attr/classification/value/confidential"
	secretFQN := "https://example.org/attr/classification/value/secret"

	departmentFQN := "https://example.org/attr/department"
	hrFQN := "https://example.org/attr/department/value/hr"
	financeFQN := "https://example.org/attr/department/value/finance"
	itFQN := "https://example.org/attr/department/value/it"

	invalidFQN := "invalid-fqn"

	// Create attribute definitions
	classificationAttr := &policy.Attribute{
		Fqn:  classificationFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
	}

	departmentAttr := &policy.Attribute{
		Fqn:  departmentFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	}

	// Create attribute values with mappings to their respective definitions
	publicValue := &policy.Value{Fqn: publicFQN}
	confidentialValue := &policy.Value{Fqn: confidentialFQN}
	secretValue := &policy.Value{Fqn: secretFQN}

	hrValue := &policy.Value{Fqn: hrFQN}
	financeValue := &policy.Value{Fqn: financeFQN}
	itValue := &policy.Value{Fqn: itFQN}

	// Create subject mappings for some of the values
	publicMapping := &policy.SubjectMapping{
		AttributeValue: publicValue,
	}

	confidentialMapping := &policy.SubjectMapping{
		AttributeValue: confidentialValue,
	}

	hrMapping := &policy.SubjectMapping{
		AttributeValue: hrValue,
	}

	invalidMapping := &policy.SubjectMapping{
		AttributeValue: &policy.Value{Fqn: invalidFQN},
	}

	// Create the complete map of all entitleable attributes
	allEntitleableAttributes := map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		publicFQN: {
			Value:     publicValue,
			Attribute: classificationAttr,
		},
		confidentialFQN: {
			Value:     confidentialValue,
			Attribute: classificationAttr,
		},
		secretFQN: {
			Value:     secretValue,
			Attribute: classificationAttr,
		},
		hrFQN: {
			Value:     hrValue,
			Attribute: departmentAttr,
		},
		financeFQN: {
			Value:     financeValue,
			Attribute: departmentAttr,
		},
		itFQN: {
			Value:     itValue,
			Attribute: departmentAttr,
		},
	}

	tests := []struct {
		name                     string
		matchedSubjectMappings   []*policy.SubjectMapping
		allEntitleableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
		expectedFilteredFQNs     []string
		unexpectedFilteredFQNs   []string
		wantErr                  bool
	}{
		{
			name:                     "Filter to single value",
			matchedSubjectMappings:   []*policy.SubjectMapping{publicMapping},
			allEntitleableAttributes: allEntitleableAttributes,
			expectedFilteredFQNs:     []string{publicFQN},
			unexpectedFilteredFQNs:   []string{confidentialFQN, secretFQN, hrFQN, financeFQN, itFQN},
			wantErr:                  false,
		},
		{
			name:                     "Filter to multiple values from same attribute",
			matchedSubjectMappings:   []*policy.SubjectMapping{publicMapping, confidentialMapping},
			allEntitleableAttributes: allEntitleableAttributes,
			expectedFilteredFQNs:     []string{publicFQN, confidentialFQN},
			unexpectedFilteredFQNs:   []string{secretFQN, hrFQN, financeFQN, itFQN},
			wantErr:                  false,
		},
		{
			name:                     "Filter to values from different attributes",
			matchedSubjectMappings:   []*policy.SubjectMapping{publicMapping, hrMapping},
			allEntitleableAttributes: allEntitleableAttributes,
			expectedFilteredFQNs:     []string{publicFQN, hrFQN},
			unexpectedFilteredFQNs:   []string{confidentialFQN, secretFQN, financeFQN, itFQN},
			wantErr:                  false,
		},
		{
			name:                     "Empty subject mappings result in empty filtered map",
			matchedSubjectMappings:   []*policy.SubjectMapping{},
			allEntitleableAttributes: allEntitleableAttributes,
			expectedFilteredFQNs:     []string{},
			unexpectedFilteredFQNs:   []string{publicFQN, confidentialFQN, secretFQN, hrFQN, financeFQN, itFQN},
			wantErr:                  false,
		},
		{
			name:                     "Invalid FQN in subject mapping causes error",
			matchedSubjectMappings:   []*policy.SubjectMapping{publicMapping, invalidMapping},
			allEntitleableAttributes: allEntitleableAttributes,
			expectedFilteredFQNs:     []string{},
			unexpectedFilteredFQNs:   []string{},
			wantErr:                  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, err := getFilteredEntitleableAttributes(tt.matchedSubjectMappings, tt.allEntitleableAttributes)

			// Check error handling
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Verify size matches expected number of filtered elements
			assert.Equal(t, len(tt.expectedFilteredFQNs), len(filtered),
				"Expected filtered map to have %d elements, got %d",
				len(tt.expectedFilteredFQNs), len(filtered))

			// Verify expected FQNs are present
			for _, expectedFQN := range tt.expectedFilteredFQNs {
				attributeAndValue, exists := filtered[expectedFQN]
				assert.True(t, exists, "Expected filtered results to contain FQN: %s", expectedFQN)

				// Verify attribute definitions are preserved from the original map
				originalAttributeAndValue := tt.allEntitleableAttributes[expectedFQN]
				assert.Equal(t, originalAttributeAndValue.Attribute, attributeAndValue.Attribute,
					"Expected attribute definition to be preserved for FQN: %s", expectedFQN)

				// Verify value FQN is correct
				assert.Equal(t, expectedFQN, attributeAndValue.Value.GetFqn(),
					"Expected value FQN to match for FQN: %s", expectedFQN)
			}

			// Verify unexpected FQNs are not present
			for _, unexpectedFQN := range tt.unexpectedFilteredFQNs {
				_, exists := filtered[unexpectedFQN]
				assert.False(t, exists, "Unexpected FQN found in filtered results: %s", unexpectedFQN)
			}
		})
	}
}

func TestPopulateLowerValuesIfHierarchy(t *testing.T) {
	values := []*policy.Value{
		{Fqn: "https://example.org/attr/classification/value/secret"},
		{Fqn: "https://example.org/attr/classification/value/restricted"},
		{Fqn: "https://example.org/attr/classification/value/confidential"},
		{Fqn: "https://example.org/attr/classification/value/public"},
	}
	hierarchyAttributeAndValue := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		Attribute: &policy.Attribute{
			Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: values,
		},
	}

	entitledActions := &authz.EntityEntitlements_ActionsList{
		Actions: []*policy.Action{
			{Name: actions.ActionNameRead},
			{Name: actions.ActionNameCreate},
		},
	}

	tests := []struct {
		name                        string
		valueFQN                    string
		attributeAndValue           *attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
		entitledActions             *authz.EntityEntitlements_ActionsList
		actionsPerAttributeValueFqn map[string]*authz.EntityEntitlements_ActionsList
		wantErr                     error
		expectedMapKeyFQNs          []string
	}{
		{
			name:                        "Top level hierarchy value",
			valueFQN:                    values[0].GetFqn(),
			attributeAndValue:           hierarchyAttributeAndValue,
			entitledActions:             entitledActions,
			actionsPerAttributeValueFqn: make(map[string]*authz.EntityEntitlements_ActionsList),
			wantErr:                     nil,
			expectedMapKeyFQNs: []string{
				values[1].GetFqn(),
				values[2].GetFqn(),
				values[3].GetFqn(),
			},
		},
		{
			name:                        "mid level hierarchy value",
			valueFQN:                    values[2].GetFqn(),
			attributeAndValue:           hierarchyAttributeAndValue,
			entitledActions:             entitledActions,
			actionsPerAttributeValueFqn: make(map[string]*authz.EntityEntitlements_ActionsList),
			wantErr:                     nil,
			expectedMapKeyFQNs: []string{
				values[3].GetFqn(),
			},
		},
		{
			name:                        "lowest level hierarchy value",
			valueFQN:                    values[3].GetFqn(),
			attributeAndValue:           hierarchyAttributeAndValue,
			entitledActions:             entitledActions,
			actionsPerAttributeValueFqn: make(map[string]*authz.EntityEntitlements_ActionsList),
			wantErr:                     nil,
			expectedMapKeyFQNs:          []string{},
		},
		{
			name:     "Missing attribute rule",
			valueFQN: values[0].GetFqn(),
			attributeAndValue: &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				Attribute: &policy.Attribute{
					Values: values,
				},
			},
			entitledActions:             entitledActions,
			actionsPerAttributeValueFqn: make(map[string]*authz.EntityEntitlements_ActionsList),
			wantErr:                     nil,
			expectedMapKeyFQNs:          nil,
		},
		{
			name:     "Unspecified attribute rule",
			valueFQN: values[0].GetFqn(),
			attributeAndValue: &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				Attribute: &policy.Attribute{
					Values: values,
					Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
				},
			},
			entitledActions:             entitledActions,
			actionsPerAttributeValueFqn: make(map[string]*authz.EntityEntitlements_ActionsList),
			wantErr:                     nil,
			expectedMapKeyFQNs:          nil,
		},
		{
			name:     "ANY_OF attribute rule",
			valueFQN: values[0].GetFqn(),
			attributeAndValue: &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				Attribute: &policy.Attribute{
					Values: values,
					Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				},
			},
			entitledActions:             entitledActions,
			actionsPerAttributeValueFqn: make(map[string]*authz.EntityEntitlements_ActionsList),
			wantErr:                     nil,
			expectedMapKeyFQNs:          nil,
		},
		{
			name:     "ALL_OF attribute rule",
			valueFQN: values[0].GetFqn(),
			attributeAndValue: &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				Attribute: &policy.Attribute{
					Values: values,
					Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				},
			},
			entitledActions:             entitledActions,
			actionsPerAttributeValueFqn: make(map[string]*authz.EntityEntitlements_ActionsList),
			wantErr:                     nil,
			expectedMapKeyFQNs:          nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entitleableAttributes := map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				tt.valueFQN: tt.attributeAndValue,
			}
			err := populateLowerValuesIfHierarchy(tt.valueFQN, entitleableAttributes, tt.entitledActions, tt.actionsPerAttributeValueFqn)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, tt.wantErr), "Expected error %v, got %v", tt.wantErr, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, tt.expectedMapKeyFQNs, len(tt.actionsPerAttributeValueFqn), "Expected map to have %d keys, got %d", len(tt.expectedMapKeyFQNs), len(tt.actionsPerAttributeValueFqn))
				for _, key := range tt.expectedMapKeyFQNs {
					assert.Contains(t, tt.actionsPerAttributeValueFqn, key, "Expected map to contain key %s", key)
					assert.Equal(t, tt.entitledActions, tt.actionsPerAttributeValueFqn[key], "Expected map value for key %s to match", key)
					assert.Equal(t, len(tt.entitledActions.Actions), len(tt.actionsPerAttributeValueFqn[key].Actions), "Expected map value for key %s to match", key)
				}
			}
		})
	}
}

func TestPopulateHigherValuesIfHierarchy(t *testing.T) {
	values := []*policy.Value{
		{Fqn: "https://example.org/attr/classification/value/secret"},
		{Fqn: "https://example.org/attr/classification/value/restricted"},
		{Fqn: "https://example.org/attr/classification/value/confidential"},
		{Fqn: "https://example.org/attr/classification/value/public"},
	}
	hierarchyAttribute := &policy.Attribute{
		Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values: values,
	}
	anyOfAttribute := &policy.Attribute{
		Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values: []*policy.Value{},
	}
	allOfAttribute := &policy.Attribute{
		Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []*policy.Value{},
	}

	tests := []struct {
		name                 string
		valueFQN             string
		definition           *policy.Attribute
		initialAttributes    map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
		wantErr              error
		expectedMapAdditions []string
	}{
		{
			name:                 "Top level hierarchy value",
			valueFQN:             values[0].GetFqn(),
			definition:           hierarchyAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{}, // No higher values should be added for top level
		},
		{
			name:                 "Second level hierarchy value",
			valueFQN:             values[1].GetFqn(),
			definition:           hierarchyAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{values[0].GetFqn()}, // Should add the top level
		},
		{
			name:                 "Third level hierarchy value",
			valueFQN:             values[2].GetFqn(),
			definition:           hierarchyAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{values[0].GetFqn(), values[1].GetFqn()}, // Should add the top two levels
		},
		{
			name:                 "Bottom level hierarchy value",
			valueFQN:             values[3].GetFqn(),
			definition:           hierarchyAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{values[0].GetFqn(), values[1].GetFqn(), values[2].GetFqn()}, // Should add all higher levels
		},
		{
			name:                 "Non-hierarchy attribute",
			valueFQN:             values[0].GetFqn(),
			definition:           anyOfAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{}, // No additions for non-hierarchy attributes
		},
		{
			name:                 "All-of attribute",
			valueFQN:             values[0].GetFqn(),
			definition:           allOfAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{}, // No additions for non-hierarchy attributes
		},
		{
			name:                 "Nil attribute",
			valueFQN:             values[0].GetFqn(),
			definition:           nil,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              ErrInvalidAttributeDefinition,
			expectedMapAdditions: []string{}, // Error expected, no additions
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decisionableAttributes := tt.initialAttributes

			err := populateHigherValuesIfHierarchy(tt.valueFQN, tt.definition, decisionableAttributes)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, tt.wantErr), "Expected error %v, got %v", tt.wantErr, err)
				return
			}

			assert.NoError(t, err)

			// Check for expected additions to the map
			for _, expectedAddition := range tt.expectedMapAdditions {
				attributeAndValue, exists := decisionableAttributes[expectedAddition]
				assert.True(t, exists, "Expected map to contain key %s", expectedAddition)
				assert.Equal(t, tt.definition, attributeAndValue.Attribute, "Expected attribute to match definition")
				assert.Equal(t, expectedAddition, attributeAndValue.Value.GetFqn(), "Expected value FQN to match")
			}

			// Verify only the expected keys were added
			assert.Equal(t, len(tt.expectedMapAdditions), len(decisionableAttributes), "Expected %d additions to map, got %d", len(tt.expectedMapAdditions), len(decisionableAttributes))
		})
	}
}
