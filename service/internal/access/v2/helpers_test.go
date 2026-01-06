package access

import (
	"fmt"
	"testing"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/access/v2/obligations"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/actions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

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
				require.Error(t, err)
			} else {
				require.NoError(t, err)
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

	deptFQN := "https://example.org/attr/department"
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
		Fqn:  deptFQN,
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
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify size matches expected number of filtered elements
			assert.Len(t, filtered, len(tt.expectedFilteredFQNs),
				"Expected filtered map to have %d elements, got %d",
				len(tt.expectedFilteredFQNs), len(filtered))

			// Verify expected FQNs are present
			for _, expectedFQN := range tt.expectedFilteredFQNs {
				attributeAndValue, exists := filtered[expectedFQN]
				assert.True(t, exists, "Expected filtered results to contain FQN: %s", expectedFQN)

				// Verify attribute definitions are preserved from the original map
				originalAttributeAndValue := tt.allEntitleableAttributes[expectedFQN]
				assert.Equal(t, originalAttributeAndValue.GetAttribute(), attributeAndValue.GetAttribute(),
					"Expected attribute definition to be preserved for FQN: %s", expectedFQN)

				// Verify value FQN is correct
				assert.Equal(t, expectedFQN, attributeAndValue.GetValue().GetFqn(),
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
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Len(t, tt.expectedMapKeyFQNs, len(tt.actionsPerAttributeValueFqn), "Expected map to have %d keys, got %d", len(tt.expectedMapKeyFQNs), len(tt.actionsPerAttributeValueFqn))
				for _, key := range tt.expectedMapKeyFQNs {
					assert.Contains(t, tt.actionsPerAttributeValueFqn, key, "Expected map to contain key %s", key)
					assert.True(t, proto.Equal(tt.entitledActions, tt.actionsPerAttributeValueFqn[key]), "Expected map value for key %s to match", key)
					assert.Len(t, tt.actionsPerAttributeValueFqn[key].GetActions(), len(tt.entitledActions.GetActions()), "Expected map value for key %s to match", key)
				}
			}
		})
	}
}

func TestPopulateHigherValuesIfHierarchy(t *testing.T) {
	exampleSecretFQN := "https://example.org/attr/classification/value/secret"
	exampleRestrictedFQN := "https://example.org/attr/classification/value/restricted"
	exampleConfidentialFQN := "https://example.org/attr/classification/value/confidential"
	examplePublicFQN := "https://example.org/attr/classification/value/public"

	valueSecret := &policy.Value{
		Fqn:             exampleSecretFQN,
		SubjectMappings: []*policy.SubjectMapping{createSimpleSubjectMapping(exampleSecretFQN, "secret", []*policy.Action{actionRead}, ".test", []string{"value"})},
	}
	valueRestricted := &policy.Value{
		Fqn:             exampleRestrictedFQN,
		SubjectMappings: []*policy.SubjectMapping{createSimpleSubjectMapping(exampleSecretFQN, "restricted", []*policy.Action{actionRead}, ".test", []string{"somethingelse"})},
	}
	valueConf := &policy.Value{
		Fqn:             exampleConfidentialFQN,
		SubjectMappings: []*policy.SubjectMapping{createSimpleSubjectMapping(exampleConfidentialFQN, "confidential", []*policy.Action{actionRead}, ".hello", []string{"world"})},
	}
	valuePublic := &policy.Value{
		Fqn:             examplePublicFQN,
		SubjectMappings: []*policy.SubjectMapping{createSimpleSubjectMapping(examplePublicFQN, "public", []*policy.Action{actionRead}, ".goodnight", []string{"moon"})},
	}

	values := []*policy.Value{valueSecret, valueRestricted, valueConf, valuePublic}

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

	allValueFQNsToAttributeValues := map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		exampleSecretFQN: {
			Value:     valueSecret,
			Attribute: hierarchyAttribute,
		},
		exampleRestrictedFQN: {
			Value:     valueRestricted,
			Attribute: hierarchyAttribute,
		},
		exampleConfidentialFQN: {
			Value:     valueConf,
			Attribute: hierarchyAttribute,
		},
		examplePublicFQN: {
			Value:     valuePublic,
			Attribute: hierarchyAttribute,
		},
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
			valueFQN:             exampleSecretFQN,
			definition:           hierarchyAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{}, // No higher values should be added for top level
		},
		{
			name:                 "Second level hierarchy value",
			valueFQN:             exampleRestrictedFQN,
			definition:           hierarchyAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{exampleSecretFQN}, // Should add the top level
		},
		{
			name:                 "Third level hierarchy value",
			valueFQN:             exampleConfidentialFQN,
			definition:           hierarchyAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{exampleRestrictedFQN, exampleSecretFQN}, // Should add the top two levels
		},
		{
			name:                 "Bottom level hierarchy value",
			valueFQN:             examplePublicFQN,
			definition:           hierarchyAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{exampleConfidentialFQN, exampleSecretFQN, exampleRestrictedFQN}, // Should add all higher levels
		},
		{
			name:                 "Non-hierarchy attribute",
			valueFQN:             "irrelevant-to-this-test",
			definition:           anyOfAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{}, // No additions for non-hierarchy attributes
		},
		{
			name:                 "All-of attribute",
			valueFQN:             "irrelevant-to-this-test",
			definition:           allOfAttribute,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              nil,
			expectedMapAdditions: []string{}, // No additions for non-hierarchy attributes
		},
		{
			name:                 "Nil attribute",
			valueFQN:             exampleRestrictedFQN,
			definition:           nil,
			initialAttributes:    make(map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue),
			wantErr:              ErrInvalidAttributeDefinition,
			expectedMapAdditions: []string{}, // Error expected, no additions
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decisionableAttributes := tt.initialAttributes

			err := populateHigherValuesIfHierarchy(t.Context(), logger.CreateTestLogger(), tt.valueFQN, tt.definition, allValueFQNsToAttributeValues, decisionableAttributes)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)

			// Check for expected additions to the map
			for _, expectedAddition := range tt.expectedMapAdditions {
				attributeAndValue, exists := decisionableAttributes[expectedAddition]
				assert.True(t, exists, "Expected map to contain key %s", expectedAddition)
				assert.Equal(t, tt.definition, attributeAndValue.GetAttribute(), "Expected attribute to match definition")
				assert.Equal(t, expectedAddition, attributeAndValue.GetValue().GetFqn(), "Expected value FQN to match")
				assert.NotEmpty(t, attributeAndValue.GetValue().GetSubjectMappings(), "Bubbled up higher hierarchy values should contain subject mappings to check entitlement")
			}

			// Verify only the expected keys were added
			assert.Len(t, decisionableAttributes, len(tt.expectedMapAdditions), "Expected %d additions to map, got %d", len(tt.expectedMapAdditions), len(decisionableAttributes))
		})
	}

	decisionableAttributes := map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{}

	// Populate up from second highest
	err := populateHigherValuesIfHierarchy(t.Context(), logger.CreateTestLogger(), exampleRestrictedFQN, hierarchyAttribute, allValueFQNsToAttributeValues, decisionableAttributes)
	require.NoError(t, err)
	assert.NotNil(t, decisionableAttributes)
	assert.Len(t, decisionableAttributes, 1)

	// Secret should have been added, as it's higher than restriected
	decisionableSecret := decisionableAttributes[exampleSecretFQN]
	assert.NotNil(t, decisionableSecret)
	assert.NotEmpty(t, decisionableSecret.GetValue().GetSubjectMappings())

	// Call it with lowest
	err = populateHigherValuesIfHierarchy(t.Context(), logger.CreateTestLogger(), examplePublicFQN, hierarchyAttribute, allValueFQNsToAttributeValues, decisionableAttributes)
	require.NoError(t, err)
	assert.NotNil(t, decisionableAttributes)

	// Every value above public should be present
	assert.Len(t, decisionableAttributes, 3)
	found := map[string]bool{
		exampleSecretFQN:       false,
		exampleRestrictedFQN:   false,
		exampleConfidentialFQN: false,
	}
	for fqn, attrAndVal := range decisionableAttributes {
		_, exists := found[fqn]
		assert.True(t, exists)
		found[fqn] = true
		assert.NotEmpty(t, attrAndVal.GetValue().GetSubjectMappings())
	}
	for _, state := range found {
		assert.True(t, state)
	}
}

func TestMergeDeduplicatedActions(t *testing.T) {
	// Define test actions
	readAction := &policy.Action{Name: "read"}
	writeAction := &policy.Action{Name: "write"}
	updateAction := &policy.Action{Name: "update"}
	deleteAction := &policy.Action{Name: "delete"}

	tests := []struct {
		name            string
		initialSet      map[string]*policy.Action
		actionsToMerge  [][]*policy.Action
		expectedActions map[string]bool
	}{
		{
			name:       "Empty initial set with single merge list",
			initialSet: map[string]*policy.Action{},
			actionsToMerge: [][]*policy.Action{
				{readAction, writeAction},
			},
			expectedActions: map[string]bool{
				"read":  true,
				"write": true,
			},
		},
		{
			name: "Populated initial set with no merge",
			initialSet: map[string]*policy.Action{
				"read":   readAction,
				"update": updateAction,
			},
			actionsToMerge: [][]*policy.Action{},
			expectedActions: map[string]bool{
				"read":   true,
				"update": true,
			},
		},
		{
			name: "Populated initial set with non-overlapping merge",
			initialSet: map[string]*policy.Action{
				"read":   readAction,
				"update": updateAction,
			},
			actionsToMerge: [][]*policy.Action{
				{writeAction, deleteAction},
			},
			expectedActions: map[string]bool{
				"read":   true,
				"write":  true,
				"update": true,
				"delete": true,
			},
		},
		{
			name: "Populated initial set with overlapping merge",
			initialSet: map[string]*policy.Action{
				"read":   readAction,
				"update": updateAction,
			},
			actionsToMerge: [][]*policy.Action{
				{readAction, writeAction},
			},
			expectedActions: map[string]bool{
				"read":   true,
				"write":  true,
				"update": true,
			},
		},
		{
			name: "Multiple merge lists with overlaps",
			initialSet: map[string]*policy.Action{
				"read": readAction,
			},
			actionsToMerge: [][]*policy.Action{
				{writeAction, updateAction},
				{deleteAction, writeAction},
			},
			expectedActions: map[string]bool{
				"read":   true,
				"write":  true,
				"update": true,
				"delete": true,
			},
		},
		{
			name: "Nil action lists",
			initialSet: map[string]*policy.Action{
				"read": readAction,
			},
			actionsToMerge: [][]*policy.Action{
				nil,
				{writeAction},
				nil,
			},
			expectedActions: map[string]bool{
				"read":  true,
				"write": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the initial set to avoid modifying the test data
			initialSet := make(map[string]*policy.Action)
			for k, v := range tt.initialSet {
				initialSet[k] = v
			}

			// Convert actionsToMerge to variadic arguments
			var actionsToMergeSlices [][]*policy.Action
			actionsToMergeSlices = append(actionsToMergeSlices, tt.actionsToMerge...)

			// Call the function under test
			result := mergeDeduplicatedActions(initialSet, actionsToMergeSlices...)

			assert.Len(t, result, len(tt.expectedActions))

			// Check that all expected action names are present
			resultNames := make(map[string]bool)
			for _, action := range result {
				resultNames[action.GetName()] = true
			}

			for name := range tt.expectedActions {
				assert.True(t, resultNames[name], "Expected action %s not found in result", name)
			}
		})
	}
}

const (
	testObligation1FQN = "https://example.org/obligation/attr1/value/obl1"
	testObligation2FQN = "https://example.org/obligation/attr2/value/obl2"

	testResource1ID   = "resource1"
	testResource2ID   = "resource2"
	testResource3ID   = "resource3"
	testResource1Name = "Resource One"
	testResource2Name = "Resource Two"
	testResource3Name = "Resource Three"
)

func mkExpectedResourceDecision(id, name string, entitled, obligationsSatisfied, passed bool, obligations []string, dataRules ...DataRuleResult) ResourceDecision {
	return ResourceDecision{
		Entitled:                    entitled,
		ObligationsSatisfied:        obligationsSatisfied,
		Passed:                      passed,
		ResourceID:                  id,
		ResourceName:                name,
		RequiredObligationValueFQNs: obligations,
		DataRuleResults:             dataRules,
	}
}

func mkPerResourceDecision(satisfied bool, obligationFQNs ...string) obligations.PerResourceDecision {
	return obligations.PerResourceDecision{
		ObligationsSatisfied:        satisfied,
		RequiredObligationValueFQNs: obligationFQNs,
	}
}

func assertResourceDecision(t *testing.T, expected, actual ResourceDecision, idx int, prefix string) {
	t.Helper()
	assert.Equal(t, expected.Entitled, actual.Entitled, "%s resource %d: Entitled mismatch", prefix, idx)
	assert.Equal(t, expected.ObligationsSatisfied, actual.ObligationsSatisfied, "%s resource %d: ObligationsSatisfied mismatch", prefix, idx)
	assert.Equal(t, expected.Passed, actual.Passed, "%s resource %d: Passed mismatch", prefix, idx)
	assert.Equal(t, expected.ResourceID, actual.ResourceID, "%s resource %d: ResourceID mismatch", prefix, idx)
	assert.Equal(t, expected.ResourceName, actual.ResourceName, "%s resource %d: ResourceName mismatch", prefix, idx)
	assert.Equal(t, expected.RequiredObligationValueFQNs, actual.RequiredObligationValueFQNs, "%s resource %d: RequiredObligationValueFQNs mismatch", prefix, idx)
	assert.Equal(t, expected.DataRuleResults, actual.DataRuleResults, "%s resource %d: DataRuleResults mismatch", prefix, idx)
}

func Test_applyObligationsAndConsolidate(t *testing.T) {
	testAttrFQN := "https://example.org/attr/test/value/v1"

	tests := []struct {
		name                 string
		accumulated          []ResourceDecision
		nextDecision         *Decision
		obligationDecision   obligations.ObligationPolicyDecision
		expectedConsolidated []ResourceDecision
		expectedAudit        []ResourceDecision
		expectedErr          error
	}{
		// First entity scenarios
		{
			name:        "first entity - no obligations",
			accumulated: nil,
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				RequiredObligationValueFQNs: []string{},
				PerResourceDecisions:        []obligations.PerResourceDecision{},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil),
			},
		},
		{
			name:        "first entity - with obligations satisfied",
			accumulated: nil,
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				AllObligationsSatisfied:     true,
				RequiredObligationValueFQNs: []string{testObligation1FQN},
				PerResourceDecisions:        []obligations.PerResourceDecision{mkPerResourceDecision(true, testObligation1FQN)},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN}),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN}),
			},
		},
		{
			name:        "first entity - obligations not satisfied",
			accumulated: nil,
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				AllObligationsSatisfied:     false,
				RequiredObligationValueFQNs: []string{testObligation1FQN},
				PerResourceDecisions:        []obligations.PerResourceDecision{mkPerResourceDecision(false, testObligation1FQN)},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, false, false, []string{testObligation1FQN}),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, false, false, []string{testObligation1FQN}),
			},
		},
		{
			name:        "first entity - not entitled",
			accumulated: nil,
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: false},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				AllObligationsSatisfied:     true,
				RequiredObligationValueFQNs: []string{testObligation1FQN},
				PerResourceDecisions:        []obligations.PerResourceDecision{mkPerResourceDecision(true, testObligation1FQN)},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, false, true, false, nil),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, false, true, false, []string{testObligation1FQN}),
			},
		},
		// Second entity AND scenarios
		{
			name: "second entity - both entitled (AND succeeds)",
			accumulated: []ResourceDecision{
				{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true, Passed: true, ObligationsSatisfied: true},
			},
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				RequiredObligationValueFQNs: []string{},
				PerResourceDecisions:        []obligations.PerResourceDecision{},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil),
			},
		},
		{
			name: "second entity - first entitled, second not (AND fails)",
			accumulated: []ResourceDecision{
				{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true, Passed: true, ObligationsSatisfied: true},
			},
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: false},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				RequiredObligationValueFQNs: []string{},
				PerResourceDecisions:        []obligations.PerResourceDecision{},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, false, true, false, nil),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, false, true, false, nil),
			},
		},
		{
			name: "second entity - obligations preserved when both entitled",
			accumulated: []ResourceDecision{
				{
					ResourceID:                  testResource1ID,
					ResourceName:                testResource1Name,
					Entitled:                    true,
					Passed:                      true,
					ObligationsSatisfied:        true,
					RequiredObligationValueFQNs: []string{testObligation1FQN},
				},
			},
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				RequiredObligationValueFQNs: []string{},
				PerResourceDecisions:        []obligations.PerResourceDecision{},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN}),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil),
			},
		},
		{
			name: "second entity - obligations cleared when second not entitled",
			accumulated: []ResourceDecision{
				{
					ResourceID:                  testResource1ID,
					ResourceName:                testResource1Name,
					Entitled:                    true,
					Passed:                      true,
					ObligationsSatisfied:        true,
					RequiredObligationValueFQNs: []string{testObligation1FQN},
				},
			},
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: false},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				RequiredObligationValueFQNs: []string{},
				PerResourceDecisions:        []obligations.PerResourceDecision{},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, false, true, false, nil),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, false, true, false, nil),
			},
		},
		// Multiple resources
		{
			name: "multiple resources - mixed entitlement",
			accumulated: []ResourceDecision{
				{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true, Passed: true, ObligationsSatisfied: true},
				{ResourceID: testResource2ID, ResourceName: testResource2Name, Entitled: false, Passed: false, ObligationsSatisfied: true},
			},
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true},
					{ResourceID: testResource2ID, ResourceName: testResource2Name, Entitled: true},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				RequiredObligationValueFQNs: []string{},
				PerResourceDecisions:        []obligations.PerResourceDecision{{}, {}},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil),
				mkExpectedResourceDecision(testResource2ID, testResource2Name, false, true, false, nil),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil),
				mkExpectedResourceDecision(testResource2ID, testResource2Name, true, true, true, nil),
			},
		},
		{
			name:        "multiple resources - mixed obligations",
			accumulated: nil,
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true},
					{ResourceID: testResource2ID, ResourceName: testResource2Name, Entitled: false},
					{ResourceID: testResource3ID, ResourceName: testResource3Name, Entitled: true},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				AllObligationsSatisfied:     false,
				RequiredObligationValueFQNs: []string{testObligation1FQN, testObligation2FQN},
				PerResourceDecisions: []obligations.PerResourceDecision{
					mkPerResourceDecision(true, testObligation1FQN),
					mkPerResourceDecision(false, testObligation2FQN),
					mkPerResourceDecision(false, testObligation2FQN),
				},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN}),
				mkExpectedResourceDecision(testResource2ID, testResource2Name, false, false, false, nil),
				mkExpectedResourceDecision(testResource3ID, testResource3Name, true, false, false, []string{testObligation2FQN}),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, []string{testObligation1FQN}),
				mkExpectedResourceDecision(testResource2ID, testResource2Name, false, false, false, []string{testObligation2FQN}),
				mkExpectedResourceDecision(testResource3ID, testResource3Name, true, false, false, []string{testObligation2FQN}),
			},
		},
		{
			name:        "first entity - data rule results in audit only",
			accumulated: nil,
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{
						ResourceID:   testResource1ID,
						ResourceName: testResource1Name,
						Entitled:     true,
						DataRuleResults: []DataRuleResult{
							{
								Passed:            true,
								ResourceValueFQNs: []string{testAttrFQN},
							},
						},
					},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				RequiredObligationValueFQNs: []string{},
				PerResourceDecisions:        []obligations.PerResourceDecision{},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil, DataRuleResult{
					Passed:            true,
					ResourceValueFQNs: []string{testAttrFQN},
				}),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil, DataRuleResult{
					Passed:            true,
					ResourceValueFQNs: []string{testAttrFQN},
				}),
			},
		},
		{
			name: "second entity - data rule results in audit only",
			accumulated: []ResourceDecision{
				{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true, Passed: true, ObligationsSatisfied: true},
			},
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{
						ResourceID:   testResource1ID,
						ResourceName: testResource1Name,
						Entitled:     true,
						DataRuleResults: []DataRuleResult{
							{
								Passed:            true,
								ResourceValueFQNs: []string{testAttrFQN},
							},
						},
					},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{
				RequiredObligationValueFQNs: []string{},
				PerResourceDecisions:        []obligations.PerResourceDecision{},
			},
			expectedConsolidated: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil),
			},
			expectedAudit: []ResourceDecision{
				mkExpectedResourceDecision(testResource1ID, testResource1Name, true, true, true, nil, DataRuleResult{
					Passed:            true,
					ResourceValueFQNs: []string{testAttrFQN},
				}),
			},
		},
		// Error scenarios
		{
			name: "length mismatch error",
			accumulated: []ResourceDecision{
				{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true},
			},
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true},
					{ResourceID: testResource2ID, ResourceName: testResource2Name, Entitled: true},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{},
			expectedErr:        ErrResourceDecisionLengthMismatch,
		},
		{
			name: "resource ID mismatch error",
			accumulated: []ResourceDecision{
				{ResourceID: testResource1ID, ResourceName: testResource1Name, Entitled: true, Passed: true, ObligationsSatisfied: true},
			},
			nextDecision: &Decision{
				Results: []ResourceDecision{
					{ResourceID: testResource2ID, ResourceName: testResource2Name, Entitled: true},
				},
			},
			obligationDecision: obligations.ObligationPolicyDecision{},
			expectedErr:        ErrResourceDecisionIDMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			consolidated, audit, err := applyObligationsAndConsolidate(tt.accumulated, tt.nextDecision, tt.obligationDecision)

			if tt.expectedErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Len(t, consolidated, len(tt.expectedConsolidated))
			require.Len(t, audit, len(tt.expectedAudit))

			for i := range consolidated {
				assertResourceDecision(t, tt.expectedConsolidated[i], consolidated[i], i, "consolidated")
			}

			for i := range audit {
				assertResourceDecision(t, tt.expectedAudit[i], audit[i], i, "audit")
			}
		})
	}
}

func Test_getResourceDecisionableAttributes(t *testing.T) {
	ctx := t.Context()
	logger := logger.CreateTestLogger()

	attr := &policy.Attribute{
		Fqn:  "https://demo.com/attr/adhoc",
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	attrFQN := attr.GetFqn()

	attrSyntheticValue := &policy.Value{
		Fqn:   attrFQN + "/value/direct_entitlement_1",
		Value: "direct_entitlement_1",
	}
	attrSyntheticValueFQN := attrSyntheticValue.GetFqn()

	entitleableAttributesByDefinitionFQN := map[string]*policy.Attribute{
		attrFQN: attr,
	}

	t.Run("direct entitlements - enabled, synthetic value found by definition and returned", func(t *testing.T) {
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{attrSyntheticValueFQN},
					},
				},
			},
		}

		decisionableAttrs, err := getResourceDecisionableAttributes(ctx, logger,
			nil, // registered resources are not used by direct entitlements
			nil, // direct entitlements will not be in entitleableAttributesByValueFQN map, due to synthetic values
			entitleableAttributesByDefinitionFQN,
			resources,
			true, // allow direct entitlements
		)
		require.NoError(t, err)
		require.Len(t, decisionableAttrs, 1)
		require.Contains(t, decisionableAttrs, attrSyntheticValueFQN)
		require.Equal(t, attr, decisionableAttrs[attrSyntheticValueFQN].GetAttribute())
		require.Equal(t, attrSyntheticValue, decisionableAttrs[attrSyntheticValueFQN].GetValue())
	})

	t.Run("direct entitlements - enabled, synthetic value NOT found by definition and error returned", func(t *testing.T) {
		invalidAttrValueFQN := "https://invalid.com/attr/non_existent/value/direct_entitlement"
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{invalidAttrValueFQN},
					},
				},
			},
		}

		decisionableAttrs, err := getResourceDecisionableAttributes(ctx, logger,
			nil, // registered resources are not used by direct entitlements
			nil, // direct entitlements will not be in entitleableAttributesByValueFQN map, due to synthetic values
			entitleableAttributesByDefinitionFQN,
			resources,
			true, // allow direct entitlements
		)
		require.EqualError(t, err, fmt.Sprintf("resource FQNs not found in memory %v: %s", []string{invalidAttrValueFQN}, ErrFQNNotFound))
		require.Empty(t, decisionableAttrs)
	})

	t.Run("direct entitlements - disabled, synthetic value NOT found by definition and error returned", func(t *testing.T) {
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{attrSyntheticValueFQN},
					},
				},
			},
		}

		decisionableAttrs, err := getResourceDecisionableAttributes(ctx, logger,
			nil, // registered resources are not used by direct entitlements
			nil, // direct entitlements will not be in entitleableAttributesByValueFQN map, due to synthetic values
			entitleableAttributesByDefinitionFQN,
			resources,
			false, // disable direct entitlements
		)
		require.EqualError(t, err, fmt.Sprintf("resource FQNs not found in memory %v: %s", []string{attrSyntheticValueFQN}, ErrFQNNotFound))
		require.Empty(t, decisionableAttrs)
	})
}
