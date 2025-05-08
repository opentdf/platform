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
	validFQN := "https://example.org/attr/classification/value/public"
	validAttributeAndValue := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		Value: &policy.Value{
			Fqn: validFQN,
		},
		Attribute: &policy.Attribute{
			Fqn: "https://example.org/attr/classification",
		},
	}

	validSubjectMapping := &policy.SubjectMapping{
		AttributeValue: &policy.Value{
			Fqn: validFQN,
		},
	}

	allEntitleableAttributes := map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		validFQN: validAttributeAndValue,
	}

	tests := []struct {
		name                     string
		matchedSubjectMappings   []*policy.SubjectMapping
		allEntitleableAttributes map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
		wantErr                  bool
	}{
		{
			name:                     "Valid subject mapping",
			matchedSubjectMappings:   []*policy.SubjectMapping{validSubjectMapping},
			allEntitleableAttributes: allEntitleableAttributes,
			wantErr:                  false,
		},
		{
			name: "Invalid subject mapping",
			matchedSubjectMappings: []*policy.SubjectMapping{{
				AttributeValue: &policy.Value{
					Fqn: "invalid-fqn",
				},
			}},
			allEntitleableAttributes: allEntitleableAttributes,
			wantErr:                  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, err := getFilteredEntitleableAttributes(tt.matchedSubjectMappings, tt.allEntitleableAttributes)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, filtered, validFQN, "Expected filtered results to contain valid FQN")
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
