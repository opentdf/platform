package access

import (
	"testing"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/policy/actions"
	"github.com/stretchr/testify/assert"
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
			name:        "Invalid FQN",
			valueFQN:    invalidFQN,
			definitions: definitions,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getDefinition(tt.valueFQN, tt.definitions)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
			_, err := getFilteredEntitleableAttributes(tt.matchedSubjectMappings, tt.allEntitleableAttributes)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPopulateLowerValuesIfHierarchy(t *testing.T) {
	validFQN := "https://example.org/attr/classification/value/public"
	validAttributeAndValue := &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		Attribute: &policy.Attribute{
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{
				{Fqn: "https://example.org/attr/classification/value/confidential"},
				{Fqn: validFQN},
				{Fqn: "https://example.org/attr/classification/value/restricted"},
			},
		},
	}

	entitledActions := &authz.EntityEntitlements_ActionsList{
		Actions: []*policy.Action{
			{Name: actions.ActionNameRead},
			{Name: actions.ActionNameCreate},
		},
	}

	actionsPerAttributeValueFqn := make(map[string]*authz.EntityEntitlements_ActionsList)

	tests := []struct {
		name                        string
		valueFQN                    string
		attributeAndValue           *attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
		entitledActions             *authz.EntityEntitlements_ActionsList
		actionsPerAttributeValueFqn map[string]*authz.EntityEntitlements_ActionsList
		wantErr                     bool
	}{
		{
			name:                        "Valid hierarchy attribute",
			valueFQN:                    validFQN,
			attributeAndValue:           validAttributeAndValue,
			entitledActions:             entitledActions,
			actionsPerAttributeValueFqn: actionsPerAttributeValueFqn,
			wantErr:                     false,
		},
		{
			name:     "Missing attribute rule",
			valueFQN: validFQN,
			attributeAndValue: &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				Attribute: &policy.Attribute{},
			},
			entitledActions:             entitledActions,
			actionsPerAttributeValueFqn: actionsPerAttributeValueFqn,
			wantErr:                     true,
		},
		{
			name:     "ANY_OF attribute rule",
			valueFQN: validFQN,
			attributeAndValue: &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				Attribute: &policy.Attribute{
					Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				},
			},
			entitledActions:             entitledActions,
			actionsPerAttributeValueFqn: actionsPerAttributeValueFqn,
			wantErr:                     true,
		},
		{
			name:     "ALL_OF attribute rule",
			valueFQN: validFQN,
			attributeAndValue: &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				Attribute: &policy.Attribute{
					Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				},
			},
			entitledActions:             entitledActions,
			actionsPerAttributeValueFqn: actionsPerAttributeValueFqn,
			wantErr:                     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := populateLowerValuesIfHierarchy(tt.valueFQN, tt.attributeAndValue, tt.entitledActions, tt.actionsPerAttributeValueFqn)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
