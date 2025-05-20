package access

import (
	"testing"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/policy/actions"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestValidateGetDecision(t *testing.T) {
	validEntityRepresentation := &entityresolutionV2.EntityRepresentation{
		OriginalId: "entity-id",
		AdditionalProps: []*structpb.Struct{
			{
				Fields: map[string]*structpb.Value{
					"key": structpb.NewStringValue("value"),
				},
			},
		},
	}

	validAction := &policy.Action{
		Name: "read",
	}

	validResources := []*authzV2.Resource{
		{
			Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{
					Fqns: []string{"https://example.org/attr/classification/value/public"},
				},
			},
		},
	}

	tests := []struct {
		name      string
		entityRep *entityresolutionV2.EntityRepresentation
		action    *policy.Action
		resources []*authzV2.Resource
		wantErr   error
	}{
		{
			name:      "Valid inputs",
			entityRep: validEntityRepresentation,
			action:    validAction,
			resources: validResources,
			wantErr:   nil,
		},
		{
			name:      "Nil entity representation",
			entityRep: nil,
			action:    validAction,
			resources: validResources,
			wantErr:   ErrInvalidEntityChain,
		},
		{
			name:      "Nil action",
			entityRep: validEntityRepresentation,
			action:    nil,
			resources: validResources,
			wantErr:   ErrInvalidAction,
		},
		{
			name:      "Empty resources",
			entityRep: validEntityRepresentation,
			action:    validAction,
			resources: []*authzV2.Resource{},
			wantErr:   ErrInvalidResource,
		},
		{
			name:      "Nil resources",
			entityRep: validEntityRepresentation,
			action:    validAction,
			resources: nil,
			wantErr:   ErrInvalidResource,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGetDecision(tt.entityRep, tt.action, tt.resources)
			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateSubjectMapping(t *testing.T) {
	validFQN := "https://example.org/attr/classification/value/public"
	validValue := &policy.Value{
		Fqn: validFQN,
	}
	validActions := []*policy.Action{
		{
			Id:   "action-1",
			Name: "read",
		},
	}

	tests := []struct {
		name           string
		subjectMapping *policy.SubjectMapping
		wantErr        error
	}{
		{
			name: "Valid subject mapping",
			subjectMapping: &policy.SubjectMapping{
				AttributeValue: validValue,
				Actions:        validActions,
			},
			wantErr: nil,
		},
		{
			name:           "Nil subject mapping",
			subjectMapping: nil,
			wantErr:        ErrInvalidSubjectMapping,
		},
		{
			name: "Nil attribute value",
			subjectMapping: &policy.SubjectMapping{
				AttributeValue: nil,
				Actions:        validActions,
			},
			wantErr: ErrInvalidSubjectMapping,
		},
		{
			name: "Empty attribute value FQN",
			subjectMapping: &policy.SubjectMapping{
				AttributeValue: &policy.Value{
					Fqn: "",
				},
				Actions: validActions,
			},
			wantErr: ErrInvalidSubjectMapping,
		},
		{
			name: "Nil actions",
			subjectMapping: &policy.SubjectMapping{
				AttributeValue: validValue,
				Actions:        nil,
			},
			wantErr: ErrInvalidSubjectMapping,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSubjectMapping(tt.subjectMapping)
			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateAttribute(t *testing.T) {
	validValues := []*policy.Value{
		{
			Fqn: "https://example.org/attr/name/value/public",
		},
	}

	tests := []struct {
		name      string
		attribute *policy.Attribute
		wantErr   error
	}{
		{
			name: "Valid attribute",
			attribute: &policy.Attribute{
				Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				Fqn:    "https://example.org/attr/name",
				Values: validValues,
			},
			wantErr: nil,
		},
		{
			name: "Unspecified attribute rule",
			attribute: &policy.Attribute{
				Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
				Fqn:    "https://example.org/attr/name",
				Values: validValues,
			},
			wantErr: ErrInvalidAttributeDefinition,
		},
		{
			name: "Missing attribute rule",
			attribute: &policy.Attribute{
				Fqn:    "https://example.org/attr/name",
				Values: validValues,
			},
			wantErr: ErrInvalidAttributeDefinition,
		},
		{
			name:      "Nil attribute",
			attribute: nil,
			wantErr:   ErrInvalidAttributeDefinition,
		},
		{
			name: "Empty attribute FQN",
			attribute: &policy.Attribute{
				Fqn:    "",
				Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				Values: validValues,
			},
			wantErr: ErrInvalidAttributeDefinition,
		},
		{
			name: "Empty attribute values",
			attribute: &policy.Attribute{
				Fqn:    "https://example.org/attr/name",
				Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				Values: []*policy.Value{},
			},
			wantErr: ErrInvalidAttributeDefinition,
		},
		{
			name: "Nil attribute values",
			attribute: &policy.Attribute{
				Fqn:    "https://example.org/attr/name",
				Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
				Values: nil,
			},
			wantErr: ErrInvalidAttributeDefinition,
		},
		{
			name: "Nil value in attribute values",
			attribute: &policy.Attribute{
				Fqn:    "https://example.org/attr/name",
				Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				Values: []*policy.Value{nil},
			},
			wantErr: ErrInvalidAttributeDefinition,
		},
		{
			name: "Empty FQN in attribute value",
			attribute: &policy.Attribute{
				Fqn:  "https://example.org/attr/name",
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				Values: []*policy.Value{
					{
						Fqn: "",
					},
				},
			},
			wantErr: ErrInvalidAttributeDefinition,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAttribute(tt.attribute)
			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateEntityRepresentations(t *testing.T) {
	tests := []struct {
		name                  string
		entityRepresentations []*entityresolutionV2.EntityRepresentation
		wantErr               error
	}{
		{
			name:                  "Valid entity representations",
			entityRepresentations: []*entityresolutionV2.EntityRepresentation{{}},
			wantErr:               nil,
		},
		{
			name:                  "Nil entity representations",
			entityRepresentations: nil,
			wantErr:               ErrInvalidEntityChain,
		},
		{
			name:                  "Empty entity representations",
			entityRepresentations: []*entityresolutionV2.EntityRepresentation{},
			wantErr:               ErrInvalidEntityChain,
		},
		{
			name:                  "Entity representation is nil",
			entityRepresentations: []*entityresolutionV2.EntityRepresentation{nil},
			wantErr:               ErrInvalidEntityChain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEntityRepresentations(tt.entityRepresentations)
			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateGetResourceDecision(t *testing.T) {
	// non-nil policy map
	validDecisionableAttributes := map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		"https://example.org/attr/classification/value/public": {},
	}

	// non-nil entitlements mapmap
	validEntitledFQNsToActions := map[string][]*policy.Action{
		"https://example.org/attr/name/value/public": {},
	}

	// non-nil action
	validAction := &policy.Action{
		Name: actions.ActionNameRead,
	}

	// non-nil resource
	validResource := &authzV2.Resource{
		Resource: &authzV2.Resource_AttributeValues_{
			AttributeValues: &authzV2.Resource_AttributeValues{
				Fqns: []string{"https://example.org/attr/classification/value/public"},
			},
		},
	}

	tests := []struct {
		name                      string
		accessibleAttributeValues map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
		entitlements              map[string][]*policy.Action
		action                    *policy.Action
		resource                  *authzV2.Resource
		wantErr                   error
	}{
		{
			name:                      "Valid inputs",
			accessibleAttributeValues: validDecisionableAttributes,
			entitlements:              validEntitledFQNsToActions,
			action:                    validAction,
			resource:                  validResource,
			wantErr:                   nil,
		},
		{
			name:                      "Nil accessible attribute values",
			accessibleAttributeValues: nil,
			entitlements:              validEntitledFQNsToActions,
			action:                    validAction,
			resource:                  validResource,
			wantErr:                   ErrMissingRequiredPolicy,
		},
		{
			name:                      "Nil entitlements",
			accessibleAttributeValues: validDecisionableAttributes,
			entitlements:              nil,
			action:                    validAction,
			resource:                  validResource,
			wantErr:                   ErrInvalidEntitledFQNsToActions,
		},
		{
			name:                      "Nil action",
			accessibleAttributeValues: validDecisionableAttributes,
			entitlements:              validEntitledFQNsToActions,
			action:                    nil,
			resource:                  validResource,
			wantErr:                   ErrInvalidAction,
		},
		{
			name:                      "Nil resource",
			accessibleAttributeValues: validDecisionableAttributes,
			entitlements:              validEntitledFQNsToActions,
			action:                    validAction,
			resource:                  nil,
			wantErr:                   ErrInvalidResource,
		},
		{
			name:                      "Empty accessible attribute values",
			accessibleAttributeValues: map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{},
			entitlements:              validEntitledFQNsToActions,
			action:                    validAction,
			resource:                  validResource,
			wantErr:                   ErrMissingRequiredPolicy,
		},
		{
			name:                      "Empty action",
			accessibleAttributeValues: validDecisionableAttributes,
			entitlements:              validEntitledFQNsToActions,
			action:                    &policy.Action{},
			resource:                  validResource,
			wantErr:                   ErrInvalidAction,
		},
		{
			name:                      "Empty resource",
			accessibleAttributeValues: validDecisionableAttributes,
			entitlements:              validEntitledFQNsToActions,
			action:                    validAction,
			resource:                  &authzV2.Resource{},
			wantErr:                   ErrInvalidResource,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGetResourceDecision(tt.accessibleAttributeValues, tt.entitlements, tt.action, tt.resource)
			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
