package access

import (
	"testing"

	"github.com/opentdf/platform/lib/identifier"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
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
		{
			name: "Attribute value FQN does not match attribute FQN",
			attribute: &policy.Attribute{
				Fqn:  "https://example.org/attr/name",
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				Values: []*policy.Value{
					{
						Fqn: "https://example.org/attr/other/value/public",
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
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateRegisteredResource(t *testing.T) {
	tests := []struct {
		name               string
		registeredResource *policy.RegisteredResource
		wantErr            error
	}{
		{
			name: "Valid registered resource",
			registeredResource: &policy.RegisteredResource{
				Name: "valid-resource",
			},
			wantErr: nil,
		},
		{
			name:               "Nil registered resource",
			registeredResource: nil,
			wantErr:            ErrInvalidRegisteredResource,
		},
		{
			name: "Empty registered resource name",
			registeredResource: &policy.RegisteredResource{
				Name: "",
			},
			wantErr: ErrInvalidRegisteredResource,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRegisteredResource(tt.registeredResource)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateRegisteredResourceValue(t *testing.T) {
	tests := []struct {
		name                    string
		registeredResourceValue *policy.RegisteredResourceValue
		wantErr                 error
	}{
		{
			name: "Valid registered resource value",
			registeredResourceValue: &policy.RegisteredResourceValue{
				Value: "valid-value",
			},
			wantErr: nil,
		},
		{
			name:                    "Nil registered resource value",
			registeredResourceValue: nil,
			wantErr:                 ErrInvalidRegisteredResourceValue,
		},
		{
			name: "Empty registered resource value",
			registeredResourceValue: &policy.RegisteredResourceValue{
				Value: "",
			},
			wantErr: ErrInvalidRegisteredResourceValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRegisteredResourceValue(tt.registeredResourceValue)
			if tt.wantErr != nil {
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
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateGetResourceDecision(t *testing.T) {
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
		name         string
		entitlements map[string][]*policy.Action
		action       *policy.Action
		resource     *authzV2.Resource
		wantErr      error
	}{
		{
			name:         "Valid inputs",
			entitlements: validEntitledFQNsToActions,
			action:       validAction,
			resource:     validResource,
			wantErr:      nil,
		},
		{
			name:         "Nil entitlements",
			entitlements: nil,
			action:       validAction,
			resource:     validResource,
			wantErr:      ErrInvalidEntitledFQNsToActions,
		},
		{
			name:         "Nil action",
			entitlements: validEntitledFQNsToActions,
			action:       nil,
			resource:     validResource,
			wantErr:      ErrInvalidAction,
		},
		{
			name:         "Nil resource",
			entitlements: validEntitledFQNsToActions,
			action:       validAction,
			resource:     nil,
			wantErr:      ErrInvalidResource,
		},
		{
			name:         "Empty action",
			entitlements: validEntitledFQNsToActions,
			action:       &policy.Action{},
			resource:     validResource,
			wantErr:      ErrInvalidAction,
		},
		{
			name:         "Empty resource",
			entitlements: validEntitledFQNsToActions,
			action:       validAction,
			resource:     &authzV2.Resource{},
			wantErr:      ErrInvalidResource,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGetResourceDecision(tt.entitlements, tt.action, tt.resource)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateGetDecisionRegisteredResource(t *testing.T) {
	validRegisteredResourceValueFQN := "https://reg_res/resource1/value/value1"

	validAction := &policy.Action{
		Name: "read",
	}

	emptyNameAction := &policy.Action{
		Name: "",
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
		name                       string
		registeredResourceValueFQN string
		action                     *policy.Action
		resources                  []*authzV2.Resource
		wantErr                    error
	}{
		{
			name:                       "Valid inputs",
			registeredResourceValueFQN: validRegisteredResourceValueFQN,
			action:                     validAction,
			resources:                  validResources,
			wantErr:                    nil,
		},
		{
			name:                       "Invalid registered resource value FQN",
			registeredResourceValueFQN: "invalid-fqn",
			action:                     validAction,
			resources:                  validResources,
			wantErr:                    identifier.ErrInvalidFQNFormat,
		},
		{
			name:                       "Empty action name",
			registeredResourceValueFQN: validRegisteredResourceValueFQN,
			action:                     emptyNameAction,
			resources:                  validResources,
			wantErr:                    ErrInvalidAction,
		},
		{
			name:                       "Empty resources",
			registeredResourceValueFQN: validRegisteredResourceValueFQN,
			action:                     validAction,
			resources:                  []*authzV2.Resource{},
			wantErr:                    ErrInvalidResource,
		},
		{
			name:                       "Nil resource in list",
			registeredResourceValueFQN: validRegisteredResourceValueFQN,
			action:                     validAction,
			resources:                  []*authzV2.Resource{nil},
			wantErr:                    ErrInvalidResource,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGetDecisionRegisteredResource(tt.registeredResourceValueFQN, tt.action, tt.resources)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
