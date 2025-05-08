package access

import (
	"errors"
	"testing"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
)

func TestValidateGetDecision(t *testing.T) {
	validEntityChain := &authz.EntityChain{
		Entities: []*authz.Entity{
			{
				EphemeralId: "entity-1",
			},
		},
	}

	validAction := &policy.Action{
		Name: "read",
	}

	validResources := []*authz.Resource{
		{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{"https://example.org/attr/classification/value/public"},
				},
			},
		},
	}

	tests := []struct {
		name      string
		chain     *authz.EntityChain
		action    *policy.Action
		resources []*authz.Resource
		wantErr   error
	}{
		{
			name:      "Valid inputs",
			chain:     validEntityChain,
			action:    validAction,
			resources: validResources,
			wantErr:   nil,
		},
		{
			name:      "Nil entity chain",
			chain:     nil,
			action:    validAction,
			resources: validResources,
			wantErr:   ErrInvalidEntityChain,
		},
		{
			name:      "Empty entity chain",
			chain:     &authz.EntityChain{},
			action:    validAction,
			resources: validResources,
			wantErr:   ErrInvalidEntityChain,
		},
		{
			name:      "Nil action",
			chain:     validEntityChain,
			action:    nil,
			resources: validResources,
			wantErr:   ErrInvalidAction,
		},
		{
			name:      "Empty resources",
			chain:     validEntityChain,
			action:    validAction,
			resources: []*authz.Resource{},
			wantErr:   ErrInvalidResourceType,
		},
		{
			name:      "Nil resources",
			chain:     validEntityChain,
			action:    validAction,
			resources: nil,
			wantErr:   ErrInvalidResourceType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGetDecision(tt.chain, tt.action, tt.resources)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, tt.wantErr), "Expected error %v, got %v", tt.wantErr, err)
			} else {
				assert.NoError(t, err)
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
				assert.Error(t, err)
				assert.True(t, errors.Is(err, tt.wantErr), "Expected error %v, got %v", tt.wantErr, err)
			} else {
				assert.NoError(t, err)
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
				Fqn:    "https://example.org/attr/name",
				Values: validValues,
			},
			wantErr: nil,
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
				Values: validValues,
			},
			wantErr: ErrInvalidAttributeDefinition,
		},
		{
			name: "Empty attribute values",
			attribute: &policy.Attribute{
				Fqn:    "https://example.org/attr/name",
				Values: []*policy.Value{},
			},
			wantErr: ErrInvalidAttributeDefinition,
		},
		{
			name: "Nil attribute values",
			attribute: &policy.Attribute{
				Fqn:    "https://example.org/attr/name",
				Values: nil,
			},
			wantErr: ErrInvalidAttributeDefinition,
		},
		{
			name: "Nil value in attribute values",
			attribute: &policy.Attribute{
				Fqn:    "https://example.org/attr/name",
				Values: []*policy.Value{nil},
			},
			wantErr: ErrInvalidAttributeDefinition,
		},
		{
			name: "Empty FQN in attribute value",
			attribute: &policy.Attribute{
				Fqn: "https://example.org/attr/name",
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
				assert.Error(t, err)
				assert.True(t, errors.Is(err, tt.wantErr), "Expected error %v, got %v", tt.wantErr, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateEntityRepresentations(t *testing.T) {
	tests := []struct {
		name                  string
		entityRepresentations []*entityresolution.EntityRepresentation
		wantErr               error
	}{
		{
			name:                  "Valid entity representations",
			entityRepresentations: []*entityresolution.EntityRepresentation{{}},
			wantErr:               nil,
		},
		{
			name:                  "Nil entity representations",
			entityRepresentations: nil,
			wantErr:               ErrInvalidEntityChain,
		},
		{
			name:                  "Empty entity representations",
			entityRepresentations: []*entityresolution.EntityRepresentation{},
			wantErr:               ErrInvalidEntityChain,
		},
		{
			name:                  "Entity representation is nil",
			entityRepresentations: []*entityresolution.EntityRepresentation{nil},
			wantErr:               ErrInvalidEntityChain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEntityRepresentations(tt.entityRepresentations)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, tt.wantErr), "Expected error %v, got %v", tt.wantErr, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
