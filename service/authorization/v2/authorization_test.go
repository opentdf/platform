package authorization

import (
	"math/rand"
	"strconv"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/opentdf/platform/lib/identifier"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	sampleActionCreate = &policy.Action{
		Name: "create",
	}
	sampleResourceFQN           = "https://example.com/attr/hier/value/highest"
	sampleResourceFQN2          = "https://example.com/attr/hier/value/lowest"
	sampleRegisteredResourceFQN = "https://example.com/reg_res/system/value/internal"
	sampleObligationValueFQN    = "https://example.com/obl/drm/value/prevent_print"

	// Good multi-resource requests that should pass validation
	goodMultiResourceRequests = []struct {
		name    string
		request *authzV2.GetDecisionMultiResourceRequest
	}{
		{
			name: "entity: token, action: create, multiple resources: attribute values",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{sampleResourceFQN},
							},
						},
					},
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{sampleResourceFQN2},
							},
						},
					},
				},
			},
		},
		{
			name: "entity: chain, action: create, multiple resources: mixed types",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_EntityChain{
						EntityChain: &entity.EntityChain{
							EphemeralId: "1234",
							Entities: []*entity.Entity{
								{
									EphemeralId: "chained-1",
									EntityType:  &entity.Entity_EmailAddress{EmailAddress: "test@test.com"},
									Category:    entity.Entity_CATEGORY_SUBJECT,
								},
							},
						},
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{sampleResourceFQN},
							},
						},
					},
					{
						Resource: &authzV2.Resource_RegisteredResourceValueFqn{
							RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
						},
					},
				},
			},
		},
		{
			name: "entity: registered resource, action: create, multiple resources: registered",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_RegisteredResourceValueFqn{
							RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
						},
					},
					{
						Resource: &authzV2.Resource_RegisteredResourceValueFqn{
							RegisteredResourceValueFqn: "https://example.com/another/registered/resource",
						},
					},
				},
			},
		},
	}

	// Bad multi-resource requests that should fail validation
	badMultiResourceRequests = []struct {
		name                    string
		request                 *authzV2.GetDecisionMultiResourceRequest
		expectedValidationError string
	}{
		{
			name: "missing entity identifier",
			request: &authzV2.GetDecisionMultiResourceRequest{
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{sampleResourceFQN},
							},
						},
					},
				},
			},
			expectedValidationError: "entity_identifier",
		},
		{
			name: "entity identifier - request token invalid",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_UseRequestToken{
						UseRequestToken: wrapperspb.Bool(false),
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{sampleResourceFQN},
							},
						},
					},
				},
			},
			expectedValidationError: "entity_identifier",
		},
		{
			name: "missing action",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{sampleResourceFQN},
							},
						},
					},
				},
			},
			expectedValidationError: "action",
		},
		{
			name: "action missing name",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: &policy.Action{},
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{sampleResourceFQN},
							},
						},
					},
				},
			},
			expectedValidationError: "name",
		},
		{
			name: "missing resources",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
			},
			expectedValidationError: "resources",
		},
		{
			name: "empty resources array",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action:    sampleActionCreate,
				Resources: []*authzV2.Resource{},
			},
			expectedValidationError: "resources",
		},
		{
			name: "invalid resource - registered resource FQN is empty",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_RegisteredResourceValueFqn{},
					},
				},
			},
			expectedValidationError: "resource",
		},
		{
			name: "invalid resource - empty attribute values",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{},
							},
						},
					},
				},
			},
			expectedValidationError: "resource",
		},
		{
			name: "invalid resource - invalid attribute values",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{"invalid-format"},
							},
						},
					},
				},
			},
			expectedValidationError: "resource",
		},
		{
			name: "token entity with empty JWT",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
						},
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{sampleResourceFQN},
							},
						},
					},
				},
			},
			expectedValidationError: "jwt",
		},
		{
			name: "entity chain with no entities",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_EntityChain{
						EntityChain: &entity.EntityChain{
							EphemeralId: "1234",
						},
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{sampleResourceFQN},
							},
						},
					},
				},
			},
			expectedValidationError: "entities",
		},
		{
			name: "registered resource as entity with invalid URI",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: "invalid uri",
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{sampleResourceFQN},
							},
						},
					},
				},
			},
			expectedValidationError: "registered_resource_value_fqn",
		},
		{
			name: "too many obligations",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_EntityChain{
						EntityChain: &entity.EntityChain{
							EphemeralId: "1234",
							Entities: []*entity.Entity{
								{
									EphemeralId: "chained-1",
									EntityType:  &entity.Entity_EmailAddress{EmailAddress: "test@test.com"},
									Category:    entity.Entity_CATEGORY_SUBJECT,
								},
							},
						},
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_AttributeValues_{
							AttributeValues: &authzV2.Resource_AttributeValues{
								Fqns: []string{sampleResourceFQN},
							},
						},
					},
					{
						Resource: &authzV2.Resource_RegisteredResourceValueFqn{
							RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
						},
					},
				},
				FulfillableObligationFqns: getTooManyObligations(),
			},
			expectedValidationError: "obligation_value_fqns_valid",
		},
		{
			name: "invalid obligation",
			request: &authzV2.GetDecisionMultiResourceRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				Action: sampleActionCreate,
				Resources: []*authzV2.Resource{
					{
						Resource: &authzV2.Resource_RegisteredResourceValueFqn{
							RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
						},
					},
				},
				FulfillableObligationFqns: []string{"missing.scheme/obl/name/value/val"},
			},
			expectedValidationError: "obligation_value_fqns_valid",
		},
	}
)

func getValidator() protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func Test_EntityIdentifier_ManyChainedEntities(t *testing.T) {
	v := getValidator()
	// many entities in chain
	entityIdentifier := &authzV2.EntityIdentifier{
		Identifier: &authzV2.EntityIdentifier_EntityChain{
			EntityChain: &entity.EntityChain{
				EphemeralId: "1234",
				Entities:    make([]*entity.Entity, 10),
			},
		},
	}
	for i := range 10 {
		entityIdentifier.GetEntityChain().Entities[i] = &entity.Entity{
			EphemeralId: "chained-" + strconv.Itoa(i),
			EntityType:  &entity.Entity_EmailAddress{EmailAddress: "test@test.com"},
			Category:    entity.Entity_CATEGORY_SUBJECT,
		}
	}
	err := v.Validate(entityIdentifier)
	require.NoError(t, err, "validation should succeed for request with up to 10 entities in chain")

	// add one more
	entityIdentifier.GetEntityChain().Entities = append(entityIdentifier.GetEntityChain().Entities, &entity.Entity{
		EphemeralId: "chained-10",
		EntityType:  &entity.Entity_EmailAddress{EmailAddress: "test@test.com"},
		Category:    entity.Entity_CATEGORY_SUBJECT,
	})
	err = v.Validate(entityIdentifier)
	require.Error(t, err, "validation should fail for request with 11 entities in chain")
}

func Test_Resource_ManyAttributeValues(t *testing.T) {
	v := getValidator()
	resource := &authzV2.Resource{
		Resource: &authzV2.Resource_AttributeValues_{
			AttributeValues: &authzV2.Resource_AttributeValues{
				Fqns: make([]string, 20),
			},
		},
	}
	for i := range 20 {
		resource.GetAttributeValues().Fqns[i] = "https://example.com/attr/any_of_attr_name/value/val" + strconv.Itoa(i)
	}
	err := v.Validate(resource)
	require.NoError(t, err, "validation should succeed for request with 20 attribute values")

	// add one more
	resource.GetAttributeValues().Fqns = append(resource.GetAttributeValues().Fqns, "https://example.com/attr/any_of_attr_name/value/val20")
	err = v.Validate(resource)
	require.Error(t, err, "validation should fail for request with 21 attribute values")
}

func Test_GetDecisionRequest_Succeeds(t *testing.T) {
	v := getValidator()
	fiftyObligations := make([]string, 50)
	for i := range 50 {
		fiftyObligations[i] = sampleObligationValueFQN
	}

	cases := []struct {
		name    string
		request *authzV2.GetDecisionRequest
	}{
		{
			name: "entity: token, action: create, resource: attribute values",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{sampleResourceFQN},
						},
					},
				},
			},
		},
		{
			name: "entity: use request token, action: create, resource: attribute values",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_UseRequestToken{
						UseRequestToken: wrapperspb.Bool(true),
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{sampleResourceFQN},
						},
					},
				},
			},
		},
		{
			name: "entity: token, action: create, resource: registered",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
			},
		},
		{
			name: "entity: chain, action: create, resource: attribute values",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_EntityChain{
						EntityChain: &entity.EntityChain{
							EphemeralId: "1234",
							Entities: []*entity.Entity{
								{
									EphemeralId: "chained-1",
									EntityType:  &entity.Entity_EmailAddress{EmailAddress: "test@test.com"},
									Category:    entity.Entity_CATEGORY_SUBJECT,
								},
								{
									EphemeralId: "chained-2",
									EntityType: &entity.Entity_ClientId{
										ClientId: "client-123",
									},
									Category: entity.Entity_CATEGORY_ENVIRONMENT,
								},
							},
						},
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{sampleResourceFQN, sampleResourceFQN2},
						},
					},
				},
			},
		},
		{
			name: "entity: chain, action: create, resource: registered",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_EntityChain{
						EntityChain: &entity.EntityChain{
							EphemeralId: "1234",
							Entities: []*entity.Entity{
								{
									EphemeralId: "chained-1",
									EntityType: &entity.Entity_ClientId{
										ClientId: "client-123",
									},
									Category: entity.Entity_CATEGORY_ENVIRONMENT,
								},
							},
						},
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
			},
		},
		{
			name: "entity: registered resource, action: create, resource: attribute values",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{sampleResourceFQN2},
						},
					},
				},
			},
		},
		{
			name: "entity: registered resource, action: create, resource: registered",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
			},
		},
		{
			name: "entity: registered resource, action: create, resource: registered, obligations - 1",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				FulfillableObligationFqns: []string{sampleObligationValueFQN},
			},
		},
		{
			name: "entity: registered resource, action: create, resource: registered, obligations - 50",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				FulfillableObligationFqns: fiftyObligations,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.request)
			require.NoError(t, err, "validation should succeed for request: %s", tc.name)
		})
	}
}

func Test_GetDecisionRequest_Fails(t *testing.T) {
	v := getValidator()

	cases := []struct {
		name                    string
		request                 *authzV2.GetDecisionRequest
		expectedValidationError string
	}{
		{
			name: "missing entity identifier",
			request: &authzV2.GetDecisionRequest{
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{sampleResourceFQN},
						},
					},
				},
			},
			expectedValidationError: "entity_identifier",
		},
		{
			name: "entity identifier (request token) but nil",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_UseRequestToken{
						UseRequestToken: nil,
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{sampleResourceFQN},
						},
					},
				},
			},
			expectedValidationError: "entity_identifier",
		},
		{
			name: "entity identifier (request token) but false",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_UseRequestToken{
						UseRequestToken: wrapperspb.Bool(false),
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{sampleResourceFQN},
						},
					},
				},
			},
			expectedValidationError: "entity_identifier",
		},
		{
			name: "missing action",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{sampleResourceFQN},
						},
					},
				},
			},
			expectedValidationError: "action",
		},
		{
			name: "missing resource",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
			},
			expectedValidationError: "resource",
		},
		{
			name: "action missing name",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: &policy.Action{},
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{sampleResourceFQN},
						},
					},
				},
			},
			expectedValidationError: "name",
		},
		{
			name: "registered resource FQN is empty",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_RegisteredResourceValueFqn{},
				},
			},
			expectedValidationError: "resource",
		},
		{
			name: "registered resource FQN is invalid",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: "invalid format",
					},
				},
			},
			expectedValidationError: "resource",
		},
		{
			name: "resource attribute value FQNs are empty",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{},
						},
					},
				},
			},
			expectedValidationError: "resource",
		},
		{
			name: "resource attribute value FQNs are invalid",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{"invalid-format"},
						},
					},
				},
			},
			expectedValidationError: "resource",
		},
		{
			name: "token entity with empty JWT",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
						},
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{sampleResourceFQN},
						},
					},
				},
			},
			expectedValidationError: "jwt",
		},
		{
			name: "entity chain with no entities",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_EntityChain{
						EntityChain: &entity.EntityChain{
							EphemeralId: "1234",
						},
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_AttributeValues_{
						AttributeValues: &authzV2.Resource_AttributeValues{
							Fqns: []string{sampleResourceFQN},
						},
					},
				},
			},
			expectedValidationError: "entities",
		},
		{
			name: "too many obligations",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				FulfillableObligationFqns: getTooManyObligations(),
			},
			expectedValidationError: "obligation_value_fqns_valid",
		},
		{
			name: "invalid obligation format",
			request: &authzV2.GetDecisionRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				Action: sampleActionCreate,
				Resource: &authzV2.Resource{
					Resource: &authzV2.Resource_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
				FulfillableObligationFqns: []string{"invalid-format"},
			},
			expectedValidationError: "obligation_value_fqns_valid",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.request)
			if err == nil {
				t.Errorf("expected validation error for request: %s, but got none", tc.name)
			} else {
				assert.Contains(t, err.Error(), tc.expectedValidationError, "validation error should contain expected message")
			}
		})
	}
}

func Test_GetDecisionMultiResourceRequest_Succeeds(t *testing.T) {
	v := getValidator()

	// All known good cases should pass
	for _, tc := range goodMultiResourceRequests {
		t.Run(tc.name, func(t *testing.T) {
			clonedReq, _ := proto.Clone(tc.request).(*authzV2.GetDecisionMultiResourceRequest)
			clonedReq.FulfillableObligationFqns = getRandomValidObligationValueFQNsList()
			err := v.Validate(tc.request)
			require.NoError(t, err, "validation should succeed for request: %s", tc.name)
		})
	}
}

func Test_GetDecisionMultiResourceRequest_ResourceLimit(t *testing.T) {
	v := getValidator()
	upperBoundLimit := 1000

	req := &authzV2.GetDecisionMultiResourceRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_Token{
				Token: &entity.Token{
					EphemeralId: "123",
					Jwt:         "test-jwt-token",
				},
			},
		},
		Action:    sampleActionCreate,
		Resources: make([]*authzV2.Resource, upperBoundLimit),
	}
	for i := range req.GetResources() {
		req.Resources[i] = &authzV2.Resource{
			Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{
					Fqns: []string{sampleRegisteredResourceFQN},
				},
			},
		}
	}
	err := v.Validate(req)
	require.NoError(t, err, "validation should succeed for request with 1000 resources")

	// Add one more resource to exceed the limit
	req.Resources = append(req.Resources, &authzV2.Resource{
		Resource: &authzV2.Resource_AttributeValues_{
			AttributeValues: &authzV2.Resource_AttributeValues{
				Fqns: []string{sampleRegisteredResourceFQN},
			},
		},
	})
	err = v.Validate(req)
	require.Error(t, err, "validation should fail for request with 1001 resources")
}

func Test_GetDecisionMultiResourceRequest_Fails(t *testing.T) {
	v := getValidator()

	for _, tc := range badMultiResourceRequests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.request)
			if err == nil {
				t.Errorf("expected validation error for request: %s, but got none", tc.name)
			} else {
				assert.Contains(t, err.Error(), tc.expectedValidationError, "validation error should contain expected message")
			}
		})
	}
}

func Test_GetDecisionBulkRequest_Succeeds(t *testing.T) {
	v := getValidator()

	cases := make([]*authzV2.GetDecisionBulkRequest, 5)

	for i := range 5 {
		// Randomly pick two good multi-resource requests, repeated at least one time each, and combine into a bulk request
		firstReq := rand.Intn(len(goodMultiResourceRequests))
		firstCount := rand.Intn(10) + 1

		secondReq := rand.Intn(len(goodMultiResourceRequests))
		secondCount := rand.Intn(10) + 1

		actions := []string{"create", "read", "update", "delete", "custom_1", "CUSTOM-2"}

		reqs := make([]*authzV2.GetDecisionMultiResourceRequest, firstCount+secondCount)
		for j := range firstCount {
			originalReq := goodMultiResourceRequests[firstReq].request
			clonedReq, _ := proto.Clone(originalReq).(*authzV2.GetDecisionMultiResourceRequest)
			clonedReq.Action = &policy.Action{
				Name: actions[rand.Intn(len(actions))],
			}
			clonedReq.FulfillableObligationFqns = getRandomValidObligationValueFQNsList()
			reqs[j] = clonedReq
		}
		for j := firstCount; j < firstCount+secondCount; j++ {
			originalReq := goodMultiResourceRequests[secondReq].request
			clonedReq, _ := proto.Clone(originalReq).(*authzV2.GetDecisionMultiResourceRequest)
			clonedReq.Action = &policy.Action{
				Name: actions[rand.Intn(len(actions))],
			}
			clonedReq.FulfillableObligationFqns = getRandomValidObligationValueFQNsList()
			reqs[j] = clonedReq
		}

		cases[i] = &authzV2.GetDecisionBulkRequest{
			DecisionRequests: reqs,
		}
	}

	for _, testReq := range cases {
		err := v.Validate(testReq)
		require.NoError(t, err)
	}
}

func Test_GetDecisionBulkRequest_Fails(t *testing.T) {
	v := getValidator()

	cases := make([]struct {
		name    string
		request *authzV2.GetDecisionBulkRequest
	}, len(badMultiResourceRequests))

	goodRequests := make([]*authzV2.GetDecisionMultiResourceRequest, len(goodMultiResourceRequests))
	for i, goodReq := range goodMultiResourceRequests {
		goodRequests[i] = goodReq.request
	}

	for i, badReq := range badMultiResourceRequests {
		requests := make([]*authzV2.GetDecisionMultiResourceRequest, 0, len(goodRequests)+1)
		requests = append(requests, goodRequests...)
		requests = append(requests, badReq.request)

		cases[i] = struct {
			name    string
			request *authzV2.GetDecisionBulkRequest
		}{
			badReq.name,
			&authzV2.GetDecisionBulkRequest{
				DecisionRequests: requests,
			},
		}
	}

	for _, testReq := range cases {
		err := v.Validate(testReq.request)
		require.Error(t, err, "validation should fail for request: %s", testReq.name)
	}
}

func Test_GetDecisionBulkRequest_Limits(t *testing.T) {
	v := getValidator()
	// requests must be between 1 and 200
	req := &authzV2.GetDecisionBulkRequest{}
	err := v.Validate(req)
	require.Error(t, err, "validation should fail for bulk request without any multi resource decision requests")

	dr := &authzV2.GetDecisionMultiResourceRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_Token{
				Token: &entity.Token{
					EphemeralId: "123",
					Jwt:         "sample-jwt-token",
				},
			},
		},
		Action: sampleActionCreate,
		Resources: []*authzV2.Resource{
			{
				Resource: &authzV2.Resource_AttributeValues_{
					AttributeValues: &authzV2.Resource_AttributeValues{
						Fqns: []string{sampleResourceFQN},
					},
				},
			},
		},
	}
	req.DecisionRequests = make([]*authzV2.GetDecisionMultiResourceRequest, 201)
	for i := range req.GetDecisionRequests() {
		req.DecisionRequests[i] = dr
	}
	err = v.Validate(req)
	require.Error(t, err, "validation should fail for bulk request with more than 200 multi resource decision requests")

	req.DecisionRequests = append(req.GetDecisionRequests(), dr)
	err = v.Validate(req)
	require.Error(t, err, "validation should fail for bulk request with more than 200 multi resource decision requests")
}

func Test_GetEntitlementsRequest_Succeeds(t *testing.T) {
	v := getValidator()

	cases := []struct {
		name    string
		request *authzV2.GetEntitlementsRequest
	}{
		{
			name: "entity: token, with comprehensive hierarchy",
			request: &authzV2.GetEntitlementsRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				WithComprehensiveHierarchy: &[]bool{true}[0],
			},
		},
		{
			name: "entity: token, without comprehensive hierarchy",
			request: &authzV2.GetEntitlementsRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
				WithComprehensiveHierarchy: &[]bool{false}[0],
			},
		},
		{
			name: "entity: token, hierarchy option not specified",
			request: &authzV2.GetEntitlementsRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
							Jwt:         "sample-jwt-token",
						},
					},
				},
			},
		},
		{
			name: "entity: chain of multiple entities",
			request: &authzV2.GetEntitlementsRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_EntityChain{
						EntityChain: &entity.EntityChain{
							EphemeralId: "1234",
							Entities: []*entity.Entity{
								{
									EphemeralId: "chained-1",
									EntityType:  &entity.Entity_EmailAddress{EmailAddress: "test@test.com"},
									Category:    entity.Entity_CATEGORY_SUBJECT,
								},
								{
									EphemeralId: "chained-2",
									EntityType: &entity.Entity_ClientId{
										ClientId: "client-123",
									},
									Category: entity.Entity_CATEGORY_ENVIRONMENT,
								},
							},
						},
					},
				},
				WithComprehensiveHierarchy: &[]bool{true}[0],
			},
		},
		{
			name: "entity: registered resource",
			request: &authzV2.GetEntitlementsRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.request)
			require.NoError(t, err, "validation should succeed for request: %s", tc.name)
		})
	}
}

func Test_GetEntitlementsRequest_Fails(t *testing.T) {
	v := getValidator()

	cases := []struct {
		name                    string
		request                 *authzV2.GetEntitlementsRequest
		expectedValidationError string
	}{
		{
			name:                    "missing entity identifier",
			request:                 &authzV2.GetEntitlementsRequest{},
			expectedValidationError: "entity_identifier",
		},
		{
			name: "token entity with empty JWT",
			request: &authzV2.GetEntitlementsRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_Token{
						Token: &entity.Token{
							EphemeralId: "123",
						},
					},
				},
			},
			expectedValidationError: "jwt",
		},
		{
			name: "entity chain with no entities",
			request: &authzV2.GetEntitlementsRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_EntityChain{
						EntityChain: &entity.EntityChain{
							EphemeralId: "1234",
						},
					},
				},
			},
			expectedValidationError: "entities",
		},
		{
			name: "registered resource FQN is empty",
			request: &authzV2.GetEntitlementsRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: "",
					},
				},
			},
			expectedValidationError: "registered_resource_value_fqn",
		},
		{
			name: "registered resource FQN is invalid URI",
			request: &authzV2.GetEntitlementsRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{
					Identifier: &authzV2.EntityIdentifier_RegisteredResourceValueFqn{
						RegisteredResourceValueFqn: "invalid uri",
					},
				},
			},
			expectedValidationError: "registered_resource_value_fqn",
		},
		{
			name: "no identifier specified",
			request: &authzV2.GetEntitlementsRequest{
				EntityIdentifier: &authzV2.EntityIdentifier{},
			},
			expectedValidationError: "identifier",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.request)
			if err == nil {
				t.Errorf("expected validation error for request: %s, but got none", tc.name)
			} else {
				assert.Contains(t, err.Error(), tc.expectedValidationError, "validation error should contain expected message")
			}
		})
	}
}

func Test_RollupSingleResourceDecision(t *testing.T) {
	tests := []struct {
		name           string
		permitted      bool
		decisions      []*access.Decision
		expectedResult *authzV2.GetDecisionResponse
		expectedError  error
	}{
		{
			name:      "should return permit decision when permitted is true",
			permitted: true,
			decisions: []*access.Decision{
				{
					Access: true,
					Results: []access.ResourceDecision{
						{
							ResourceID: "resource-123",
						},
					},
				},
			},
			expectedResult: &authzV2.GetDecisionResponse{
				Decision: &authzV2.ResourceDecision{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-123",
				},
			},
			expectedError: nil,
		},
		{
			name:      "should surface obligations in a permit decision",
			permitted: true,
			decisions: []*access.Decision{
				{
					Access: true,
					Results: []access.ResourceDecision{
						{
							ResourceID: "resource-123",
							RequiredObligationValueFQNs: []string{
								"obligation-abc",
							},
						},
					},
				},
			},
			expectedResult: &authzV2.GetDecisionResponse{
				Decision: &authzV2.ResourceDecision{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-123",
					RequiredObligations: []string{
						"obligation-abc",
					},
				},
			},
			expectedError: nil,
		},
		{
			name:      "should return deny decision when permitted is false",
			permitted: false,
			decisions: []*access.Decision{
				{
					Access: true, // Verify permitted takes precedence
					Results: []access.ResourceDecision{
						{
							ResourceID: "resource-123",
						},
					},
				},
			},
			expectedResult: &authzV2.GetDecisionResponse{
				Decision: &authzV2.ResourceDecision{
					Decision:            authzV2.Decision_DECISION_DENY,
					EphemeralResourceId: "resource-123",
				},
			},
			expectedError: nil,
		},
		{
			name:      "should surface obligations within a deny decision",
			permitted: false,
			decisions: []*access.Decision{
				{
					Access: true, // Verify permitted takes precedence
					Results: []access.ResourceDecision{
						{
							ResourceID:                  "resource-123",
							RequiredObligationValueFQNs: []string{"obligation-123"},
						},
					},
				},
			},
			expectedResult: &authzV2.GetDecisionResponse{
				Decision: &authzV2.ResourceDecision{
					Decision:            authzV2.Decision_DECISION_DENY,
					EphemeralResourceId: "resource-123",
					RequiredObligations: []string{"obligation-123"},
				},
			},
			expectedError: nil,
		},
		{
			name:           "should return error when no decisions are provided",
			permitted:      true,
			decisions:      []*access.Decision{},
			expectedResult: nil,
			expectedError:  ErrNoDecisions,
		},
		{
			name:      "should return error when decision has no results",
			permitted: true,
			decisions: []*access.Decision{
				{
					Access:  true,
					Results: []access.ResourceDecision{},
				},
			},
			expectedResult: nil,
			expectedError:  ErrDecisionMustHaveResults,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rollupSingleResourceDecision(tc.permitted, tc.decisions)

			if tc.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedError)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.True(t, proto.Equal(tc.expectedResult, result))
			}
		})
	}
}

func Test_RollupMultiResourceDecisions(t *testing.T) {
	tests := []struct {
		name           string
		decisions      []*access.Decision
		expectedResult []*authzV2.ResourceDecision
		expectedError  error
	}{
		{
			name: "should return multiple permit decisions",
			decisions: []*access.Decision{
				{
					Access: true,
					Results: []access.ResourceDecision{
						{
							Passed:     true,
							ResourceID: "resource-123",
						},
					},
				},
				{
					Access: true,
					Results: []access.ResourceDecision{
						{
							Passed:     true,
							ResourceID: "resource-456",
						},
					},
				},
			},
			expectedResult: []*authzV2.ResourceDecision{
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-123",
				},
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-456",
				},
			},
		},
		{
			name: "should return mix of permit and deny decisions",
			decisions: []*access.Decision{
				{
					Access: true,
					Results: []access.ResourceDecision{
						{
							Passed:     true,
							ResourceID: "resource-123",
						},
					},
				},
				{
					Access: false,
					Results: []access.ResourceDecision{
						{
							Passed:     false,
							ResourceID: "resource-456",
						},
					},
				},
			},
			expectedResult: []*authzV2.ResourceDecision{
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-123",
				},
				{
					Decision:            authzV2.Decision_DECISION_DENY,
					EphemeralResourceId: "resource-456",
				},
			},
		},
		{
			name: "should rely on results and default to false decisions",
			decisions: []*access.Decision{
				{
					Access: true,
					Results: []access.ResourceDecision{
						{
							Passed:     true,
							ResourceID: "resource-123",
						},
						{
							Passed:     false,
							ResourceID: "resource-abc",
						},
					},
				},
				{
					Access: false,
					Results: []access.ResourceDecision{
						{
							Passed:     false,
							ResourceID: "resource-456",
						},
					},
				},
			},
			expectedResult: []*authzV2.ResourceDecision{
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-123",
				},
				{
					Decision:            authzV2.Decision_DECISION_DENY,
					EphemeralResourceId: "resource-abc",
				},
				{
					Decision:            authzV2.Decision_DECISION_DENY,
					EphemeralResourceId: "resource-456",
				},
			},
		},
		{
			name: "should ignore global access and care about resource decisions predominantly",
			decisions: []*access.Decision{
				{
					Access: false,
					Results: []access.ResourceDecision{
						{
							Passed:     false,
							ResourceID: "resource-123",
						},
						{
							Passed:     true,
							ResourceID: "resource-abc",
						},
					},
				},
				{
					Access: false,
					Results: []access.ResourceDecision{
						{
							Passed:     true,
							ResourceID: "resource-456",
						},
					},
				},
			},
			expectedResult: []*authzV2.ResourceDecision{
				{
					Decision:            authzV2.Decision_DECISION_DENY,
					EphemeralResourceId: "resource-123",
				},
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-abc",
				},
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-456",
				},
			},
		},
		{
			name: "should return obligations whenever found on a resource",
			decisions: []*access.Decision{
				{
					Access: true,
					Results: []access.ResourceDecision{
						{
							Passed:     true,
							ResourceID: "resource-123",
							RequiredObligationValueFQNs: []string{
								"obligation-123",
								"obligation-abc",
								"obligation-456",
							},
						},
						{
							Passed:     true,
							ResourceID: "resource-abc",
							RequiredObligationValueFQNs: []string{
								"obligation-abc",
							},
						},
					},
				},
				{
					Access: false,
					Results: []access.ResourceDecision{
						{
							Passed:     false,
							ResourceID: "resource-456",
						},
						{
							Passed:     true,
							ResourceID: "resource-extra",
							RequiredObligationValueFQNs: []string{
								"obligation-extra",
							},
						},
					},
				},
			},
			expectedResult: []*authzV2.ResourceDecision{
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-123",
					RequiredObligations: []string{
						"obligation-123",
						"obligation-abc",
						"obligation-456",
					},
				},
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-abc",
					RequiredObligations: []string{
						"obligation-abc",
					},
				},
				{
					Decision:            authzV2.Decision_DECISION_DENY,
					EphemeralResourceId: "resource-456",
				},
				{
					Decision:            authzV2.Decision_DECISION_PERMIT,
					EphemeralResourceId: "resource-extra",
					RequiredObligations: []string{
						"obligation-extra",
					},
				},
			},
		},
		{
			name: "should return error when decision has no results",
			decisions: []*access.Decision{
				{
					Access:  true,
					Results: []access.ResourceDecision{},
				},
			},
			expectedError: ErrDecisionMustHaveResults,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rollupMultiResourceDecisions(tc.decisions)

			if tc.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedError)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				// resource order preserved
				for i, decision := range result {
					assert.True(t, proto.Equal(tc.expectedResult[i], decision))
				}
			}
		})
	}
}

func Test_RollupMultiResourceDecisions_Simple(t *testing.T) {
	// This test checks the minimal viable structure to pass through rollupMultiResourceDecision
	decision := &access.Decision{
		Results: []access.ResourceDecision{
			{
				Passed:     true,
				ResourceID: "resource-123",
			},
		},
	}

	decisions := []*access.Decision{decision}

	result, err := rollupMultiResourceDecisions(decisions)

	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "resource-123", result[0].GetEphemeralResourceId())
	assert.Equal(t, authzV2.Decision_DECISION_PERMIT, result[0].GetDecision())
}

func Test_RollupMultiResourceDecisions_WithNilChecks(t *testing.T) {
	t.Run("nil decisions array", func(t *testing.T) {
		var decisions []*access.Decision
		_, err := rollupMultiResourceDecisions(decisions)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoDecisions)
	})

	t.Run("nil decision in array", func(t *testing.T) {
		decisions := []*access.Decision{nil}
		_, err := rollupMultiResourceDecisions(decisions)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrDecisionCannotBeNil)
	})

	t.Run("nil Results field", func(t *testing.T) {
		decisions := []*access.Decision{
			{
				Access:  true,
				Results: nil,
			},
		}
		_, err := rollupMultiResourceDecisions(decisions)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrDecisionMustHaveResults)
	})
}

func Test_RollupSingleResourceDecision_WithNilChecks(t *testing.T) {
	t.Run("nil decisions array", func(t *testing.T) {
		var decisions []*access.Decision
		_, err := rollupSingleResourceDecision(true, decisions)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoDecisions)
	})

	t.Run("nil decision in array", func(t *testing.T) {
		decisions := []*access.Decision{nil}
		_, err := rollupSingleResourceDecision(true, decisions)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrDecisionCannotBeNil)
	})

	t.Run("nil Results field", func(t *testing.T) {
		decisions := []*access.Decision{
			{
				Access:  true,
				Results: nil,
			},
		}
		_, err := rollupSingleResourceDecision(true, decisions)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrDecisionMustHaveResults)
	})
}

// Helpers

// A random list of obligation FQNs 0 to 50 in length
func getRandomValidObligationValueFQNsList() []string {
	count := rand.Intn(51)
	randomList := make([]string, count)
	for i := range count {
		randomList[i] = getRandomObligationValueFQN()
	}
	return randomList
}

func getTooManyObligations() []string {
	tooMany := make([]string, 51)
	for i := range tooMany {
		tooMany[i] = getRandomObligationValueFQN()
	}
	return tooMany
}

const charset = "abcdefghijklmnopqrstuvwxyz"

func randString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// builds a random FQN for an obligation value that matches
// https://<namespace>.com/obl/<name>/value/<value>
func getRandomObligationValueFQN() string {
	namespace := "https://" + randString(5) + ".com"
	name := randString(5)
	value := randString(5)
	return identifier.BuildOblValFQN(namespace, name, value)
}
