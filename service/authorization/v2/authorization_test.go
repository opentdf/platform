package authorization

import (
	"errors"
	"testing"

	"buf.build/go/protovalidate"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	sampleActionCreate = &policy.Action{
		Name: "create",
	}
	sampleResourceFQN           = "https://example.com/attr/hier/value/highest"
	sampleResourceFQN2          = "https://example.com/attr/hier/value/lowest"
	sampleRegisteredResourceFQN = "https://example.com/reg_res/system/value/internal"
)

func getValidator() protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func Test_GetDecisionRequest_Succeeds(t *testing.T) {
	v := getValidator()

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

	cases := []struct {
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
		{
			name: "entity: token, action: create, empty resources array",
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
				Resources: []*authzV2.Resource{}, // Empty resources is valid (though may not be useful)
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
func Test_GetDecisionMultiResourceRequest_Fails(t *testing.T) {}
func Test_GetEntitlementsRequest_Succeeds(t *testing.T)       {}
func Test_GetEntitlementsRequest_Fails(t *testing.T)          {}

func Test_RollupSingleResourceDecision(t *testing.T) {
	tests := []struct {
		name            string
		permitted       bool
		decisions       []*access.Decision
		expectedResult  *authzV2.GetDecisionResponse
		expectedError   error
		errorMsgContain string
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
			name:            "should return error when no decisions are provided",
			permitted:       true,
			decisions:       []*access.Decision{},
			expectedResult:  nil,
			expectedError:   errors.New("no decisions returned"),
			errorMsgContain: "no decisions returned",
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
			expectedResult:  nil,
			expectedError:   errors.New("no decision results returned"),
			errorMsgContain: "no decision results returned",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rollupSingleResourceDecision(tc.permitted, tc.decisions)

			if tc.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsgContain)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

func Test_RollupMultiResourceDecision(t *testing.T) {
	tests := []struct {
		name            string
		decisions       []*access.Decision
		expectedResult  []*authzV2.ResourceDecision
		expectedError   error
		errorMsgContain string
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
			expectedError: nil,
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
			expectedError: nil,
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
			expectedError: nil,
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
			expectedError: nil,
		},
		{
			name: "should return error when decision has no results",
			decisions: []*access.Decision{
				{
					Access:  true,
					Results: []access.ResourceDecision{},
				},
			},
			expectedResult:  nil,
			expectedError:   errors.New("no decision results returned"),
			errorMsgContain: "no decision results returned",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rollupMultiResourceDecision(tc.decisions)

			if tc.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsgContain)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

func Test_RollupMultiResourceDecision_Simple(t *testing.T) {
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

	result, err := rollupMultiResourceDecision(decisions)

	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "resource-123", result[0].GetEphemeralResourceId())
	assert.Equal(t, authzV2.Decision_DECISION_PERMIT, result[0].GetDecision())
}

func Test_RollupMultiResourceDecision_WithNilChecks(t *testing.T) {
	t.Run("nil decisions array", func(t *testing.T) {
		var decisions []*access.Decision
		_, err := rollupMultiResourceDecision(decisions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no decisions returned")
	})

	t.Run("nil decision in array", func(t *testing.T) {
		decisions := []*access.Decision{nil}
		_, err := rollupMultiResourceDecision(decisions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil decision at index 0")
	})

	t.Run("nil Results field", func(t *testing.T) {
		decisions := []*access.Decision{
			{
				Access:  true,
				Results: nil,
			},
		}
		_, err := rollupMultiResourceDecision(decisions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no decision results returned")
	})
}

func Test_RollupSingleResourceDecision_WithNilChecks(t *testing.T) {
	t.Run("nil decisions array", func(t *testing.T) {
		var decisions []*access.Decision
		_, err := rollupSingleResourceDecision(true, decisions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no decisions returned")
	})

	t.Run("nil decision in array", func(t *testing.T) {
		decisions := []*access.Decision{nil}
		_, err := rollupSingleResourceDecision(true, decisions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil decision at index 0")
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
		assert.Contains(t, err.Error(), "no decision results returned")
	})
}
