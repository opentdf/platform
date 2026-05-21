package authorization

import (
	"context"
	"strconv"
	"testing"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
)

func Test_validateGetDecisionRequest_DefaultRequestLimits(t *testing.T) {
	service := newValidationTestService(t, nil)

	cases := []struct {
		name        string
		request     *authzV2.GetDecisionRequest
		expectedErr string
	}{
		{
			name:        "entity chain entities",
			request:     newDecisionRequestWithEntityChainCount(11),
			expectedErr: "entity_identifier.entity_chain.entities exceeds maximum count: got 11, max 10",
		},
		{
			name:        "resource attribute values",
			request:     newDecisionRequestWithAttributeValueCount(21),
			expectedErr: "resource.attribute_values.fqns exceeds maximum count: got 21, max 20",
		},
		{
			name:        "fulfillable obligation fqns",
			request:     newDecisionRequestWithObligationCount(51),
			expectedErr: "fulfillable_obligation_fqns exceeds maximum count: got 51, max 50",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := service.validateGetDecisionRequest(tc.request)
			require.Error(t, err)
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func Test_validateGetEntitlementsRequest_DefaultRequestLimit(t *testing.T) {
	service := newValidationTestService(t, nil)

	err := service.validateGetEntitlementsRequest(newEntitlementsRequestWithEntityChainCount(11))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "entity_identifier.entity_chain.entities exceeds maximum count: got 11, max 10")
}

func Test_validateGetDecisionMultiResourceRequest_DefaultRequestLimit(t *testing.T) {
	service := newValidationTestService(t, nil)

	err := service.validateGetDecisionMultiResourceRequest(newDecisionMultiResourceRequestWithResourceCount(1001), "")
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "resources exceeds maximum count: got 1001, max 1000")
}

func Test_validateGetDecisionBulkRequest_DefaultRequestLimit(t *testing.T) {
	service := newValidationTestService(t, nil)

	err := service.validateGetDecisionBulkRequest(newDecisionBulkRequestWithDecisionCount(201))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "decision_requests exceeds maximum count: got 201, max 200")
}

func Test_validateGetDecisionBulkRequest_NestedLimitErrorIncludesPath(t *testing.T) {
	service := newValidationTestService(t, nil)

	err := service.validateGetDecisionBulkRequest(&authzV2.GetDecisionBulkRequest{
		DecisionRequests: []*authzV2.GetDecisionMultiResourceRequest{
			newDecisionMultiResourceRequestWithAttributeValueCount(21),
		},
	})
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "decision_requests[0].resources[0].attribute_values.fqns exceeds maximum count: got 21, max 20")
}

func Test_validateDecisionRequests_UseCustomRequestLimits(t *testing.T) {
	service := newValidationTestService(t, &RequestLimitsConfig{
		ResourceAttributeValuesMax:   21,
		EntityChainEntitiesMax:       11,
		FulfillableObligationFqnsMax: 51,
		MultiResourceRequestMax:      1001,
		BulkDecisionRequestMax:       201,
	})

	require.NoError(t, service.validateGetDecisionRequest(newDecisionRequestWithEntityChainCount(11)))
	require.NoError(t, service.validateGetDecisionRequest(newDecisionRequestWithAttributeValueCount(21)))
	require.NoError(t, service.validateGetDecisionRequest(newDecisionRequestWithObligationCount(51)))
	require.NoError(t, service.validateGetDecisionMultiResourceRequest(newDecisionMultiResourceRequestWithResourceCount(1001), ""))
	require.NoError(t, service.validateGetDecisionBulkRequest(newDecisionBulkRequestWithDecisionCount(201)))
}

func Test_GetDecision_ReturnsInvalidArgumentForConfiguredLimit(t *testing.T) {
	service := newHandlerTestService(t, nil)

	_, err := service.GetDecision(context.Background(), connect.NewRequest(newDecisionRequestWithAttributeValueCount(21)))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "resource.attribute_values.fqns exceeds maximum count: got 21, max 20")
}

func Test_GetEntitlements_ReturnsInvalidArgumentForConfiguredLimit(t *testing.T) {
	service := newHandlerTestService(t, func(config *Config) {
		config.RequestLimits.EntityChainEntitiesMax = 1
	})

	_, err := service.GetEntitlements(context.Background(), connect.NewRequest(newEntitlementsRequestWithEntityChainCount(2)))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "entity_identifier.entity_chain.entities exceeds maximum count: got 2, max 1")
}

func Test_GetDecisionMultiResource_UsesCustomConfiguredLimit(t *testing.T) {
	service := newHandlerTestService(t, func(config *Config) {
		config.RequestLimits.MultiResourceRequestMax = 2
	})

	_, err := service.GetDecisionMultiResource(context.Background(), connect.NewRequest(newDecisionMultiResourceRequestWithResourceCount(3)))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "resources exceeds maximum count: got 3, max 2")
}

func Test_GetDecisionBulk_ReturnsInvalidArgumentForConfiguredLimit(t *testing.T) {
	service := newHandlerTestService(t, func(config *Config) {
		config.RequestLimits.BulkDecisionRequestMax = 1
	})

	_, err := service.GetDecisionBulk(context.Background(), connect.NewRequest(newDecisionBulkRequestWithDecisionCount(2)))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "decision_requests exceeds maximum count: got 2, max 1")
}

func newValidationTestService(t *testing.T, requestLimits *RequestLimitsConfig) *Service {
	t.Helper()

	config := newConfigWithDefaults(t)
	if requestLimits != nil {
		config.RequestLimits = *requestLimits
	}
	require.NoError(t, config.Validate())

	return &Service{config: config}
}

func newHandlerTestService(t *testing.T, mutate func(*Config)) *Service {
	t.Helper()

	config := newConfigWithDefaults(t)
	if mutate != nil {
		mutate(config)
	}
	require.NoError(t, config.Validate())

	return &Service{
		config: config,
		logger: logger.CreateTestLogger(),
		Tracer: noop.NewTracerProvider().Tracer(""),
	}
}

func newDecisionRequestWithEntityChainCount(count int) *authzV2.GetDecisionRequest {
	return &authzV2.GetDecisionRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_EntityChain{
				EntityChain: &entity.EntityChain{
					EphemeralId: "entity-chain",
					Entities:    newEntities(count),
				},
			},
		},
		Action: sampleActionCreate,
		Resource: &authzV2.Resource{
			Resource: &authzV2.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
			},
		},
	}
}

func newEntitlementsRequestWithEntityChainCount(count int) *authzV2.GetEntitlementsRequest {
	return &authzV2.GetEntitlementsRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_EntityChain{
				EntityChain: &entity.EntityChain{
					EphemeralId: "entity-chain",
					Entities:    newEntities(count),
				},
			},
		},
	}
}

func newDecisionRequestWithAttributeValueCount(count int) *authzV2.GetDecisionRequest {
	return &authzV2.GetDecisionRequest{
		EntityIdentifier: newTokenEntityIdentifier(),
		Action:           sampleActionCreate,
		Resource: &authzV2.Resource{
			Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{
					Fqns: newAttributeValueFQNs(count),
				},
			},
		},
	}
}

func newDecisionRequestWithObligationCount(count int) *authzV2.GetDecisionRequest {
	return &authzV2.GetDecisionRequest{
		EntityIdentifier: newTokenEntityIdentifier(),
		Action:           sampleActionCreate,
		Resource: &authzV2.Resource{
			Resource: &authzV2.Resource_RegisteredResourceValueFqn{
				RegisteredResourceValueFqn: sampleRegisteredResourceFQN,
			},
		},
		FulfillableObligationFqns: newObligationFQNs(count),
	}
}

func newDecisionMultiResourceRequestWithAttributeValueCount(count int) *authzV2.GetDecisionMultiResourceRequest {
	return &authzV2.GetDecisionMultiResourceRequest{
		EntityIdentifier: newTokenEntityIdentifier(),
		Action:           sampleActionCreate,
		Resources: []*authzV2.Resource{
			{
				Resource: &authzV2.Resource_AttributeValues_{
					AttributeValues: &authzV2.Resource_AttributeValues{
						Fqns: newAttributeValueFQNs(count),
					},
				},
			},
		},
	}
}

func newDecisionMultiResourceRequestWithResourceCount(count int) *authzV2.GetDecisionMultiResourceRequest {
	resources := make([]*authzV2.Resource, count)
	for i := range count {
		resources[i] = &authzV2.Resource{
			Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{
					Fqns: []string{sampleResourceFQN},
				},
			},
		}
	}

	return &authzV2.GetDecisionMultiResourceRequest{
		EntityIdentifier: newTokenEntityIdentifier(),
		Action:           sampleActionCreate,
		Resources:        resources,
	}
}

func newDecisionBulkRequestWithDecisionCount(count int) *authzV2.GetDecisionBulkRequest {
	requests := make([]*authzV2.GetDecisionMultiResourceRequest, count)
	for i := range count {
		requests[i] = newDecisionMultiResourceRequestWithResourceCount(1)
	}
	return &authzV2.GetDecisionBulkRequest{DecisionRequests: requests}
}

func newTokenEntityIdentifier() *authzV2.EntityIdentifier {
	return &authzV2.EntityIdentifier{
		Identifier: &authzV2.EntityIdentifier_Token{
			Token: &entity.Token{
				EphemeralId: "token-entity",
				Jwt:         "sample-jwt-token",
			},
		},
	}
}

func newEntities(count int) []*entity.Entity {
	entities := make([]*entity.Entity, count)
	for i := range count {
		entities[i] = &entity.Entity{
			EphemeralId: "entity-" + strconv.Itoa(i),
			EntityType:  &entity.Entity_EmailAddress{EmailAddress: "test@test.com"},
			Category:    entity.Entity_CATEGORY_SUBJECT,
		}
	}
	return entities
}

func newAttributeValueFQNs(count int) []string {
	fqns := make([]string, count)
	for i := range count {
		fqns[i] = "https://example.com/attr/any_of_attr_name/value/val" + strconv.Itoa(i)
	}
	return fqns
}

func newObligationFQNs(count int) []string {
	fqns := make([]string, count)
	for i := range count {
		fqns[i] = "https://example.com/obl/drm/value/prevent_print_" + strconv.Itoa(i)
	}
	return fqns
}
