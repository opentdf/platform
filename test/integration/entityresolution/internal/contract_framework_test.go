package internal

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// MockERSImplementation provides a mock ERS implementation for testing the contract framework
type MockERSImplementation struct {
	mockData map[string]map[string]interface{}
}

// NewMockERSImplementation creates a new mock ERS implementation with test data
func NewMockERSImplementation() *MockERSImplementation {
	return &MockERSImplementation{
		mockData: map[string]map[string]interface{}{
			"username:alice": {
				"username":     "alice",
				"email":        "alice@opentdf.test",
				"display_name": "Alice Smith",
			},
			"username:bob": {
				"username":     "bob",
				"email":        "bob@opentdf.test",
				"display_name": "Bob Johnson",
			},
			"email:alice@opentdf.test": {
				"username":     "alice",
				"email":        "alice@opentdf.test",
				"display_name": "Alice Smith",
			},
			"email:bob@opentdf.test": {
				"username":     "bob",
				"email":        "bob@opentdf.test",
				"display_name": "Bob Johnson",
			},
			"client_id:test-client-1": {
				"client_id":   "test-client-1",
				"description": "First test client",
			},
		},
	}
}

// ResolveEntities implements the ERS interface for testing
func (m *MockERSImplementation) ResolveEntities(_ context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	var resolvedEntities []*entityresolutionV2.EntityRepresentation

	for _, ent := range req.Msg.GetEntities() {
		key := m.getEntityKey(ent)

		if data, exists := m.mockData[key]; exists {
			// Convert map to structpb.Struct
			structData, err := structpb.NewStruct(data)
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}

			resolvedEntities = append(resolvedEntities, &entityresolutionV2.EntityRepresentation{
				OriginalId:      ent.GetEphemeralId(),
				AdditionalProps: []*structpb.Struct{structData},
			})
		} else {
			// Return inferred entity for non-existent entities
			inferredData := map[string]interface{}{
				"inferred": true,
			}

			switch ent.GetEntityType().(type) {
			case *entity.Entity_UserName:
				inferredData["username"] = ent.GetUserName()
			case *entity.Entity_EmailAddress:
				inferredData["email"] = ent.GetEmailAddress()
			case *entity.Entity_ClientId:
				inferredData["client_id"] = ent.GetClientId()
			}

			structData, err := structpb.NewStruct(inferredData)
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}

			resolvedEntities = append(resolvedEntities, &entityresolutionV2.EntityRepresentation{
				OriginalId:      ent.GetEphemeralId(),
				AdditionalProps: []*structpb.Struct{structData},
			})
		}
	}

	return connect.NewResponse(&entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: resolvedEntities,
	}), nil
}

// CreateEntityChainsFromTokens implements the ERS interface for testing
func (m *MockERSImplementation) CreateEntityChainsFromTokens(_ context.Context, req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error) {
	var entityChains []*entity.EntityChain

	for _, token := range req.Msg.GetTokens() {
		// Create a simple mock entity chain for testing
		entities := []*entity.Entity{
			{
				EntityType:  &entity.Entity_ClientId{ClientId: "mock-client"},
				EphemeralId: "mock-client-entity",
				Category:    entity.Entity_CATEGORY_ENVIRONMENT,
			},
			{
				EntityType:  &entity.Entity_UserName{UserName: "mock-user"},
				EphemeralId: "mock-user-entity",
				Category:    entity.Entity_CATEGORY_SUBJECT,
			},
		}

		entityChains = append(entityChains, &entity.EntityChain{
			EphemeralId: token.GetEphemeralId(),
			Entities:    entities,
		})
	}

	return connect.NewResponse(&entityresolutionV2.CreateEntityChainsFromTokensResponse{
		EntityChains: entityChains,
	}), nil
}

// getEntityKey generates a key for looking up mock data
func (m *MockERSImplementation) getEntityKey(ent *entity.Entity) string {
	switch entityType := ent.GetEntityType().(type) {
	case *entity.Entity_UserName:
		return "username:" + entityType.UserName
	case *entity.Entity_EmailAddress:
		return "email:" + entityType.EmailAddress
	case *entity.Entity_ClientId:
		return "client_id:" + entityType.ClientId
	default:
		return "unknown"
	}
}

// TestContractTestFramework validates that the contract testing framework works correctly
func TestContractTestFramework(t *testing.T) {
	mockImpl := NewMockERSImplementation()
	contractSuite := NewContractTestSuite()

	// Test that the framework can run against a mock implementation
	t.Run("Mock_Implementation_Contract_Tests", func(t *testing.T) {
		// This should run all contract tests against the mock implementation
		contractSuite.RunContractTests(t, mockImpl, "Mock")
	})
}

// TestContractTestSuiteStructure validates the structure of the contract test suite
func TestContractTestSuiteStructure(t *testing.T) {
	suite := NewContractTestSuite()

	// Verify that we have a reasonable number of test cases
	assert.Greater(t, len(suite.TestCases), 5, "Should have multiple contract test cases")

	// Verify that each test case has required fields
	for _, testCase := range suite.TestCases {
		assert.NotEmpty(t, testCase.Name, "Test case should have a name")
		assert.NotEmpty(t, testCase.Description, "Test case should have a description")

		// At least one of entities or tokens should be provided
		hasInput := len(testCase.Input.Entities) > 0 || len(testCase.Input.Tokens) > 0
		assert.True(t, hasInput, "Test case should have input entities or tokens")
	}
}

// TestContractTestDataSet validates the contract test data set
func TestContractTestDataSet(t *testing.T) {
	dataSet := NewContractTestDataSet()

	// Verify users
	assert.NotEmpty(t, dataSet.Users, "Should have test users")
	for _, user := range dataSet.Users {
		assert.NotEmpty(t, user.Username, "User should have username")
		assert.NotEmpty(t, user.Email, "User should have email")
		assert.NotEmpty(t, user.DisplayName, "User should have display name")
	}

	// Verify clients
	assert.NotEmpty(t, dataSet.Clients, "Should have test clients")
	for _, client := range dataSet.Clients {
		assert.NotEmpty(t, client.ClientID, "Client should have client ID")
		assert.NotEmpty(t, client.Description, "Client should have description")
	}
}

// TestEntityValidationRules tests the entity validation logic in the contract framework
func TestEntityValidationRules(t *testing.T) {
	mockImpl := NewMockERSImplementation()

	// Create a simple test case to validate
	testCase := ContractTestCase{
		Name: "TestValidation",
		Input: ContractInput{
			Entities: []*entity.Entity{
				CreateTestEntityByUsername("alice"),
			},
		},
		Expected: ContractExpected{
			EntityCount: 1,
			ShouldError: false,
			EntityValidation: []EntityValidationRule{
				{
					Index:       0,
					EphemeralID: "test-user-alice",
					RequiredFields: map[string]interface{}{
						"username": "alice",
						"email":    "alice@opentdf.test",
					},
					MinFieldCount: 2,
				},
			},
		},
	}

	suite := &ContractTestSuite{TestCases: []ContractTestCase{testCase}}

	// This should pass with the mock implementation
	t.Run("ValidateEntityFields", func(t *testing.T) {
		suite.runSingleContractTest(t, mockImpl, testCase)
	})
}

// TestTestDataInjectors tests the test data injection interfaces
func TestTestDataInjectors(t *testing.T) {
	t.Run("MockTestDataInjector", func(t *testing.T) {
		ctx := t.Context()
		testLogger := logger.CreateTestLogger()
		injector := NewMockTestDataInjector(testLogger)
		dataSet := NewContractTestDataSet()

		// All methods should succeed for mock injector (no-ops)
		err := injector.InjectTestData(ctx, dataSet)
		require.NoError(t, err)

		err = injector.ValidateTestData(ctx, dataSet)
		require.NoError(t, err)

		err = injector.CleanupTestData(ctx)
		assert.NoError(t, err)
	})
}

// TestEntityTypeStringConversion tests the entity type string conversion helper
func TestEntityTypeStringConversion(t *testing.T) {
	testCases := []struct {
		entity       *entity.Entity
		expectedType string
	}{
		{
			entity: &entity.Entity{
				EntityType: &entity.Entity_UserName{UserName: "test"},
			},
			expectedType: "username",
		},
		{
			entity: &entity.Entity{
				EntityType: &entity.Entity_EmailAddress{EmailAddress: "test@example.com"},
			},
			expectedType: "email",
		},
		{
			entity: &entity.Entity{
				EntityType: &entity.Entity_ClientId{ClientId: "test-client"},
			},
			expectedType: "client_id",
		},
	}

	for _, testCase := range testCases {
		actualType := getEntityTypeString(testCase.entity)
		assert.Equal(t, testCase.expectedType, actualType)
	}
}
