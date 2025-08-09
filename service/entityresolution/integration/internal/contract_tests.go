package internal

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ERSImplementation defines the interface that all ERS implementations must satisfy for contract testing
type ERSImplementation interface {
	ResolveEntities(ctx context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error)
	CreateEntityChainsFromTokens(ctx context.Context, req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error)
}

// ERSTestAdapter defines the interface that each scope (ldap, sql, etc.) must implement
// to participate in contract testing. This allows each scope to define:
// 1. How to inject test data into their specific backend
// 2. How to create their concrete ERS service implementation
type ERSTestAdapter interface {
	// GetScopeName returns the human-readable name for this ERS scope (e.g., "LDAP", "SQL")
	GetScopeName() string
	
	// SetupTestData injects the provided test data into the backend data store
	// Each implementation handles this differently:
	// - LDAP: Creates LDAP entries via LDAP operations
	// - SQL: Inserts rows into database tables
	// - Claims: Sets up JWT signing keys and test claims
	SetupTestData(ctx context.Context, testDataSet *ContractTestDataSet) error
	
	// CreateERSService creates and returns a configured ERS service instance
	// ready for testing with the injected test data
	CreateERSService(ctx context.Context) (ERSImplementation, error)
	
	// TeardownTestData cleans up any test data and resources
	// This is called after tests complete to ensure clean state
	TeardownTestData(ctx context.Context) error
}

// ContractTestCase represents a single test case in the contract
type ContractTestCase struct {
	Name        string
	Description string
	Input       ContractInput
	Expected    ContractExpected
}

// ContractInput defines the input data for a contract test
type ContractInput struct {
	Entities []*entity.Entity
	Tokens   []*entity.Token // For CreateEntityChainsFromTokens tests
}

// ContractExpected defines the expected output for a contract test
type ContractExpected struct {
	EntityCount      int                            // Expected number of entities returned
	ShouldError      bool                          // Whether the call should return an error
	ErrorCode        connect.Code                  // Expected error code if ShouldError is true
	EntityValidation []EntityValidationRule        // Rules for validating returned entities
	ChainValidation  []EntityChainValidationRule  // Rules for validating entity chains
}

// EntityValidationRule defines how to validate a returned entity
type EntityValidationRule struct {
	Index          int                    // Which entity in the response to validate
	EphemeralID    string                // Expected ephemeral ID
	RequiredFields map[string]interface{} // Fields that must be present with specific values
	ForbiddenFields []string              // Fields that must not be present
	MinFieldCount  int                   // Minimum number of fields in additional properties
}

// EntityChainValidationRule defines how to validate a returned entity chain
type EntityChainValidationRule struct {
	EphemeralID              string   // Expected ephemeral ID
	EntityCount              int      // Expected number of entities in the chain
	EntityTypes              []string // Expected entity types in order
	EntityCategories         []string // Expected entity categories in order (CATEGORY_ENVIRONMENT, CATEGORY_SUBJECT)
	RequireConsistentOrdering bool     // Whether entity order must be consistent across implementations
}

// ContractTestSuite holds all the contract tests for ERS implementations
type ContractTestSuite struct {
	TestCases []ContractTestCase
}

// NewContractTestSuite creates a new contract test suite with standard test cases
func NewContractTestSuite() *ContractTestSuite {
	return &ContractTestSuite{
		TestCases: []ContractTestCase{
			// Basic username resolution tests
			{
				Name:        "ResolveValidUsername",
				Description: "Should resolve an existing username to entity representation",
				Input: ContractInput{
					Entities: []*entity.Entity{
						CreateTestEntityByUsername("alice"),
					},
				},
				Expected: ContractExpected{
					EntityCount:      1,
					ShouldError:      false,
					ErrorCode:        0,
					EntityValidation: []EntityValidationRule{
						{
							Index:       0,
							EphemeralID: "test-user-alice",
							RequiredFields: map[string]interface{}{
								"username": "alice",
								"email":    "alice@opentdf.test",
							},
							ForbiddenFields: []string{},
							MinFieldCount:   2,
						},
					},
					ChainValidation: []EntityChainValidationRule{},
				},
			},
			{
				Name:        "ResolveMultipleUsernames",
				Description: "Should resolve multiple usernames to entity representations",
				Input: ContractInput{
					Entities: []*entity.Entity{
						CreateTestEntityByUsername("alice"),
						CreateTestEntityByUsername("bob"),
					},
				},
				Expected: ContractExpected{
					EntityCount: 2,
					ShouldError: false,
					EntityValidation: []EntityValidationRule{
						{
							Index:       0,
							EphemeralID: "test-user-alice",
							RequiredFields: map[string]interface{}{
								"username": "alice",
							},
							MinFieldCount: 2,
						},
						{
							Index:       1,
							EphemeralID: "test-user-bob",
							RequiredFields: map[string]interface{}{
								"username": "bob",
							},
							MinFieldCount: 2,
						},
					},
				},
			},
			// Basic email resolution tests
			{
				Name:        "ResolveValidEmail",
				Description: "Should resolve an existing email to entity representation",
				Input: ContractInput{
					Entities: []*entity.Entity{
						CreateTestEntityByEmail("alice@opentdf.test"),
					},
				},
				Expected: ContractExpected{
					EntityCount: 1,
					ShouldError: false,
					EntityValidation: []EntityValidationRule{
						{
							Index:       0,
							EphemeralID: "test-email-alice@opentdf.test",
							RequiredFields: map[string]interface{}{
								"email": "alice@opentdf.test",
							},
							MinFieldCount: 2,
						},
					},
				},
			},
			// Basic client ID resolution tests
			{
				Name:        "ResolveValidClientID",
				Description: "Should resolve an existing client ID to entity representation",
				Input: ContractInput{
					Entities: []*entity.Entity{
						CreateTestEntityByClientID("test-client-1"),
					},
				},
				Expected: ContractExpected{
					EntityCount: 1,
					ShouldError: false,
					EntityValidation: []EntityValidationRule{
						{
							Index:       0,
							EphemeralID: "test-client-test-client-1",
							RequiredFields: map[string]interface{}{
								"client_id": "test-client-1",
							},
							MinFieldCount: 1,
						},
					},
				},
			},
			// Non-existent entity tests with inference
			{
				Name:        "ResolveNonExistentUsernameWithInference",
				Description: "Should infer entity when username doesn't exist and inference is enabled",
				Input: ContractInput{
					Entities: []*entity.Entity{
						CreateTestEntityByUsername("nonexistent"),
					},
				},
				Expected: ContractExpected{
					EntityCount: 1,
					ShouldError: false,
					EntityValidation: []EntityValidationRule{
						{
							Index:       0,
							EphemeralID: "test-user-nonexistent",
							MinFieldCount: 1, // Should have at least the inferred entity data
						},
					},
				},
			},
			{
				Name:        "ResolveNonExistentEmailWithInference",
				Description: "Should infer entity when email doesn't exist and inference is enabled",
				Input: ContractInput{
					Entities: []*entity.Entity{
						CreateTestEntityByEmail("nonexistent@example.com"),
					},
				},
				Expected: ContractExpected{
					EntityCount: 1,
					ShouldError: false,
					EntityValidation: []EntityValidationRule{
						{
							Index:       0,
							EphemeralID: "test-email-nonexistent@example.com",
							MinFieldCount: 1,
						},
					},
				},
			},
			{
				Name:        "ResolveNonExistentClientIDWithInference",
				Description: "Should infer entity when client ID doesn't exist and inference is enabled",
				Input: ContractInput{
					Entities: []*entity.Entity{
						CreateTestEntityByClientID("nonexistent-client"),
					},
				},
				Expected: ContractExpected{
					EntityCount: 1,
					ShouldError: false,
					EntityValidation: []EntityValidationRule{
						{
							Index:       0,
							EphemeralID: "test-client-nonexistent-client",
							MinFieldCount: 1,
						},
					},
				},
			},
			// Mixed entity type tests
			{
				Name:        "ResolveMixedEntityTypes",
				Description: "Should resolve mixed entity types in a single request",
				Input: ContractInput{
					Entities: []*entity.Entity{
						CreateTestEntityByUsername("alice"),
						CreateTestEntityByEmail("bob@opentdf.test"),
						CreateTestEntityByClientID("test-client-1"),
					},
				},
				Expected: ContractExpected{
					EntityCount: 3,
					ShouldError: false,
					EntityValidation: []EntityValidationRule{
						{
							Index:       0,
							EphemeralID: "test-user-alice",
							RequiredFields: map[string]interface{}{
								"username": "alice",
							},
							MinFieldCount: 2,
						},
						{
							Index:       1,
							EphemeralID: "test-email-bob@opentdf.test",
							RequiredFields: map[string]interface{}{
								"email": "bob@opentdf.test",
							},
							MinFieldCount: 2,
						},
						{
							Index:       2,
							EphemeralID: "test-client-test-client-1",
							RequiredFields: map[string]interface{}{
								"client_id": "test-client-1",
							},
							MinFieldCount: 1,
						},
					},
				},
			},
		},
		// NOTE: Token-based entity chain tests have been moved to chain_contract_tests.go
		// to avoid struct literal syntax conflicts with existing test cases
	}
}

// RunContractTests executes all contract tests against the given ERS implementation
func (suite *ContractTestSuite) RunContractTests(t *testing.T, implementation ERSImplementation, implementationName string) {
	for _, testCase := range suite.TestCases {
		t.Run(fmt.Sprintf("%s_%s", implementationName, testCase.Name), func(t *testing.T) {
			suite.runSingleContractTest(t, implementation, testCase)
		})
	}
}

// RunContractTestsWithAdapter executes all contract tests against the given ERS adapter
// This is the preferred way to run contract tests as it handles data setup/teardown
func (suite *ContractTestSuite) RunContractTestsWithAdapter(t *testing.T, adapter ERSTestAdapter) {
	ctx := context.Background()
	testDataSet := NewContractTestDataSet()
	
	// Setup test data
	err := adapter.SetupTestData(ctx, testDataSet)
	if err != nil {
		if strings.Contains(err.Error(), "Docker not available") {
			t.Skipf("Skipping %s tests: %v", adapter.GetScopeName(), err)
		}
		t.Fatalf("Failed to setup test data for %s: %v", adapter.GetScopeName(), err)
	}
	
	// Ensure cleanup happens
	t.Cleanup(func() {
		if err := adapter.TeardownTestData(ctx); err != nil {
			t.Logf("Warning: Failed to cleanup test data for %s: %v", adapter.GetScopeName(), err)
		}
	})
	
	// Create ERS service
	implementation, err := adapter.CreateERSService(ctx)
	if err != nil {
		t.Fatalf("Failed to create ERS service for %s: %v", adapter.GetScopeName(), err)
	}
	
	// Run all contract tests
	for _, testCase := range suite.TestCases {
		t.Run(fmt.Sprintf("%s_%s", adapter.GetScopeName(), testCase.Name), func(t *testing.T) {
			suite.runSingleContractTest(t, implementation, testCase)
		})
	}
}

// runSingleContractTest executes a single contract test
func (suite *ContractTestSuite) runSingleContractTest(t *testing.T, implementation ERSImplementation, testCase ContractTestCase) {
	ctx := context.Background()

	// Test ResolveEntities if entities are provided
	if len(testCase.Input.Entities) > 0 {
		req := CreateResolveEntitiesRequest(testCase.Input.Entities...)
		resp, err := implementation.ResolveEntities(ctx, connect.NewRequest(req))

		if testCase.Expected.ShouldError {
			require.Error(t, err, "Expected error but got none")
			connectErr, ok := err.(*connect.Error)
			require.True(t, ok, "Expected connect.Error")
			assert.Equal(t, testCase.Expected.ErrorCode, connectErr.Code(), "Unexpected error code")
			return
		}

		require.NoError(t, err, "Unexpected error: %v", err)
		require.NotNil(t, resp, "Response should not be nil")

		representations := resp.Msg.GetEntityRepresentations()
		assert.Len(t, representations, testCase.Expected.EntityCount, "Unexpected number of entities returned")

		// Validate each entity according to the rules
		for _, validationRule := range testCase.Expected.EntityValidation {
			if validationRule.Index >= len(representations) {
				t.Errorf("Validation rule index %d out of bounds (got %d entities)", validationRule.Index, len(representations))
				continue
			}

			entity := representations[validationRule.Index]
			
			// Validate ephemeral ID
			if validationRule.EphemeralID != "" {
				assert.Equal(t, validationRule.EphemeralID, entity.GetOriginalId(), "Unexpected ephemeral ID")
			}

			// Validate additional properties
			additionalProps := entity.GetAdditionalProps()
			assert.NotEmpty(t, additionalProps, "Additional properties should not be empty")

			if len(additionalProps) > 0 {
				// Convert first additional prop to map for easier validation
				propMap := additionalProps[0].AsMap()
				
				// Check minimum field count
				if validationRule.MinFieldCount > 0 {
					assert.GreaterOrEqual(t, len(propMap), validationRule.MinFieldCount, "Insufficient number of fields in additional properties")
				}

				// Check required fields - with support for alternative field names
				for fieldName, expectedValue := range validationRule.RequiredFields {
					actualValue, exists := propMap[fieldName]
					
					// Handle alternative field names for cross-implementation compatibility
					if !exists && fieldName == "client_id" {
						// Try camelCase version for Keycloak compatibility
						actualValue, exists = propMap["clientId"]
					}
					
					if !exists {
						// Debug: print all available fields when a required field is missing
						t.Logf("DEBUG: Required field '%s' missing. Available fields: %v", fieldName, propMap)
					}
					assert.True(t, exists, "Required field %s is missing", fieldName)
					
					// For flexible validation, we only check if the expected value is non-nil
					if expectedValue != nil {
						// Convert both to strings for easier comparison
						assert.Contains(t, fmt.Sprintf("%v", actualValue), fmt.Sprintf("%v", expectedValue), 
							"Field %s has unexpected value", fieldName)
					}
				}

				// Check forbidden fields
				for _, fieldName := range validationRule.ForbiddenFields {
					_, exists := propMap[fieldName]
					assert.False(t, exists, "Forbidden field %s is present", fieldName)
				}
			}
		}
	}

	// Test CreateEntityChainsFromTokens if tokens are provided
	if len(testCase.Input.Tokens) > 0 {
		req := &entityresolutionV2.CreateEntityChainsFromTokensRequest{
			Tokens: testCase.Input.Tokens,
		}
		resp, err := implementation.CreateEntityChainsFromTokens(ctx, connect.NewRequest(req))

		if testCase.Expected.ShouldError {
			require.Error(t, err, "Expected error but got none")
			connectErr, ok := err.(*connect.Error)
			require.True(t, ok, "Expected connect.Error")
			assert.Equal(t, testCase.Expected.ErrorCode, connectErr.Code(), "Unexpected error code")
			return
		}

		require.NoError(t, err, "Unexpected error: %v", err)
		require.NotNil(t, resp, "Response should not be nil")

		chains := resp.Msg.GetEntityChains()
		
		// Validate each chain according to the rules
		for _, validationRule := range testCase.Expected.ChainValidation {
			// Find the chain with matching ephemeral ID
			var matchingChain *entity.EntityChain
			for _, chain := range chains {
				if chain.GetEphemeralId() == validationRule.EphemeralID {
					matchingChain = chain
					break
				}
			}
			
			require.NotNil(t, matchingChain, "Chain with ephemeral ID %s not found", validationRule.EphemeralID)
			
			entities := matchingChain.GetEntities()
			assert.Len(t, entities, validationRule.EntityCount, "Unexpected number of entities in chain")
			
			// Validate entity types if specified
			if len(validationRule.EntityTypes) > 0 {
				for i, expectedType := range validationRule.EntityTypes {
					if i >= len(entities) {
						break
					}
					actualType := getEntityTypeString(entities[i])
					if validationRule.RequireConsistentOrdering {
						assert.Equal(t, expectedType, actualType, "Unexpected entity type at index %d (strict ordering required)", i)
					} else {
						// For flexible validation, just ensure all expected types are present
						found := false
						for _, entity := range entities {
							if getEntityTypeString(entity) == expectedType {
								found = true
								break
							}
						}
						assert.True(t, found, "Expected entity type %s not found in chain", expectedType)
					}
				}
			}
			
			// Validate entity categories if specified
			if len(validationRule.EntityCategories) > 0 {
				for i, expectedCategory := range validationRule.EntityCategories {
					if i >= len(entities) {
						break
					}
					actualCategory := entities[i].GetCategory().String()
					if validationRule.RequireConsistentOrdering {
						assert.Equal(t, expectedCategory, actualCategory, "Unexpected entity category at index %d (strict ordering required)", i)
					} else {
						// For flexible validation, just ensure all expected categories are present
						found := false
						for _, entity := range entities {
							if entity.GetCategory().String() == expectedCategory {
								found = true
								break
							}
						}
						assert.True(t, found, "Expected entity category %s not found in chain", expectedCategory)
					}
				}
			}
		}
	}
}

// getEntityTypeString returns a string representation of the entity type for validation
func getEntityTypeString(e *entity.Entity) string {
	switch e.GetEntityType().(type) {
	case *entity.Entity_UserName:
		return "username"
	case *entity.Entity_EmailAddress:
		return "email"
	case *entity.Entity_ClientId:
		return "client_id"
	case *entity.Entity_Claims:
		return "claims"
	default:
		return "unknown"
	}
}

// Note: Helper functions for creating test entities are defined in helpers.go