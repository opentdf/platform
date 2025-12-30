package internal

import (
	"fmt"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Test constants for entity chain resolution expectations
	expectedChainEntityCount = 2
)

// ChainContractTestSuite holds implementation-agnostic multi-entity chain validation tests
type ChainContractTestSuite struct {
	TestCases []ContractTestCase
}

// NewChainContractTestSuite creates a test suite focused on implementation-agnostic multi-entity chain validation
func NewChainContractTestSuite() *ChainContractTestSuite {
	return &ChainContractTestSuite{
		TestCases: []ContractTestCase{
			{
				Name:        "CreateMultiEntityChainFromSingleToken",
				Description: "Should create entity chain with multiple entities and proper categorization",
				Input: ContractInput{
					Entities: []*entity.Entity{},
					Tokens: []*entity.Token{
						CreateTestToken("chain-token-1", "test-client-1", "alice", "alice@opentdf.test"),
					},
				},
				Expected: ContractExpected{
					EntityCount:      0,
					ShouldError:      false,
					ErrorCode:        0,
					EntityValidation: []EntityValidationRule{},
					ChainValidation: []EntityChainValidationRule{
						{
							EphemeralID:               "chain-token-1",
							EntityCount:               expectedChainEntityCount,                             // Both Keycloak and Multi-Strategy create 2 entities per token
							EntityTypes:               []string{},                                           // Implementation-agnostic: don't specify entity types
							EntityCategories:          []string{"CATEGORY_ENVIRONMENT", "CATEGORY_SUBJECT"}, // Both must create these categories
							RequireConsistentOrdering: false,                                                // Allow flexible ordering between implementations
						},
					},
				},
			},
			{
				Name:        "CreateMultiEntityChainsFromMultipleTokens",
				Description: "Should create multiple entity chains with consistent multi-entity behavior",
				Input: ContractInput{
					Entities: []*entity.Entity{},
					Tokens: []*entity.Token{
						CreateTestToken("chain-token-1", "test-client-1", "alice", "alice@opentdf.test"),
						CreateTestToken("chain-token-2", "test-client-2", "bob", "bob@opentdf.test"),
					},
				},
				Expected: ContractExpected{
					EntityCount:      0,
					ShouldError:      false,
					ErrorCode:        0,
					EntityValidation: []EntityValidationRule{},
					ChainValidation: []EntityChainValidationRule{
						{
							EphemeralID:               "chain-token-1",
							EntityCount:               expectedChainEntityCount, // Both implementations create 2 entities per token
							EntityTypes:               []string{},               // Implementation-agnostic
							EntityCategories:          []string{"CATEGORY_ENVIRONMENT", "CATEGORY_SUBJECT"},
							RequireConsistentOrdering: false,
						},
						{
							EphemeralID:               "chain-token-2",
							EntityCount:               expectedChainEntityCount, // Consistent behavior across tokens
							EntityTypes:               []string{},               // Implementation-agnostic
							EntityCategories:          []string{"CATEGORY_ENVIRONMENT", "CATEGORY_SUBJECT"},
							RequireConsistentOrdering: false,
						},
					},
				},
			},
			{
				Name:        "ValidateEntityChainCategoryDifferentiation",
				Description: "Should create entity chains with distinct ENVIRONMENT and SUBJECT categories",
				Input: ContractInput{
					Entities: []*entity.Entity{},
					Tokens: []*entity.Token{
						CreateTestToken("category-test-token", "opentdf-sdk", "charlie", "charlie@opentdf.test"),
					},
				},
				Expected: ContractExpected{
					EntityCount:      0,
					ShouldError:      false,
					ErrorCode:        0,
					EntityValidation: []EntityValidationRule{},
					ChainValidation: []EntityChainValidationRule{
						{
							EphemeralID:               "category-test-token",
							EntityCount:               expectedChainEntityCount,                             // Both implementations create multiple entities
							EntityTypes:               []string{},                                           // Implementation-agnostic: entity types vary by implementation
							EntityCategories:          []string{"CATEGORY_ENVIRONMENT", "CATEGORY_SUBJECT"}, // Contract: both categories must exist
							RequireConsistentOrdering: false,                                                // Allow implementation flexibility
						},
					},
				},
			},
			{
				Name:        "ValidateMultiEntityChainConsistency",
				Description: "Should create consistent multi-entity chains across multiple invocations",
				Input: ContractInput{
					Entities: []*entity.Entity{},
					Tokens: []*entity.Token{
						CreateTestToken("consistency-token", "test-client-1", "alice", "alice@opentdf.test"),
					},
				},
				Expected: ContractExpected{
					EntityCount:      0,
					ShouldError:      false,
					ErrorCode:        0,
					EntityValidation: []EntityValidationRule{},
					ChainValidation: []EntityChainValidationRule{
						{
							EphemeralID:               "consistency-token",
							EntityCount:               expectedChainEntityCount, // Consistent entity count across implementations
							EntityTypes:               []string{},               // Implementation-specific entity types allowed
							EntityCategories:          []string{"CATEGORY_ENVIRONMENT", "CATEGORY_SUBJECT"},
							RequireConsistentOrdering: false, // Behavioral contract, not implementation details
						},
					},
				},
			},
		},
	}
}

// RunChainContractTests executes multi-entity chain tests against an ERS implementation
func (suite *ChainContractTestSuite) RunChainContractTests(t *testing.T, implementation ERSImplementation, _ string) {
	for _, testCase := range suite.TestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			suite.runSingleChainTest(t, implementation, testCase)
		})
	}
}

// runSingleChainTest executes a single multi-entity chain test
func (suite *ChainContractTestSuite) runSingleChainTest(t *testing.T, implementation ERSImplementation, testCase ContractTestCase) {
	// Test CreateEntityChainsFromTokens if tokens are provided
	if len(testCase.Input.Tokens) == 0 {
		return
	}

	chains, err := suite.executeChainRequest(t, implementation, testCase)
	if err != nil {
		return // Error already handled in helper
	}

	// Validate each chain according to the rules
	for _, validationRule := range testCase.Expected.ChainValidation {
		suite.validateSingleChain(t, chains, validationRule)
	}
}

// executeChainRequest handles the request execution and error handling
func (suite *ChainContractTestSuite) executeChainRequest(t *testing.T, implementation ERSImplementation, testCase ContractTestCase) ([]*entity.EntityChain, error) {
	ctx := t.Context()
	req := &entityresolutionV2.CreateEntityChainsFromTokensRequest{
		Tokens: testCase.Input.Tokens,
	}
	resp, err := implementation.CreateEntityChainsFromTokens(ctx, connect.NewRequest(req))

	if testCase.Expected.ShouldError {
		require.Error(t, err, "Expected error but got none")
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr, "Expected connect.Error")
		assert.Equal(t, testCase.Expected.ErrorCode, connectErr.Code(), "Unexpected error code")
		return nil, err
	}

	require.NoError(t, err, "Unexpected error: %v", err)
	require.NotNil(t, resp, "Response should not be nil")

	return resp.Msg.GetEntityChains(), nil
}

// validateSingleChain validates a single entity chain according to the validation rule
func (suite *ChainContractTestSuite) validateSingleChain(t *testing.T, chains []*entity.EntityChain, validationRule EntityChainValidationRule) {
	matchingChain := suite.findChainByEphemeralID(chains, validationRule.EphemeralID)
	require.NotNil(t, matchingChain, "Chain with ephemeral ID %s not found", validationRule.EphemeralID)

	entities := matchingChain.GetEntities()
	assert.Len(t, entities, validationRule.EntityCount, "Unexpected number of entities in chain")

	suite.validateEntityTypes(t, entities, validationRule)
	suite.validateEntityCategories(t, entities, validationRule)
}

// findChainByEphemeralID finds a chain with matching ephemeral ID
func (suite *ChainContractTestSuite) findChainByEphemeralID(chains []*entity.EntityChain, ephemeralID string) *entity.EntityChain {
	for _, chain := range chains {
		if chain.GetEphemeralId() == ephemeralID {
			return chain
		}
	}
	return nil
}

// validateEntityTypes validates entity types in the chain
func (suite *ChainContractTestSuite) validateEntityTypes(t *testing.T, entities []*entity.Entity, validationRule EntityChainValidationRule) {
	if len(validationRule.EntityTypes) == 0 {
		// Implementation-agnostic mode: log actual entity types for debugging
		actualTypes := make([]string, len(entities))
		for i, entity := range entities {
			actualTypes[i] = getEntityTypeString(entity)
		}
		t.Logf("Implementation-agnostic validation: Chain contains entity types: %v", actualTypes)
		return
	}

	for i, expectedType := range validationRule.EntityTypes {
		if i >= len(entities) {
			break
		}
		suite.validateSingleEntityType(t, entities, expectedType, i, validationRule.RequireConsistentOrdering)
	}
}

// validateSingleEntityType validates a single entity type
func (suite *ChainContractTestSuite) validateSingleEntityType(t *testing.T, entities []*entity.Entity, expectedType string, index int, requireOrdering bool) {
	actualType := getEntityTypeString(entities[index])
	if requireOrdering {
		assert.Equal(t, expectedType, actualType, "Unexpected entity type at index %d (strict ordering required)", index)
		return
	}

	// For flexible validation, ensure all expected types are present
	for _, entity := range entities {
		if getEntityTypeString(entity) == expectedType {
			return
		}
	}
	assert.Fail(t, fmt.Sprintf("Expected entity type %s not found in chain", expectedType))
}

// validateEntityCategories validates entity categories in the chain
func (suite *ChainContractTestSuite) validateEntityCategories(t *testing.T, entities []*entity.Entity, validationRule EntityChainValidationRule) {
	for i, expectedCategory := range validationRule.EntityCategories {
		if i >= len(entities) {
			break
		}
		suite.validateSingleEntityCategory(t, entities, expectedCategory, i, validationRule.RequireConsistentOrdering)
	}
}

// validateSingleEntityCategory validates a single entity category
func (suite *ChainContractTestSuite) validateSingleEntityCategory(t *testing.T, entities []*entity.Entity, expectedCategory string, index int, requireOrdering bool) {
	actualCategory := entities[index].GetCategory().String()
	if requireOrdering {
		assert.Equal(t, expectedCategory, actualCategory, "Unexpected entity category at index %d (strict ordering required)", index)
		return
	}

	// For flexible validation, ensure all expected categories are present
	for _, entity := range entities {
		if entity.GetCategory().String() == expectedCategory {
			return
		}
	}
	assert.Fail(t, fmt.Sprintf("Expected entity category %s not found in chain", expectedCategory))
}

// getEntityTypeString is defined in contract_tests.go
