package internal

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ChainShape describes the chain an implementation is expected to build for one token.
// Entity count and categories are implementation-specific: Keycloak always emits an
// ENVIRONMENT (client) plus a SUBJECT (user) entity, while multi-strategy ERS is
// first-match-wins per its ADR and emits exactly one entity from the first matching
// strategy. Everything else the suite asserts is genuinely implementation-agnostic.
type ChainShape struct {
	EntityCount      int
	EntityCategories []string
}

// keycloakChainEntityCount is the ENVIRONMENT (client) plus SUBJECT (user) pair Keycloak
// emits for every token.
const keycloakChainEntityCount = 2

// KeycloakChainShape is the two-entity ENVIRONMENT + SUBJECT chain Keycloak produces per token.
func KeycloakChainShape() ChainShape {
	return ChainShape{
		EntityCount:      keycloakChainEntityCount,
		EntityCategories: []string{"CATEGORY_ENVIRONMENT", "CATEGORY_SUBJECT"},
	}
}

// ChainContractTestSuite holds implementation-agnostic entity chain validation tests
type ChainContractTestSuite struct {
	TestCases []ContractTestCase
}

// NewChainContractTestSuite creates a chain contract suite for an implementation that
// builds Keycloak-shaped two-entity chains.
func NewChainContractTestSuite() *ChainContractTestSuite {
	return NewChainContractTestSuiteWithShape(KeycloakChainShape())
}

// NewChainContractTestSuiteWithShape creates a chain contract suite that validates chains
// against the given implementation-specific shape.
func NewChainContractTestSuiteWithShape(shape ChainShape) *ChainContractTestSuite {
	expectedChainEntityCount := shape.EntityCount
	expectedChainCategories := shape.EntityCategories

	return &ChainContractTestSuite{
		TestCases: []ContractTestCase{
			{
				Name:        "CreateEntityChainFromSingleToken",
				Description: "Should create an entity chain matching the implementation chain shape with proper categorization",
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
							EntityCount:               expectedChainEntityCount,
							EntityTypes:               []string{}, // Implementation-agnostic: don't specify entity types
							EntityCategories:          expectedChainCategories,
							RequireConsistentOrdering: false, // Allow flexible ordering between implementations
						},
					},
				},
			},
			{
				Name:        "CreateEntityChainsFromMultipleTokens",
				Description: "Should create one entity chain per token with consistent shape",
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
							EntityCount:               expectedChainEntityCount,
							EntityTypes:               []string{}, // Implementation-agnostic
							EntityCategories:          expectedChainCategories,
							RequireConsistentOrdering: false,
						},
						{
							EphemeralID:               "chain-token-2",
							EntityCount:               expectedChainEntityCount,
							EntityTypes:               []string{}, // Implementation-agnostic
							EntityCategories:          expectedChainCategories,
							RequireConsistentOrdering: false,
						},
					},
				},
			},
			{
				Name:        "ValidateEntityChainCategoryDifferentiation",
				Description: "Should create entity chains carrying the expected entity categories",
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
							EntityCount:               expectedChainEntityCount,
							EntityTypes:               []string{}, // Implementation-agnostic: entity types vary by implementation
							EntityCategories:          expectedChainCategories,
							RequireConsistentOrdering: false, // Allow implementation flexibility
						},
					},
				},
			},
			{
				Name:        "ValidateEntityChainConsistency",
				Description: "Should create consistent entity chains across multiple invocations",
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
							EntityCount:               expectedChainEntityCount,
							EntityTypes:               []string{}, // Implementation-specific entity types allowed
							EntityCategories:          expectedChainCategories,
							RequireConsistentOrdering: false, // Behavioral contract, not implementation details
						},
					},
				},
			},
		},
	}
}

// RunChainContractTests executes entity chain tests against an ERS implementation
func (suite *ChainContractTestSuite) RunChainContractTests(t *testing.T, implementation ERSImplementation, _ string) {
	for _, testCase := range suite.TestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			suite.runSingleChainTest(t, implementation, testCase)
		})
	}
}

// runSingleChainTest executes a single entity chain test
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

	suite.handleConnectionErrors(t, err)

	require.NoError(t, err, "Unexpected error: %v", err)
	require.NotNil(t, resp, "Response should not be nil")

	return resp.Msg.GetEntityChains(), nil
}

// handleConnectionErrors checks for connection-related errors and skips tests if service unavailable
func (suite *ChainContractTestSuite) handleConnectionErrors(t *testing.T, err error) {
	if err == nil {
		return
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		return
	}

	if connectErr.Code() != connect.CodeInternal {
		return
	}

	errorMsg := connectErr.Message()
	if strings.Contains(errorMsg, "connection refused") ||
		strings.Contains(errorMsg, "could not get token") ||
		strings.Contains(errorMsg, "failed to login") {
		t.Skipf("Service unavailable (likely connection issue): %v", errorMsg)
		return
	}
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
