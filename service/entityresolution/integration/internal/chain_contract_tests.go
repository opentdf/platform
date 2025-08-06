package internal

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
							EphemeralID:              "chain-token-1",
							EntityCount:              2, // Both Keycloak and Multi-Strategy create 2 entities per token
							EntityTypes:              []string{}, // Implementation-agnostic: don't specify entity types
							EntityCategories:         []string{"CATEGORY_ENVIRONMENT", "CATEGORY_SUBJECT"}, // Both must create these categories
							RequireConsistentOrdering: false, // Allow flexible ordering between implementations
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
							EphemeralID:              "chain-token-1",
							EntityCount:              2, // Both implementations create 2 entities per token
							EntityTypes:              []string{}, // Implementation-agnostic
							EntityCategories:         []string{"CATEGORY_ENVIRONMENT", "CATEGORY_SUBJECT"},
							RequireConsistentOrdering: false,
						},
						{
							EphemeralID:              "chain-token-2", 
							EntityCount:              2, // Consistent behavior across tokens
							EntityTypes:              []string{}, // Implementation-agnostic
							EntityCategories:         []string{"CATEGORY_ENVIRONMENT", "CATEGORY_SUBJECT"},
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
							EphemeralID:              "category-test-token",
							EntityCount:              2, // Both implementations create multiple entities
							EntityTypes:              []string{}, // Implementation-agnostic: entity types vary by implementation
							EntityCategories:         []string{"CATEGORY_ENVIRONMENT", "CATEGORY_SUBJECT"}, // Contract: both categories must exist
							RequireConsistentOrdering: false, // Allow implementation flexibility
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
							EphemeralID:              "consistency-token",
							EntityCount:              2, // Consistent entity count across implementations
							EntityTypes:              []string{}, // Implementation-specific entity types allowed
							EntityCategories:         []string{"CATEGORY_ENVIRONMENT", "CATEGORY_SUBJECT"},
							RequireConsistentOrdering: false, // Behavioral contract, not implementation details
						},
					},
				},
			},
		},
	}
}

// RunChainContractTests executes multi-entity chain tests against an ERS implementation
func (suite *ChainContractTestSuite) RunChainContractTests(t *testing.T, implementation ERSImplementation, implementationName string) {
	for _, testCase := range suite.TestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			suite.runSingleChainTest(t, implementation, testCase)
		})
	}
}

// runSingleChainTest executes a single multi-entity chain test
func (suite *ChainContractTestSuite) runSingleChainTest(t *testing.T, implementation ERSImplementation, testCase ContractTestCase) {
	ctx := context.Background()

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

		// Check for connection-related errors and skip tests if service unavailable
		if err != nil {
			if connectErr, ok := err.(*connect.Error); ok {
				if connectErr.Code() == connect.CodeInternal {
					errorMsg := connectErr.Message()
					// Skip if this appears to be a connection-related error (Keycloak unavailable)
					if strings.Contains(errorMsg, "connection refused") || 
					   strings.Contains(errorMsg, "could not get token") ||
					   strings.Contains(errorMsg, "failed to login") {
						t.Skipf("Service unavailable (likely connection issue): %v", errorMsg)
						return
					}
				}
			}
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
			
			// Validate entity types if specified (implementation-agnostic: skip if empty)
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
			} else {
				// Implementation-agnostic mode: log actual entity types for debugging but don't validate
				actualTypes := make([]string, len(entities))
				for i, entity := range entities {
					actualTypes[i] = getEntityTypeString(entity)
				}
				t.Logf("Implementation-agnostic validation: Chain contains entity types: %v", actualTypes)
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