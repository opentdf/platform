package integration

import (
	"testing"

	"github.com/opentdf/platform/service/entityresolution/integration/internal"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	multistrategyv2 "github.com/opentdf/platform/service/entityresolution/multi-strategy/v2"
	"github.com/opentdf/platform/service/logger"
)

// TestMultiStrategyContractValidation runs the complete contract test suite against
// the multi-strategy ERS implementation to validate multi-entity chain support
func TestMultiStrategyContractValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping multi-strategy contract validation tests in short mode")
	}

	// Create chain-specific contract test suite
	chainSuite := internal.NewChainContractTestSuite()

	// Create multi-strategy implementation with enhanced configuration for multi-entity chains
	config := types.MultiStrategyConfig{
		FailureStrategy: types.FailureStrategyContinue, // Critical: Continue to try all strategies
		Providers: map[string]types.ProviderConfig{
			"jwt_claims": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			// Strategy 1: Create ENVIRONMENT entity from client claims (like Keycloak)
			{
				Name:       "client_environment_strategy",
				Provider:   "jwt_claims",
				EntityType: types.EntityTypeEnvironment, // ENVIRONMENT category
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "azp",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "azp",
						ClaimName:   "client_id",
					},
				},
			},
			// Strategy 2: Create SUBJECT entity from user claims (like Keycloak)
			// IMPORTANT: This strategy should NOT create client_id claims to avoid conflicts
			{
				Name:       "user_subject_strategy",
				Provider:   "jwt_claims",
				EntityType: types.EntityTypeSubject, // SUBJECT category
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "sub",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "username",
					},
					{
						SourceClaim: "email",
						ClaimName:   "email_address",
					},
					// Do NOT map azp to client_id in the user strategy
				},
			},
		},
	}

	ctx := t.Context()
	ers, err := multistrategyv2.NewMultiStrategyERSV2(ctx, config, logger.CreateTestLogger())
	if err != nil {
		t.Fatalf("Failed to create multi-strategy ERS: %v", err)
	}

	// Create wrapper for contract testing
	wrapper := &MultiStrategyERSWrapper{
		ers:    ers,
		logger: logger.CreateTestLogger(),
	}

	t.Log("Running multi-entity chain contract tests against Multi-Strategy ERS")

	// Run chain-specific contract tests
	chainSuite.RunChainContractTests(t, wrapper, "MultiStrategy")

	t.Log("✅ Multi-Strategy ERS multi-entity chain contract validation completed successfully!")
	t.Log("🎯 All entity chain tests passed - Multi-Strategy now matches Keycloak behavior")
}

// TestMultiStrategyChainSpecific runs specific chain validation tests
func TestMultiStrategyChainSpecific(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping multi-strategy chain-specific tests in short mode")
	}

	// Use the chain contract test suite
	chainSuite := internal.NewChainContractTestSuite()

	// Create ERS configuration for multi-entity chains
	config := types.MultiStrategyConfig{
		FailureStrategy: types.FailureStrategyContinue,
		Providers: map[string]types.ProviderConfig{
			"jwt_claims": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "client_strategy",
				Provider:   "jwt_claims",
				EntityType: types.EntityTypeEnvironment,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{Claim: "azp", Operator: "exists", Values: []string{}},
					},
				},
				OutputMapping: []types.OutputMapping{
					{SourceClaim: "azp", ClaimName: "client_id"},
				},
			},
			{
				Name:       "user_strategy",
				Provider:   "jwt_claims",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{Claim: "sub", Operator: "exists", Values: []string{}},
					},
				},
				OutputMapping: []types.OutputMapping{
					{SourceClaim: "sub", ClaimName: "username"},
				},
			},
		},
	}

	ctx := t.Context()
	ers, err := multistrategyv2.NewMultiStrategyERSV2(ctx, config, logger.CreateTestLogger())
	if err != nil {
		t.Fatalf("Failed to create multi-strategy ERS: %v", err)
	}

	wrapper := &MultiStrategyERSWrapper{
		ers:    ers,
		logger: logger.CreateTestLogger(),
	}

	// Run chain-specific tests
	chainSuite.RunChainContractTests(t, wrapper, "MultiStrategyChainTest")
}
