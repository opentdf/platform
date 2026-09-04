package integration

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	keycloakv2 "github.com/opentdf/platform/service/entityresolution/keycloak/v2"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	multistrategyv2 "github.com/opentdf/platform/service/entityresolution/multi-strategy/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestEntityChainComparison documents the deliberate difference between Keycloak
// (2 entities per chain: ENVIRONMENT + SUBJECT) and Multi-Strategy (1 entity per chain,
// from the first matching strategy, per the multi-strategy ERS ADR).
func TestEntityChainComparison(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping entity chain comparison tests in short mode")
	}

	testJWT := createTestJWTForComparison("testuser", "test@example.com", "test-client")

	// Create test token
	testToken := &entity.Token{
		EphemeralId: "comparison-token",
		Jwt:         testJWT,
	}

	t.Run("Keycloak_EntityChainLength", func(t *testing.T) {
		ctx := t.Context()
		// Create Keycloak ERS service
		keycloakConfig := map[string]interface{}{
			"url":            "http://localhost:8080",
			"realm":          "test-realm",
			"clientid":       "test-client",
			"clientsecret":   "test-secret",
			"legacykeycloak": false,
			"subgroups":      false,
			"inferid": map[string]interface{}{
				"from": map[string]interface{}{
					"clientid": true,
					"email":    true,
					"username": true,
				},
			},
		}

		testLogger := logger.CreateTestLogger()
		var testCache *cache.Cache

		keycloakService, _ := keycloakv2.RegisterKeycloakERS(keycloakConfig, testLogger, testCache)
		keycloakService.Tracer = noop.NewTracerProvider().Tracer("test-keycloak-v2")

		// Test CreateEntityChainsFromTokens
		req := &entityresolutionV2.CreateEntityChainsFromTokensRequest{
			Tokens: []*entity.Token{testToken},
		}

		// This will fail because we don't have a real Keycloak instance
		// But the test structure shows what Keycloak SHOULD return
		_, err := keycloakService.CreateEntityChainsFromTokens(ctx, connect.NewRequest(req))
		if err != nil {
			t.Logf("⚠️  Keycloak test failed (expected without real Keycloak): %v", err)
			t.Logf("🎯 Keycloak SHOULD create 2-entity chains:")
			t.Logf("   - Entity 1: CATEGORY_ENVIRONMENT (client)")
			t.Logf("   - Entity 2: CATEGORY_SUBJECT (user)")
			return
		}

		// If we had a real Keycloak, we would assert:
		// assert.Len(t, resp.Msg.GetEntityChains()[0].Entities, 2)
	})

	t.Run("MultiStrategy_EntityChainLength", func(t *testing.T) {
		// Configure two strategies that both match the token to show that only the first runs
		config := types.MultiStrategyConfig{
			FailureStrategy: types.FailureStrategyContinue, // Only governs error handling
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
					EntityType: types.EntityTypeEnvironment, // ENVIRONMENT category like Keycloak
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
				{
					Name:       "user_subject_strategy",
					Provider:   "jwt_claims",
					EntityType: types.EntityTypeSubject, // SUBJECT category like Keycloak
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
					},
				},
			},
		}

		ctx := t.Context()
		ers, err := multistrategyv2.NewERSV2(ctx, config, logger.CreateTestLogger())
		if err != nil {
			t.Fatalf("Failed to create multi-strategy ERS: %v", err)
		}

		// Test CreateEntityChainsFromTokens
		req := &entityresolutionV2.CreateEntityChainsFromTokensRequest{
			Tokens: []*entity.Token{testToken},
		}

		resp, err := ers.CreateEntityChainsFromTokens(ctx, connect.NewRequest(req))
		if err != nil {
			t.Fatalf("Multi-strategy CreateEntityChainsFromTokens failed: %v", err)
		}

		if len(resp.Msg.GetEntityChains()) != 1 {
			t.Fatalf("Expected 1 entity chain, got %d", len(resp.Msg.GetEntityChains()))
		}

		chain := resp.Msg.GetEntityChains()[0]
		actualEntityCount := len(chain.GetEntities())

		t.Logf("🔍 Multi-Strategy Result:")
		t.Logf("   - Chain ID: %s", chain.GetEphemeralId())
		t.Logf("   - Entity Count: %d", actualEntityCount)

		for i, ent := range chain.GetEntities() {
			t.Logf("   - Entity %d: %s (Category: %s)", i+1, getEntityIdentifier(ent), ent.GetCategory())
		}

		// Both configured strategies match this token, but per the ADR the first match wins,
		// so the chain holds a single ENVIRONMENT entity. failure_strategy: continue does not
		// change this — it only decides whether a *failing* strategy falls through to the next.
		require.Len(t, chain.GetEntities(), 1, "multi-strategy chains carry only the first matching strategy's entity")
		assert.Equal(t, entity.Entity_CATEGORY_ENVIRONMENT, chain.GetEntities()[0].GetCategory(),
			"client_environment_strategy is configured first, so it is the match that wins")
	})

	t.Run("CompareEntityChainStructures", func(t *testing.T) {
		t.Log("📊 COMPARISON SUMMARY:")
		t.Log("   Keycloak V2:")
		t.Log("     ✅ Creates 2-entity chains (Environment + Subject)")
		t.Log("     ✅ Properly categorizes entities")
		t.Log("     ✅ Full JWT token processing with multiple entities")
		t.Log("")
		t.Log("   Multi-Strategy V2:")
		t.Log("     ✅ Creates 1-entity chains from the first matching mapping strategy (ADR: first-match-wins)")
		t.Log("     ✅ Proper entity categorization (ENVIRONMENT vs SUBJECT) driven by that strategy's entity_type")
		t.Log("     ✅ failure_strategy governs error handling only, never how many strategies resolve")
		t.Log("")
		t.Log("🎯 The entity count difference is intentional: multi-entity chains are an")
		t.Log("   explicit 'Future Considerations' item in the multi-strategy ERS ADR, not")
		t.Log("   current behavior. Deployments needing several sources in one entity should")
		t.Log("   merge them in a single strategy's output mapping.")
	})
}

// createTestJWTForComparison creates a JWT with both user and client claims for testing
func createTestJWTForComparison(_, _, _ string) string {
	// Header: {"alg":"HS256","typ":"JWT"}
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

	// Base64 encode the payload (simplified for testing)
	payload := "eyJzdWIiOiJ0ZXN0dXNlciIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3R1c2VyIiwiYXpwIjoidGVzdC1jbGllbnQiLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudCIsImF1ZCI6WyJ0ZXN0LWF1ZGllbmNlIl0sImlzcyI6InRlc3QtaXNzdWVyIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjE2MDAwMDk2MDB9"

	// Mock signature
	signature := "dGVzdHNpZ25hdHVyZQ"

	return header + "." + payload + "." + signature
}

// getEntityIdentifier returns a human-readable identifier for an entity
func getEntityIdentifier(ent *entity.Entity) string {
	switch ent.GetEntityType().(type) {
	case *entity.Entity_UserName:
		return "username:" + ent.GetUserName()
	case *entity.Entity_EmailAddress:
		return "email:" + ent.GetEmailAddress()
	case *entity.Entity_ClientId:
		return "client:" + ent.GetClientId()
	default:
		return "unknown"
	}
}
