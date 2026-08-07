package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	multistrategyv2 "github.com/opentdf/platform/service/entityresolution/multi-strategy/v2"
	"github.com/opentdf/platform/service/logger"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// Integration tests targeting the exact response-marshalling path where the
// []string -> structpb bug lives. The existing multistrategy_contract_test.go
// suite covers chain construction and strategy selection but never asserts
// that resolved entities survive serialization back to the caller — this
// file fills that gap.
//
// These tests exercise the real ERSV2 handler (no HTTP layer) with real
// providers, mirroring the JustInTimePDP call patterns from production.

// serializationTestConfig builds a claims-provider configuration for both
// direct ResolveEntities calls and token-created chains. Token chains preserve
// the phase-1 mapped output and therefore do not need a mirror strategy for a
// second resolution pass.
func serializationTestConfig() types.MultiStrategyConfig {
	return types.MultiStrategyConfig{
		FailureStrategy: types.FailureStrategyContinue,
		Providers: map[string]types.ProviderConfig{
			"jwt_claims": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "user_strategy",
				Provider:   "jwt_claims",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{Claim: "sub", Operator: "exists"},
					},
				},
				OutputMapping: []types.OutputMapping{
					{SourceClaim: "sub", ClaimName: "username"},
					{SourceClaim: "email", ClaimName: "email_address"},
				},
			},
			{
				Name:       "client_strategy",
				Provider:   "jwt_claims",
				EntityType: types.EntityTypeEnvironment,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{Claim: "azp", Operator: "exists"},
					},
				},
				OutputMapping: []types.OutputMapping{
					{SourceClaim: "azp", ClaimName: "client_id"},
				},
			},
		},
	}
}

// ctxWithClaims wraps ctx with JWT claims the way production callers
// (admin API middleware, JustInTimePDP) do before invoking the handler.
func ctxWithClaims(t *testing.T, claims types.JWTClaims) context.Context {
	t.Helper()
	return context.WithValue(t.Context(), types.JWTClaimsContextKey, claims)
}

// entityFromClaims builds an Entity_Claims payload from a map, matching
// what admin UIs / direct API callers send.
func entityFromClaims(t *testing.T, ephemeralID string, claims map[string]interface{}) *entity.Entity {
	t.Helper()
	claimsStruct, err := structpb.NewStruct(claims)
	if err != nil {
		t.Fatalf("build claims struct: %v", err)
	}
	claimsAny, err := anypb.New(claimsStruct)
	if err != nil {
		t.Fatalf("wrap claims in anypb.Any: %v", err)
	}
	return &entity.Entity{
		EphemeralId: ephemeralID,
		EntityType:  &entity.Entity_Claims{Claims: claimsAny},
	}
}

// TestIntegration_ResolveEntities_ReturnsPopulatedRepresentation is spec
// integration test 1: exercise the full v2 handler pipeline in-process
// (real handler + real service + real claims provider + structpb
// serialization) and assert the response contains the resolved claims
// AND metadata_attempted_strategies as an array — the two things the
// caller (KAS/authz) needs to make a decision.
//
// We call the handler in-process rather than via httptest.NewServer
// because the bug is in the handler-to-structpb path, not the HTTP
// transport. In-process exercises the same serialization code with far
// less scaffolding.
func TestIntegration_ResolveEntities_ReturnsPopulatedRepresentation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping multi-strategy integration tests in short mode")
	}

	ers, err := multistrategyv2.NewERSV2(t.Context(), serializationTestConfig(), logger.CreateTestLogger())
	if err != nil {
		t.Fatalf("Failed to create ERSV2: %v", err)
	}

	claims := types.JWTClaims{
		"sub":   "alice",
		"email": "alice@example.com",
	}
	req := connect.NewRequest(&entityresolutionV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{
			entityFromClaims(t, "entity-alice", map[string]interface{}(claims)),
		},
	})

	resp, err := ers.ResolveEntities(ctxWithClaims(t, claims), req)
	if err != nil {
		t.Fatalf("ResolveEntities returned error: %v", err)
	}

	reps := resp.Msg.GetEntityRepresentations()
	if len(reps) != 1 {
		t.Fatalf("EntityRepresentations length = %d, want 1 (empty = handler dropped the entity via structpb.NewStruct failure)", len(reps))
	}

	props := reps[0].GetAdditionalProps()
	if len(props) != 1 {
		t.Fatalf("AdditionalProps length = %d, want 1", len(props))
	}
	fields := props[0].GetFields()

	if got := fields["username"].GetStringValue(); got != "alice" {
		t.Errorf("username = %q, want %q", got, "alice")
	}
	if got := fields["email_address"].GetStringValue(); got != "alice@example.com" {
		t.Errorf("email_address = %q, want %q", got, "alice@example.com")
	}

	metaAttempted, ok := fields["metadata_attempted_strategies"]
	if !ok {
		t.Fatalf("metadata_attempted_strategies missing from response")
	}
	if metaAttempted.GetListValue() == nil {
		t.Errorf("metadata_attempted_strategies must serialize to a ListValue, got kind %T", metaAttempted.GetKind())
	}
}

// TestIntegration_TokenChainPreservesResolvedClaims is spec integration test 2:
// after CreateEntityChainsFromTokens, the returned chain should already contain
// the resolved claims needed for downstream authz. This avoids having to route
// the chain back through ResolveEntities from a lossy identity projection.
func TestIntegration_TokenChainPreservesResolvedClaims(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping multi-strategy integration tests in short mode")
	}

	ers, err := multistrategyv2.NewERSV2(t.Context(), serializationTestConfig(), logger.CreateTestLogger())
	if err != nil {
		t.Fatalf("Failed to create ERSV2: %v", err)
	}

	jwt := createMockJWTForUser("alice", "alice@example.com")

	chainReq := connect.NewRequest(&entityresolutionV2.CreateEntityChainsFromTokensRequest{
		Tokens: []*entity.Token{{EphemeralId: "token-alice", Jwt: jwt}},
	})
	chainResp, err := ers.CreateEntityChainsFromTokens(t.Context(), chainReq)
	if err != nil {
		t.Fatalf("CreateEntityChainsFromTokens returned error: %v", err)
	}

	chains := chainResp.Msg.GetEntityChains()
	if len(chains) != 1 {
		t.Fatalf("EntityChains length = %d, want 1", len(chains))
	}
	chainEntities := chains[0].GetEntities()
	if len(chainEntities) == 0 {
		t.Fatalf("chain contains no entities")
	}

	for i, chained := range chainEntities {
		claims := chained.GetClaims()
		if claims == nil {
			t.Fatalf("entity %d should preserve resolved claims in the chain, got type %T", i, chained.GetEntityType())
		}

		var claimsStruct structpb.Struct
		if err := claims.UnmarshalTo(&claimsStruct); err != nil {
			t.Fatalf("entity %d claims unmarshal failed: %v", i, err)
		}
		asMap := claimsStruct.AsMap()
		if got := asMap["username"]; got != "alice" {
			t.Fatalf("entity %d username = %v, want alice", i, got)
		}
		if got := asMap["email_address"]; got != "alice@example.com" {
			t.Fatalf("entity %d email_address = %v, want alice@example.com", i, got)
		}
	}
}

// TestIntegration_FailureIsolation_MixedBatch is spec integration test 3:
// with failure_strategy: continue and a batch where some entities resolve
// and one fails to match any strategy, the response must include ALL
// entities — resolved ones with their claims, failed ones with an error
// AdditionalProps struct. This confirms the handler's `continue` on
// structpb failure isn't swallowing legitimate successes silently
// (the current bug's symptom).
func TestIntegration_FailureIsolation_MixedBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping multi-strategy integration tests in short mode")
	}

	ers, err := multistrategyv2.NewERSV2(t.Context(), serializationTestConfig(), logger.CreateTestLogger())
	if err != nil {
		t.Fatalf("Failed to create ERSV2: %v", err)
	}

	// Batch: two entities that resolve, one whose claims don't match any
	// strategy (no `sub`, no `azp`) and will produce an error.
	req := connect.NewRequest(&entityresolutionV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{
			entityFromClaims(t, "good-1", map[string]interface{}{"sub": "alice"}),
			entityFromClaims(t, "bad-1", map[string]interface{}{"unrelated_claim": "x"}),
			entityFromClaims(t, "good-2", map[string]interface{}{"azp": "svc-account"}),
		},
	})

	// The handler processes each entity independently, so the ctx must
	// hold the right claims per entity — but claims-in-ctx is a single
	// map. To keep the test focused on the batch-isolation property (not
	// the ctx-plumbing quirk of the claims provider), populate ctx with a
	// superset containing the union of good entities' claims. The bad
	// entity will still fail because its INPUT claimsMap (from the
	// request payload) doesn't satisfy strategy conditions.
	ctx := ctxWithClaims(t, types.JWTClaims{
		"sub":   "alice",
		"email": "alice@example.com",
		"azp":   "svc-account",
	})
	resp, err := ers.ResolveEntities(ctx, req)
	if err != nil {
		t.Fatalf("ResolveEntities returned error: %v", err)
	}

	reps := resp.Msg.GetEntityRepresentations()
	if len(reps) != 3 {
		t.Fatalf("EntityRepresentations length = %d, want 3 (all entities must appear — resolved OR error-struct)", len(reps))
	}

	// Index by OriginalId for order-independence.
	byID := make(map[string]*entityresolutionV2.EntityRepresentation, len(reps))
	for _, r := range reps {
		byID[r.GetOriginalId()] = r
	}

	// good-1 and good-2 must have resolved data.
	for _, id := range []string{"good-1", "good-2"} {
		rep, ok := byID[id]
		if !ok {
			t.Fatalf("resolved entity %q missing from response — the handler silently dropped it", id)
		}
		props := rep.GetAdditionalProps()
		if len(props) == 0 {
			t.Errorf("resolved entity %q has empty AdditionalProps", id)
			continue
		}
		if _, hasError := props[0].GetFields()["error"]; hasError {
			t.Errorf("resolved entity %q unexpectedly carries an error struct", id)
		}
	}

	// bad-1 must appear with an error struct (not silently dropped).
	bad, ok := byID["bad-1"]
	if !ok {
		t.Fatalf("errored entity %q missing from response — the handler silently dropped it", "bad-1")
	}
	badProps := bad.GetAdditionalProps()
	if len(badProps) == 0 {
		t.Fatalf("errored entity has empty AdditionalProps; expected error struct")
	}
	if _, hasError := badProps[0].GetFields()["error"]; !hasError {
		t.Errorf("errored entity's AdditionalProps missing `error` field; got fields %v", badProps[0].GetFields())
	}
}
