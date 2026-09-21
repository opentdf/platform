package multistrategy

import (
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestClaimsToResultData(t *testing.T) {
	type profile struct {
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}

	tests := []struct {
		name   string
		claims map[string]interface{}
		want   map[string]interface{}
	}{
		{
			name:   "nil claims",
			claims: nil,
			want:   map[string]interface{}{},
		},
		{
			name: "all claims are normalized in one pass",
			claims: map[string]interface{}{
				"groups":    []string{"engineering", "platform"},
				"group_ids": []int{1, 2},
				"attributes": map[string][]bool{
					"enabled": {true, false},
				},
				"profile": profile{Name: "alice", Groups: []string{"engineering"}},
				"age":     42,
			},
			want: map[string]interface{}{
				"groups":    []interface{}{"engineering", "platform"},
				"group_ids": []interface{}{float64(1), float64(2)},
				"attributes": map[string]interface{}{
					"enabled": []interface{}{true, false},
				},
				"profile": map[string]interface{}{
					"name":   "alice",
					"groups": []interface{}{"engineering"},
				},
				"age": float64(42),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := claimsToResultData(tt.claims)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestClaimsToResultDataReturnsMarshalError(t *testing.T) {
	claims := map[string]interface{}{"unsupported": make(chan int)}

	_, err := claimsToResultData(claims)
	require.Error(t, err)
}

// TestERSV2_ResolveEntities_PopulatesRepresentations is spec item 4: the
// v2 handler's direct symptom test. When ResolveEntity succeeds but its
// Metadata contains a value structpb.NewValue rejects, the handler drops
// the entity via `continue` on line 134 of registration.go, and the client
// sees EntityRepresentations = []. This test asserts the opposite: a
// successfully resolved entity flows all the way through the handler's
// structpb serialization and appears in the response, with
// metadata_attempted_strategies as a ListValue (not missing, not stringified).
//
// Runs the real ERSV2 handler against a real Service with a claims
// provider — no HTTP transport, no fake service. That's still a unit test
// (in-process, no external deps) and exercises the exact serialization
// path where the bug lives.
func TestERSV2_ResolveEntities_PopulatesRepresentations(t *testing.T) {
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "jwt_strategy",
				Provider:   "jwt",
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
		},
	}

	ers, err := NewERSV2(t.Context(), config, logger.CreateTestLogger())
	require.NoError(t, err)

	claimsStruct, err := structpb.NewStruct(map[string]interface{}{
		"sub":   "alice",
		"email": "alice@example.com",
	})
	require.NoError(t, err)
	claimsAny, err := anypb.New(claimsStruct)
	require.NoError(t, err)

	req := connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{
			{
				EphemeralId: "entity-1",
				EntityType:  &entity.Entity_Claims{Claims: claimsAny},
			},
		},
	})

	resp, err := ers.ResolveEntities(t.Context(), req)
	require.NoError(t, err)

	reps := resp.Msg.GetEntityRepresentations()
	require.Len(t, reps, 1, "empty response means the handler silently dropped the entity via structpb.NewStruct failure")
	require.Equal(t, "entity-1", reps[0].GetOriginalId())

	props := reps[0].GetAdditionalProps()
	require.Len(t, props, 1)
	fields := props[0].GetFields()

	// The resolved claim should be present.
	require.Equal(t, "alice", fields["username"].GetStringValue())

	// metadata_attempted_strategies MUST serialize to a ListValue. If the
	// source-level fix regresses and the field is stored as []string again,
	// structpb.NewStruct will drop the whole entity and this assertion (and
	// the length assertion above) will fail.
	metaAttempted, ok := fields["metadata_attempted_strategies"]
	require.True(t, ok, "metadata_attempted_strategies missing from AdditionalProps; the handler likely dropped the entity")
	list := metaAttempted.GetListValue()
	require.NotNil(t, list, "metadata_attempted_strategies has kind %T", metaAttempted.GetKind())
	require.Len(t, list.GetValues(), 1)
	require.Equal(t, "jwt_strategy", list.GetValues()[0].GetStringValue())
}

func TestResolveEntities_ClaimsProviderUsesInlineClaimsContext(t *testing.T) {
	erService, err := NewERSV2(t.Context(), types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "claims_passthrough",
				Provider:   "jwt",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "sub",
							Operator: "exists",
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "subject",
					},
					{
						SourceClaim: "email",
						ClaimName:   "email_address",
					},
				},
			},
		},
	}, logger.CreateTestLogger())
	require.NoError(t, err)

	claimsStruct, err := structpb.NewStruct(map[string]interface{}{
		"sub":   "diana",
		"email": "diana@example.com",
	})
	require.NoError(t, err)

	claimsAny, err := anypb.New(claimsStruct)
	require.NoError(t, err)

	resp, err := erService.ResolveEntities(t.Context(), connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{
			{
				EphemeralId: "diana-claims",
				EntityType:  &entity.Entity_Claims{Claims: claimsAny},
				Category:    entity.Entity_CATEGORY_SUBJECT,
			},
		},
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetEntityRepresentations(), 1)

	props := resp.Msg.GetEntityRepresentations()[0].GetAdditionalProps()
	require.Len(t, props, 1)

	result := props[0].AsMap()
	require.Equal(t, "diana", result["subject"])
	require.Equal(t, "diana@example.com", result["email_address"])
	require.Equal(t, "jwt_claims", result["metadata_source"])
	require.NotContains(t, result, "error")
}

func TestResolveEntities_UserNameEntityDoesNotSeedClaimsContext(t *testing.T) {
	erService, err := NewERSV2(t.Context(), types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		FailureStrategy: types.FailureStrategyContinue,
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "claims_passthrough",
				Provider:   "jwt",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{{Claim: "userName", Operator: "exists"}},
				},
				OutputMapping: []types.OutputMapping{{SourceClaim: "userName", ClaimName: "username"}},
			},
		},
	}, logger.CreateTestLogger())
	require.NoError(t, err)

	resp, err := erService.ResolveEntities(t.Context(), connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{{
			EphemeralId: "alice-user-name",
			EntityType:  &entity.Entity_UserName{UserName: "alice"},
			Category:    entity.Entity_CATEGORY_SUBJECT,
		}},
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetEntityRepresentations(), 1)

	props := resp.Msg.GetEntityRepresentations()[0].GetAdditionalProps()
	require.Len(t, props, 1)

	result := props[0].AsMap()
	require.Contains(t, result, "error")
	require.Equal(t, "alice-user-name", result["entity_id"])
}

func TestCreateEntityFromResultV2ExcludesResolutionMetadataFromPolicyClaims(t *testing.T) {
	ers := &ERSV2{logger: logger.CreateTestLogger()}
	result := &types.EntityResult{
		Claims: map[string]interface{}{
			"username":   "alice",
			"department": "engineering",
		},
		Metadata: map[string]interface{}{
			"strategy_name":     "sql_subject",
			"strategy_provider": "directory",
			"provider_type":     "sql",
		},
	}
	strategy := &types.MappingStrategy{
		Name:       "sql_subject",
		EntityType: types.EntityTypeSubject,
	}

	resolved, err := ers.createEntityFromResultV2(t.Context(), result, strategy, "token-1")
	require.NoError(t, err)
	require.Equal(t, entity.Entity_CATEGORY_SUBJECT, resolved.GetCategory())
	require.NotNil(t, resolved.GetClaims())

	var claimsStruct structpb.Struct
	require.NoError(t, resolved.GetClaims().UnmarshalTo(&claimsStruct))
	policyClaims := claimsStruct.AsMap()

	require.Equal(t, "alice", policyClaims["username"])
	require.Equal(t, "engineering", policyClaims["department"])
	require.NotContains(t, policyClaims, "strategy_name")
	require.NotContains(t, policyClaims, "strategy_provider")
	require.NotContains(t, policyClaims, "provider_type")
	require.NotContains(t, policyClaims, "metadata_strategy_name")
	require.NotContains(t, policyClaims, "metadata_strategy_provider")
	require.NotContains(t, policyClaims, "metadata_provider_type")
}

func TestCreateEntityFromResultV2RejectsUnserializableClaims(t *testing.T) {
	ers := &ERSV2{logger: logger.CreateTestLogger()}
	result := &types.EntityResult{
		Claims: map[string]interface{}{
			"username":    "alice",
			"unsupported": make(chan int),
		},
	}
	strategy := &types.MappingStrategy{
		Name:       "sql_subject",
		EntityType: types.EntityTypeSubject,
	}

	resolved, err := ers.createEntityFromResultV2(t.Context(), result, strategy, "token-1")
	require.Error(t, err)
	require.Nil(t, resolved)
	require.ErrorContains(t, err, "failed to normalize resolved claims for entity chain")
}

func TestCreateEntityForTokenChainFailsClosedOnSerializationErrorWithContinue(t *testing.T) {
	ers := &ERSV2{logger: logger.CreateTestLogger()}
	result := &types.EntityResult{
		Claims: map[string]interface{}{
			"username":    "alice",
			"unsupported": make(chan int),
		},
	}
	strategy := &types.MappingStrategy{
		Name:       "bad_subject",
		EntityType: types.EntityTypeSubject,
	}

	resolved, err := ers.createEntityForTokenChain(
		t.Context(),
		result,
		strategy,
		"token-1",
		types.FailureStrategyContinue,
		[]string{"bad_subject"},
	)
	require.Error(t, err)
	require.Nil(t, resolved)
	require.ErrorContains(t, err, "resolved entity serialization failed after successful strategy resolution")
	require.ErrorContains(t, err, "failed to normalize resolved claims for entity chain")

	var outer *types.MultiStrategyError
	require.ErrorAs(t, err, &outer)
	require.Equal(t, types.ErrorTypeMapping, outer.Type)
	require.Equal(t, "token-1", outer.Context["token_id"])
	require.Equal(t, "bad_subject", outer.Context["strategy"])
	require.Equal(t, types.FailureStrategyContinue, outer.Context["failure_strategy"])
	require.Equal(t, []string{"bad_subject"}, outer.Context["attempted_strategies"])

	var inner *types.MultiStrategyError
	require.ErrorAs(t, errors.Unwrap(err), &inner)
	require.Equal(t, types.ErrorTypeMapping, inner.Type)
	require.Equal(t, "token-1", inner.Context["token_id"])
	require.Equal(t, "bad_subject", inner.Context["strategy"])
}

// firstMatchWinsConfig builds a config with two strategies that both match the test token:
// an ENVIRONMENT strategy on "azp" followed by a SUBJECT strategy on "sub".
func firstMatchWinsConfig(failureStrategy string, strategies ...types.MappingStrategy) types.MultiStrategyConfig {
	return types.MultiStrategyConfig{
		FailureStrategy: failureStrategy,
		Providers: map[string]types.ProviderConfig{
			"jwt": {Type: "claims", Connection: map[string]interface{}{}},
		},
		MappingStrategies: strategies,
	}
}

func environmentStrategy() types.MappingStrategy {
	return types.MappingStrategy{
		Name:       "client_environment",
		Provider:   "jwt",
		EntityType: types.EntityTypeEnvironment,
		Conditions: types.StrategyConditions{
			JWTClaims: []types.JWTClaimCondition{{Claim: "azp", Operator: "exists"}},
		},
		OutputMapping: []types.OutputMapping{{SourceClaim: "azp", ClaimName: "client_id"}},
	}
}

func subjectStrategy() types.MappingStrategy {
	return types.MappingStrategy{
		Name:       "user_subject",
		Provider:   "jwt",
		EntityType: types.EntityTypeSubject,
		Conditions: types.StrategyConditions{
			JWTClaims: []types.JWTClaimCondition{{Claim: "sub", Operator: "exists"}},
		},
		OutputMapping: []types.OutputMapping{{SourceClaim: "sub", ClaimName: "username"}},
	}
}

// testTokenJWT is an unsigned-but-well-formed JWT carrying both "azp" and "sub", so every
// strategy in firstMatchWinsConfig matches it.
// Payload: {"sub":"alice","azp":"opentdf-sdk","iat":1600000000,"exp":4102444800}
const testTokenJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiJhbGljZSIsImF6cCI6Im9wZW50ZGYtc2RrIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9." +
	"dGVzdHNpZ25hdHVyZQ"

func chainForTestToken(t *testing.T, config types.MultiStrategyConfig) *entity.EntityChain {
	t.Helper()

	erService, err := NewERSV2(t.Context(), config, logger.CreateTestLogger())
	require.NoError(t, err)

	resp, err := erService.CreateEntityChainsFromTokens(t.Context(), connect.NewRequest(&ersV2.CreateEntityChainsFromTokensRequest{
		Tokens: []*entity.Token{{EphemeralId: "token-1", Jwt: testTokenJWT}},
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetEntityChains(), 1)

	return resp.Msg.GetEntityChains()[0]
}

func claimsOf(t *testing.T, resolved *entity.Entity) map[string]interface{} {
	t.Helper()

	require.NotNil(t, resolved.GetClaims())
	var claimsStruct structpb.Struct
	require.NoError(t, resolved.GetClaims().UnmarshalTo(&claimsStruct))
	return claimsStruct.AsMap()
}

// secondSubjectStrategy is another subject strategy matching the same token, mapping a
// different claim so tests can tell which of the two produced the chain's subject entity.
func secondSubjectStrategy() types.MappingStrategy {
	return types.MappingStrategy{
		Name:       "user_subject_fallback",
		Provider:   "jwt",
		EntityType: types.EntityTypeSubject,
		Conditions: types.StrategyConditions{
			JWTClaims: []types.JWTClaimCondition{{Claim: "azp", Operator: "exists"}},
		},
		OutputMapping: []types.OutputMapping{{SourceClaim: "azp", ClaimName: "username"}},
	}
}

func categoriesOf(chain *entity.EntityChain) []entity.Entity_Category {
	categories := make([]entity.Entity_Category, 0, len(chain.GetEntities()))
	for _, e := range chain.GetEntities() {
		categories = append(categories, e.GetCategory())
	}
	return categories
}

func subjectEntity(t *testing.T, chain *entity.EntityChain) *entity.Entity {
	t.Helper()

	var found *entity.Entity
	for _, e := range chain.GetEntities() {
		if e.GetCategory() == entity.Entity_CATEGORY_SUBJECT {
			require.Nil(t, found, "chain must not carry more than one subject entity")
			found = e
		}
	}
	require.NotNil(t, found, "chain must carry a subject entity")
	return found
}

// TestCreateEntityChainsFromTokens_AtMostOneEntityPerCategory pins the chain contract: a
// token yields at most one ENVIRONMENT and one SUBJECT entity, and within a category the
// first matching strategy wins. Multiple subject entities are what made AND semantics
// unpredictable; a missing subject entity breaks authz, which discards environment entities.
func TestCreateEntityChainsFromTokens_AtMostOneEntityPerCategory(t *testing.T) {
	tests := []struct {
		name               string
		failureStrategy    string
		strategies         []types.MappingStrategy
		expectedCategories []entity.Entity_Category
		expectedUsername   string
	}{
		{
			name:               "competing subject strategies collapse to the first",
			failureStrategy:    types.FailureStrategyContinue,
			strategies:         []types.MappingStrategy{subjectStrategy(), secondSubjectStrategy()},
			expectedCategories: []entity.Entity_Category{entity.Entity_CATEGORY_SUBJECT},
			expectedUsername:   "alice",
		},
		{
			name:               "environment and subject strategies each contribute one entity",
			failureStrategy:    types.FailureStrategyContinue,
			strategies:         []types.MappingStrategy{environmentStrategy(), subjectStrategy()},
			expectedCategories: []entity.Entity_Category{entity.Entity_CATEGORY_ENVIRONMENT, entity.Entity_CATEGORY_SUBJECT},
			expectedUsername:   "alice",
		},
		{
			name:               "chain follows strategy order",
			failureStrategy:    types.FailureStrategyContinue,
			strategies:         []types.MappingStrategy{subjectStrategy(), environmentStrategy()},
			expectedCategories: []entity.Entity_Category{entity.Entity_CATEGORY_SUBJECT, entity.Entity_CATEGORY_ENVIRONMENT},
			expectedUsername:   "alice",
		},
		{
			name:               "a redundant subject strategy after a full chain is skipped",
			failureStrategy:    types.FailureStrategyContinue,
			strategies:         []types.MappingStrategy{environmentStrategy(), subjectStrategy(), secondSubjectStrategy()},
			expectedCategories: []entity.Entity_Category{entity.Entity_CATEGORY_ENVIRONMENT, entity.Entity_CATEGORY_SUBJECT},
			expectedUsername:   "alice",
		},
		{
			name:               "fail-fast produces the same chain shape",
			failureStrategy:    types.FailureStrategyFailFast,
			strategies:         []types.MappingStrategy{environmentStrategy(), subjectStrategy()},
			expectedCategories: []entity.Entity_Category{entity.Entity_CATEGORY_ENVIRONMENT, entity.Entity_CATEGORY_SUBJECT},
			expectedUsername:   "alice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := chainForTestToken(t, firstMatchWinsConfig(tt.failureStrategy, tt.strategies...))

			require.Equal(t, tt.expectedCategories, categoriesOf(chain))
			require.Equal(t, tt.expectedUsername, claimsOf(t, subjectEntity(t, chain))["username"],
				"the first matching subject strategy must own the subject entity")
		})
	}
}

// TestCreateEntityChainsFromTokens_EnvironmentFirstStillResolvesSubject guards the ordering
// regression: authz resolves decisions with skipEnvironmentEntities=true, so a chain built
// from an environment-first config must still carry a subject or every decision errors out.
func TestCreateEntityChainsFromTokens_EnvironmentFirstStillResolvesSubject(t *testing.T) {
	chain := chainForTestToken(t, firstMatchWinsConfig(
		types.FailureStrategyContinue, environmentStrategy(), subjectStrategy(),
	))

	require.Equal(t, "alice", claimsOf(t, subjectEntity(t, chain))["username"])
}

// TestCreateEntityChainsFromTokens_ContinueFallsThroughFailureToNextStrategy shows the one
// thing "continue" does change: a failing strategy hands off to the next matching one.
func TestCreateEntityChainsFromTokens_ContinueFallsThroughFailureToNextStrategy(t *testing.T) {
	failing := environmentStrategy()
	failing.Name = "missing_provider"
	failing.Provider = "not-registered"

	chain := chainForTestToken(t, firstMatchWinsConfig(types.FailureStrategyContinue, failing, subjectStrategy()))

	require.Len(t, chain.GetEntities(), 1)
	require.Equal(t, "alice", claimsOf(t, subjectEntity(t, chain))["username"])
}
