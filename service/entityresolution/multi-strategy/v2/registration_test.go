package multistrategy

import (
	"errors"
	"strings"
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

// TestCreateEntityFromResultV2MarksChainEntitiesPreResolved pins the producer half of the
// pre-resolved contract. Without the marker, ResolveEntities cannot tell a finished strategy
// payload apart from caller-supplied claims and re-runs every strategy against it.
func TestCreateEntityFromResultV2MarksChainEntitiesPreResolved(t *testing.T) {
	ers := &ERSV2{logger: logger.CreateTestLogger()}
	result := &types.EntityResult{
		Claims: map[string]interface{}{"username": "alice"},
	}
	strategy := &types.MappingStrategy{
		Name:       "sql_subject",
		EntityType: types.EntityTypeSubject,
	}

	resolved, err := ers.createEntityFromResultV2(t.Context(), result, strategy, "token-1")
	require.NoError(t, err)
	require.True(t,
		strings.HasPrefix(resolved.GetEphemeralId(), preResolvedEntityIDPrefix),
		"chain entity %q must be marked pre-resolved", resolved.GetEphemeralId())
}

// preResolvedTestERS builds an ERS whose only strategy selects on a raw JWT claim ("sub") that a
// resolved payload no longer carries. Any attempt to re-resolve a pre-resolved entity therefore
// fails strategy selection and surfaces as an error representation, which makes "did this
// short-circuit?" directly observable.
func preResolvedTestERS(t *testing.T) *ERSV2 {
	t.Helper()
	ers, err := NewERSV2(t.Context(), types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {Type: "claims", Connection: map[string]interface{}{}},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "jwt_strategy",
				Provider:   "jwt",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{{Claim: "sub", Operator: "exists"}},
				},
				OutputMapping: []types.OutputMapping{{SourceClaim: "sub", ClaimName: "username"}},
			},
		},
	}, logger.CreateTestLogger())
	require.NoError(t, err)
	return ers
}

func resolvedClaimsEntity(t *testing.T, ephemeralID string) *entity.Entity {
	t.Helper()
	claimsStruct, err := structpb.NewStruct(map[string]interface{}{
		"username":   "alice",
		"department": "engineering",
	})
	require.NoError(t, err)
	claimsAny, err := anypb.New(claimsStruct)
	require.NoError(t, err)
	return &entity.Entity{
		EphemeralId: ephemeralID,
		EntityType:  &entity.Entity_Claims{Claims: claimsAny},
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}
}

// TestResolveEntitiesReturnsPreResolvedEntityWithoutReResolving is the consumer half. The token
// flow calls CreateEntityChainsFromTokens then ResolveEntities, so without this short-circuit the
// authz round-trip re-runs strategy selection against resolved rather than raw claims and repeats
// every backend query. Keeping the optimization here - rather than in the PDP - is what lets authz
// always go through ERS, which is what preserves ERS-projected fields like DirectEntitlements.
func TestResolveEntitiesReturnsPreResolvedEntityWithoutReResolving(t *testing.T) {
	ers := preResolvedTestERS(t)
	entityID := preResolvedEntityIDPrefix + "jwt_strategy-token-1-claims-alice"

	resp, err := ers.ResolveEntities(t.Context(), connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{resolvedClaimsEntity(t, entityID)},
	}))
	require.NoError(t, err)

	reps := resp.Msg.GetEntityRepresentations()
	require.Len(t, reps, 1)
	require.Equal(t, entityID, reps[0].GetOriginalId())
	require.Len(t, reps[0].GetAdditionalProps(), 1)

	fields := reps[0].GetAdditionalProps()[0].AsMap()
	require.Equal(t, "alice", fields["username"])
	require.Equal(t, "engineering", fields["department"])
	require.NotContains(t, fields, "error", "pre-resolved entity must not be re-resolved")
}

// TestResolveEntitiesStillResolvesUnmarkedClaimsEntity proves the marker is what gates the
// short-circuit, not merely the presence of claims. Caller-supplied claims entities - the
// entity-chain decision path - must still go through full strategy resolution.
func TestResolveEntitiesStillResolvesUnmarkedClaimsEntity(t *testing.T) {
	ers := preResolvedTestERS(t)

	resp, err := ers.ResolveEntities(t.Context(), connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{resolvedClaimsEntity(t, "caller-supplied-entity")},
	}))
	require.NoError(t, err)

	reps := resp.Msg.GetEntityRepresentations()
	require.Len(t, reps, 1)
	require.Equal(t, "caller-supplied-entity", reps[0].GetOriginalId())
	require.Len(t, reps[0].GetAdditionalProps(), 1)

	// The strategy selects on "sub", which these claims lack, so resolution runs and fails.
	// The point of the assertion is that resolution ran at all.
	require.Contains(t, reps[0].GetAdditionalProps()[0].AsMap(), "error")
}
