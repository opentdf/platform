package access

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	multistrategyV2 "github.com/opentdf/platform/service/entityresolution/multi-strategy/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
)

// realERSV2Client adapts the in-process multi-strategy ERS v2 handler to the SDK client
// interface the PDP consumes, so these tests exercise the real chain-building code rather
// than a canned response.
type realERSV2Client struct {
	ers          *multistrategyV2.ERSV2
	resolveCalls int
}

func (c *realERSV2Client) CreateEntityChainsFromTokens(ctx context.Context, req *entityresolutionV2.CreateEntityChainsFromTokensRequest) (*entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	resp, err := c.ers.CreateEntityChainsFromTokens(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (c *realERSV2Client) ResolveEntities(ctx context.Context, req *entityresolutionV2.ResolveEntitiesRequest) (*entityresolutionV2.ResolveEntitiesResponse, error) {
	c.resolveCalls++
	resp, err := c.ers.ResolveEntities(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// environmentFirstJWT carries both "azp" and "sub", so both strategies below match it.
// Payload: {"sub":"alice","azp":"opentdf-sdk","iat":1600000000,"exp":4102444800}
const environmentFirstJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiJhbGljZSIsImF6cCI6Im9wZW50ZGYtc2RrIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9." +
	"dGVzdHNpZ25hdHVyZQ"

func multiStrategyPDP(t *testing.T, strategies ...types.MappingStrategy) (*JustInTimePDP, *realERSV2Client) {
	t.Helper()

	ers, err := multistrategyV2.NewERSV2(t.Context(), types.MultiStrategyConfig{
		FailureStrategy: types.FailureStrategyContinue,
		Providers: map[string]types.ProviderConfig{
			"jwt": {Type: "claims", Connection: map[string]interface{}{}},
		},
		MappingStrategies: strategies,
	}, logger.CreateTestLogger())
	require.NoError(t, err)

	client := &realERSV2Client{ers: ers}
	return &JustInTimePDP{
		logger: logger.CreateTestLogger(),
		sdk:    &otdfSDK.SDK{EntityResolutionV2: client},
	}, client
}

func environmentMappingStrategy() types.MappingStrategy {
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

func subjectMappingStrategy() types.MappingStrategy {
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

// TestResolveEntitiesFromTokenResolvesSubjectWhenEnvironmentStrategyIsFirst is the failing
// test that describes the bug.
//
// A token that matches a subject strategy must yield a decision-usable entity
// representation. It does not when an entity_type: environment strategy is configured ahead
// of the subject strategy: first-match-wins chain building stops at the environment strategy,
// the decision flow filters environment entities out (skipEnvironmentEntities=true), and the
// request fails outright instead of deciding on alice.
//
// This test asserts the required outcome, not a mechanism, so any of the plausible fixes
// satisfies it: skipping environment-typed strategies when picking the chain winner, keeping
// the environment entity but continuing to the first subject match, or rejecting the ordering
// at config load.
func TestResolveEntitiesFromTokenResolvesSubjectWhenEnvironmentStrategyIsFirst(t *testing.T) {
	pdp, _ := multiStrategyPDP(t, environmentMappingStrategy(), subjectMappingStrategy())
	token := &entity.Token{EphemeralId: "alice-token", Jwt: environmentFirstJWT}

	reps, err := pdp.resolveEntitiesFromToken(t.Context(), token, true, nil)

	require.NoError(t, err, "a token matching a subject strategy must resolve regardless of strategy order")
	require.Len(t, reps, 1)
	require.Equal(t, "alice", reps[0].GetAdditionalProps()[0].AsMap()["username"])
}

// TestResolveEntitiesFromTokenResolvesSubjectWhenSubjectStrategyIsFirst is the control. Same
// token, same two strategies, opposite order. It passes today, which is what makes strategy
// ordering the variable under test.
func TestResolveEntitiesFromTokenResolvesSubjectWhenSubjectStrategyIsFirst(t *testing.T) {
	pdp, _ := multiStrategyPDP(t, subjectMappingStrategy(), environmentMappingStrategy())
	token := &entity.Token{EphemeralId: "alice-token", Jwt: environmentFirstJWT}

	reps, err := pdp.resolveEntitiesFromToken(t.Context(), token, true, nil)

	require.NoError(t, err)
	require.Len(t, reps, 1)
	require.Equal(t, "alice", reps[0].GetAdditionalProps()[0].AsMap()["username"])
}

// TestResolveEntitiesFromTokenEnvironmentFirstChainIsWellFormedButEmptyAfterFiltering pins the
// mechanism behind the failure above: the chain the ERS builds is valid, and the same token
// resolves when environment entities are not filtered. It is the filtering step in the
// decision flow that leaves nothing to decide on.
func TestResolveEntitiesFromTokenEnvironmentFirstChainIsWellFormedButEmptyAfterFiltering(t *testing.T) {
	pdp, client := multiStrategyPDP(t, environmentMappingStrategy(), subjectMappingStrategy())
	token := &entity.Token{EphemeralId: "alice-token", Jwt: environmentFirstJWT}

	reps, err := pdp.resolveEntitiesFromToken(t.Context(), token, false, nil)
	require.NoError(t, err, "the chain itself is well-formed")
	require.Len(t, reps, 1)
	require.Equal(t, "opentdf-sdk", reps[0].GetAdditionalProps()[0].AsMap()["client_id"],
		"the chain holds only the environment entity, so the subject strategy never ran")

	// And nothing recovers it: the failure is not errResolvedTokenChainRequiresHydration, so
	// resolveEntitiesFromToken's hydration fallback never re-resolves through ERS.
	_, err = pdp.resolveEntitiesFromToken(t.Context(), token, true, nil)
	require.ErrorContains(t, err, "no subject entities to resolve - all were environment entities and skipped")
	require.NotErrorIs(t, err, errResolvedTokenChainRequiresHydration)
	require.Zero(t, client.resolveCalls, "no ERS re-resolution is attempted")
}
