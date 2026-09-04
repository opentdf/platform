package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/entityresolution/v2/entityresolutionv2connect"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	multistrategyV2 "github.com/opentdf/platform/service/entityresolution/multi-strategy/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
)

// environmentFirstJWT carries both "azp" and "sub", so both strategies below match it.
// Payload: {"sub":"alice","azp":"opentdf-sdk","iat":1600000000,"exp":4102444800}
const environmentFirstJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiJhbGljZSIsImF6cCI6Im9wZW50ZGYtc2RrIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9." +
	"dGVzdHNpZ25hdHVyZQ"

// procedureCounter tallies the RPCs the PDP actually issues, so tests can assert which
// procedures were reached without standing in for the client.
type procedureCounter struct {
	calls map[string]int
}

func (p *procedureCounter) interceptor() connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			p.calls[req.Spec().Procedure]++
			return next(ctx, req)
		}
	})
}

// multiStrategyPDP wires a JustInTimePDP to a multi-strategy ERS over the real transport: the
// generated Connect handler serves the real ERSV2 implementation, and the PDP reaches it
// through the same sdkconnect client wrapper the platform builds in sdk.New. Nothing here
// stands in for production code except the strategy configuration.
func multiStrategyPDP(t *testing.T, strategies ...types.MappingStrategy) (*JustInTimePDP, *procedureCounter) {
	t.Helper()

	ers, err := multistrategyV2.NewERSV2(t.Context(), types.MultiStrategyConfig{
		FailureStrategy: types.FailureStrategyContinue,
		Providers: map[string]types.ProviderConfig{
			"jwt": {Type: "claims", Connection: map[string]interface{}{}},
		},
		MappingStrategies: strategies,
	}, logger.CreateTestLogger())
	require.NoError(t, err)

	counter := &procedureCounter{calls: make(map[string]int)}
	mux := http.NewServeMux()
	mux.Handle(entityresolutionv2connect.NewEntityResolutionServiceHandler(ers, connect.WithInterceptors(counter.interceptor())))

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &JustInTimePDP{
		logger: logger.CreateTestLogger(),
		sdk: &otdfSDK.SDK{
			EntityResolutionV2: sdkconnect.NewEntityResolutionServiceClientV2ConnectWrapper(server.Client(), server.URL),
		},
	}, counter
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
	pdp, counter := multiStrategyPDP(t, environmentMappingStrategy(), subjectMappingStrategy())
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
	require.Zero(t, counter.calls[entityresolutionv2connect.EntityResolutionServiceResolveEntitiesProcedure],
		"no ERS re-resolution is attempted")
	require.Equal(t, 2, counter.calls[entityresolutionv2connect.EntityResolutionServiceCreateEntityChainsFromTokensProcedure])
}
