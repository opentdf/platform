package internal

import (
	"context"
	"reflect"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

const resolvedTokenChainCleanupTimeout = 30 * time.Second

// ResolvedTokenChainEntityExpectation describes one expected entity in a resolved chain.
type ResolvedTokenChainEntityExpectation struct {
	ExpectedClaims map[string]interface{}
	Category       entity.Entity_Category
}

// ResolvedTokenChainExpectation describes the final mapped context expected for one token.
// Entities are listed in mapping-strategy order; because chain resolution is first-match-wins
// the suite only ever expects one of them in a given chain.
type ResolvedTokenChainExpectation struct {
	Token    *entity.Token
	Entities []ResolvedTokenChainEntityExpectation
}

// firstMatch narrows the expectation to the entity produced by the first matching strategy.
func (e ResolvedTokenChainExpectation) firstMatch() ResolvedTokenChainExpectation {
	e.Entities = e.Entities[:1]
	return e
}

// lastMatch narrows the expectation to the entity produced by the last configured strategy,
// which becomes the first match once the strategy list is reversed.
func (e ResolvedTokenChainExpectation) lastMatch() ResolvedTokenChainExpectation {
	e.Entities = e.Entities[len(e.Entities)-1:]
	return e
}

func narrowExpectations(
	expectations []ResolvedTokenChainExpectation,
	narrow func(ResolvedTokenChainExpectation) ResolvedTokenChainExpectation,
) []ResolvedTokenChainExpectation {
	narrowed := make([]ResolvedTokenChainExpectation, 0, len(expectations))
	for _, expectation := range expectations {
		narrowed = append(narrowed, narrow(expectation))
	}
	return narrowed
}

// ResolvedTokenChainAdapter enrolls an ERS/provider configuration in the shared
// token-chain contract. Implementations provide setup and fixtures; the suite owns behavior.
type ResolvedTokenChainAdapter interface {
	ERSTestAdapter
	CreateERSServiceWithReversedStrategies(context.Context) (ERSImplementation, error)
	ResolvedTokenChainExpectations(*ContractTestDataSet) []ResolvedTokenChainExpectation
}

// ResolvedTokenChainContractSuite validates provider-independent token-chain behavior.
type ResolvedTokenChainContractSuite struct{}

func NewResolvedTokenChainContractSuite() *ResolvedTokenChainContractSuite {
	return &ResolvedTokenChainContractSuite{}
}

func (suite *ResolvedTokenChainContractSuite) RunWithAdapter(t *testing.T, adapter ResolvedTokenChainAdapter) {
	t.Helper()
	ctx := t.Context()
	dataSet := NewContractTestDataSet()

	require.NoError(t, adapter.SetupTestData(ctx, dataSet))
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), resolvedTokenChainCleanupTimeout)
		defer cancel()
		require.NoError(t, adapter.TeardownTestData(cleanupCtx))
	})

	implementation, err := adapter.CreateERSService(ctx)
	require.NoError(t, err)

	expectations := adapter.ResolvedTokenChainExpectations(dataSet)
	require.NotEmpty(t, expectations)

	// Chain resolution is first-match-wins, so the environment strategy (configured first)
	// is the only one that runs and the resolved chain carries just its mapped context.
	t.Run(adapter.GetScopeName()+"_EnvironmentThenSubjectPreservesFirstMatchMappedContext", func(t *testing.T) {
		suite.assertResolvedTokenChains(t, implementation, narrowExpectations(expectations[:1], ResolvedTokenChainExpectation.firstMatch))
	})

	// Reversing the strategy list makes the subject strategy the first match, which must be
	// the only entity in the chain. This is what proves ordering — not failure strategy —
	// decides which strategy resolves the token.
	reversedImplementation, err := adapter.CreateERSServiceWithReversedStrategies(ctx)
	require.NoError(t, err)
	t.Run(adapter.GetScopeName()+"_SubjectThenEnvironmentPreservesFirstMatchMappedContext", func(t *testing.T) {
		suite.assertResolvedTokenChains(t, reversedImplementation, narrowExpectations(expectations[:1], ResolvedTokenChainExpectation.lastMatch))
	})

	if len(expectations) > 1 {
		t.Run(adapter.GetScopeName()+"_MultipleTokensPreserveFirstMatchMappedContext", func(t *testing.T) {
			suite.assertResolvedTokenChains(t, implementation, narrowExpectations(expectations, ResolvedTokenChainExpectation.firstMatch))
		})
	}

	t.Run(adapter.GetScopeName()+"_MixedValidInvalidTokenBatchFailsClosed", func(t *testing.T) {
		resp, err := implementation.CreateEntityChainsFromTokens(t.Context(), connect.NewRequest(&entityresolutionV2.CreateEntityChainsFromTokensRequest{
			Tokens: []*entity.Token{expectations[0].Token, {EphemeralId: "invalid-token", Jwt: "not-a-jwt"}},
		}))
		require.Error(t, err)
		require.Nil(t, resp, "failed batch must not return partial chains")
	})
}

func (suite *ResolvedTokenChainContractSuite) assertResolvedTokenChains(
	t *testing.T,
	implementation ERSImplementation,
	expectations []ResolvedTokenChainExpectation,
) {
	t.Helper()

	tokens := make([]*entity.Token, 0, len(expectations))
	byTokenID := make(map[string]ResolvedTokenChainExpectation, len(expectations))
	for _, expectation := range expectations {
		tokens = append(tokens, expectation.Token)
		byTokenID[expectation.Token.GetEphemeralId()] = expectation
	}

	resp, err := implementation.CreateEntityChainsFromTokens(t.Context(), connect.NewRequest(&entityresolutionV2.CreateEntityChainsFromTokensRequest{
		Tokens: tokens,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetEntityChains(), len(expectations))

	for _, chain := range resp.Msg.GetEntityChains() {
		expectation, ok := byTokenID[chain.GetEphemeralId()]
		require.True(t, ok, "unexpected or duplicate chain %q", chain.GetEphemeralId())
		delete(byTokenID, chain.GetEphemeralId())
		require.Len(t, chain.GetEntities(), len(expectation.Entities))

		for _, expectedEntity := range expectation.Entities {
			matched := false
			for _, chained := range chain.GetEntities() {
				if chained.GetCategory() != expectedEntity.Category {
					continue
				}
				claims := chained.GetClaims()
				require.NotNil(t, claims, "resolved chain entity must carry mapped claims")

				var claimsStruct structpb.Struct
				require.NoError(t, claims.UnmarshalTo(&claimsStruct))
				if containsExpectedClaims(claimsStruct.AsMap(), expectedEntity.ExpectedClaims) {
					matched = true
					break
				}
			}
			require.True(t, matched, "chain %q did not contain category %s with mapped claims %v", chain.GetEphemeralId(), expectedEntity.Category, expectedEntity.ExpectedClaims)
		}
	}
	require.Empty(t, byTokenID, "response omitted one or more requested token chains")
}

func containsExpectedClaims(actual, expected map[string]interface{}) bool {
	for key, expectedValue := range expected {
		if actualValue, ok := actual[key]; !ok || !reflect.DeepEqual(actualValue, expectedValue) {
			return false
		}
	}
	return true
}
