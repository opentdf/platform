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
type ResolvedTokenChainExpectation struct {
	Token    *entity.Token
	Entities []ResolvedTokenChainEntityExpectation
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

	t.Run(adapter.GetScopeName()+"_EnvironmentThenSubjectPreservesMultiEntityMappedContext", func(t *testing.T) {
		suite.assertResolvedTokenChains(t, implementation, expectations[:1])
	})

	reversedImplementation, err := adapter.CreateERSServiceWithReversedStrategies(ctx)
	require.NoError(t, err)
	t.Run(adapter.GetScopeName()+"_SubjectThenEnvironmentPreservesMultiEntityMappedContext", func(t *testing.T) {
		suite.assertResolvedTokenChains(t, reversedImplementation, expectations[:1])
	})

	if len(expectations) > 1 {
		t.Run(adapter.GetScopeName()+"_MultipleTokensPreserveMultiEntityMappedContext", func(t *testing.T) {
			suite.assertResolvedTokenChains(t, implementation, expectations)
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
		require.True(t, ok, "unexpected chain %q", chain.GetEphemeralId())
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
}

func containsExpectedClaims(actual, expected map[string]interface{}) bool {
	for key, expectedValue := range expected {
		if actualValue, ok := actual[key]; !ok || !reflect.DeepEqual(actualValue, expectedValue) {
			return false
		}
	}
	return true
}
