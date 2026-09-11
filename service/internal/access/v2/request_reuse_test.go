package access

import (
	"fmt"
	"testing"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRequestReuseCachesPolicySetsAndStaysRequestScoped(t *testing.T) {
	const def = "https://example.com/attr/department"
	const fqn = def + "/value/engineering"
	client := decisionAttrFake(def, fqn, "abc")
	original := &JustInTimePDP{logger: logger.CreateTestLogger(), sdk: &otdfSDK.SDK{Attributes: client}}
	scoped := original.WithRequestReuse()
	first, err := scoped.buildInnerPDP(t.Context(), []string{fqn})
	require.NoError(t, err)
	second, err := scoped.buildInnerPDP(t.Context(), []string{fqn, fqn})
	require.NoError(t, err)
	require.Same(t, first, second)
	require.Len(t, client.requests, 1)
	fresh := original.WithRequestReuse()
	third, err := fresh.buildInnerPDP(t.Context(), []string{fqn})
	require.NoError(t, err)
	require.NotSame(t, first, third)
	require.Len(t, client.requests, 2)
	for i := 0; i < maxRequestPolicyCacheEntries+1; i++ {
		_, err := scoped.buildInnerPDP(t.Context(), []string{fmt.Sprintf("%s/value/%d", def, i)})
		require.NoError(t, err)
	}
	require.Len(t, scoped.reuse.policies, maxRequestPolicyCacheEntries)
}

func TestRequestReuseIncludesTokenResourcesAndEnvironmentMode(t *testing.T) {
	client := &recordingERSV2Client{createResponse: &entityresolutionV2.CreateEntityChainsFromTokensResponse{
		EntityChains: []*entity.EntityChain{{Entities: []*entity.Entity{{EphemeralId: "subject", Category: entity.Entity_CATEGORY_SUBJECT, EntityType: &entity.Entity_Claims{Claims: claimsAnyForTest(t, map[string]interface{}{"name": "alice"})}}}}},
	}}
	scoped := testJITPDP(client).WithRequestReuse()
	token := &entity.Token{Jwt: "token", EphemeralId: "token-id"}
	resources := attrValueResource("https://example.com/attr/a/value/one")
	_, err := scoped.resolveEntitiesFromToken(t.Context(), token, true, resources)
	require.NoError(t, err)
	_, err = scoped.resolveEntitiesFromToken(t.Context(), proto.CloneOf(token), true, []*authzV2.Resource{proto.CloneOf(resources[0])})
	require.NoError(t, err)
	require.Equal(t, 1, client.createCalls)
	_, err = scoped.resolveEntitiesFromToken(t.Context(), token, true, attrValueResource("https://example.com/attr/a/value/two"))
	require.NoError(t, err)
	require.Equal(t, 2, client.createCalls)
	_, err = scoped.resolveEntitiesFromToken(t.Context(), token, false, resources)
	require.NoError(t, err)
	require.Equal(t, 3, client.createCalls)
	_, err = scoped.resolveEntitiesFromToken(t.Context(), &entity.Token{Jwt: "different", EphemeralId: "token-id"}, true, resources)
	require.NoError(t, err)
	require.Equal(t, 4, client.createCalls)
}

func TestRequestReuseResolvesIdenticalEntityChainOnce(t *testing.T) {
	client := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID("abc")}}}
	scoped := testJITPDP(client).WithRequestReuse()
	chain := entityChainIdentifier().GetEntityChain()
	for range 3 {
		_, err := scoped.resolveEntitiesFromEntityChain(t.Context(), chain, true)
		require.NoError(t, err)
	}
	require.Equal(t, 1, client.resolveCalls)
}
