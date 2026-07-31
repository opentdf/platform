package access

import (
	"context"
	"testing"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type recordingERSV2Client struct {
	createResponse  *entityresolutionV2.CreateEntityChainsFromTokensResponse
	resolveResponse *entityresolutionV2.ResolveEntitiesResponse
	createCalls     int
	resolveCalls    int
	createReq       *entityresolutionV2.CreateEntityChainsFromTokensRequest
	resolveReq      *entityresolutionV2.ResolveEntitiesRequest
}

func (c *recordingERSV2Client) CreateEntityChainsFromTokens(_ context.Context, req *entityresolutionV2.CreateEntityChainsFromTokensRequest) (*entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	c.createCalls++
	c.createReq = req
	return c.createResponse, nil
}

func (c *recordingERSV2Client) ResolveEntities(_ context.Context, req *entityresolutionV2.ResolveEntitiesRequest) (*entityresolutionV2.ResolveEntitiesResponse, error) {
	c.resolveCalls++
	c.resolveReq = req
	return c.resolveResponse, nil
}

func TestResolveEntitiesFromTokenDoesNotRehydrateResolvedChain(t *testing.T) {
	claimsAny := claimsAnyForTest(t, map[string]interface{}{"username": "alice", "department": "engineering"})
	client := &recordingERSV2Client{createResponse: &entityresolutionV2.CreateEntityChainsFromTokensResponse{
		EntityChains: []*entity.EntityChain{{Entities: []*entity.Entity{
			{
				EphemeralId: "resolved-alice",
				EntityType:  &entity.Entity_Claims{Claims: claimsAny},
				Category:    entity.Entity_CATEGORY_SUBJECT,
			},
			{
				EphemeralId: "resolved-client",
				EntityType:  &entity.Entity_Claims{Claims: claimsAny},
				Category:    entity.Entity_CATEGORY_ENVIRONMENT,
			},
		}}},
	}}
	pdp := testJITPDP(client)
	resources := []*authzV2.Resource{{EphemeralId: "resource-1"}}
	token := &entity.Token{EphemeralId: "alice-token", Jwt: "token"}

	reps, err := pdp.resolveEntitiesFromToken(t.Context(), token, true, resources)
	require.NoError(t, err)
	require.Len(t, reps, 1)
	require.Equal(t, 1, client.createCalls)
	require.Zero(t, client.resolveCalls)
	require.NotNil(t, client.createReq)
	require.Len(t, client.createReq.GetTokens(), 1)
	require.Equal(t, token.GetEphemeralId(), client.createReq.GetTokens()[0].GetEphemeralId())
	require.Equal(t, token.GetJwt(), client.createReq.GetTokens()[0].GetJwt())
	require.Len(t, client.createReq.GetResources(), 1)
	require.Equal(t, "resource-1", client.createReq.GetResources()[0].GetEphemeralId())
	require.Len(t, reps[0].GetAdditionalProps(), 1)
	require.Equal(t, "alice", reps[0].GetAdditionalProps()[0].AsMap()["username"])
	require.Equal(t, "engineering", reps[0].GetAdditionalProps()[0].AsMap()["department"])
}

func TestResolveEntitiesFromTokenFallsBackToHydrationForTypedChain(t *testing.T) {
	client := &recordingERSV2Client{
		createResponse: &entityresolutionV2.CreateEntityChainsFromTokensResponse{EntityChains: []*entity.EntityChain{{
			Entities: []*entity.Entity{
				{
					EphemeralId: "typed-user",
					EntityType:  &entity.Entity_UserName{UserName: "alice"},
					Category:    entity.Entity_CATEGORY_SUBJECT,
				},
				{
					EphemeralId: "typed-env",
					EntityType:  &entity.Entity_ClientId{ClientId: "client-1"},
					Category:    entity.Entity_CATEGORY_ENVIRONMENT,
				},
			},
		}}},
		resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
			EntityRepresentations: []*entityresolutionV2.EntityRepresentation{{OriginalId: "typed-user"}},
		},
	}
	pdp := testJITPDP(client)
	resources := []*authzV2.Resource{{EphemeralId: "resource-1"}}
	token := &entity.Token{EphemeralId: "token", Jwt: "token"}

	reps, err := pdp.resolveEntitiesFromToken(t.Context(), token, true, resources)
	require.NoError(t, err)
	require.Len(t, reps, 1)
	require.Equal(t, 1, client.createCalls)
	require.Equal(t, 1, client.resolveCalls)
	require.NotNil(t, client.createReq)
	require.Len(t, client.createReq.GetTokens(), 1)
	require.Equal(t, token.GetEphemeralId(), client.createReq.GetTokens()[0].GetEphemeralId())
	require.Equal(t, token.GetJwt(), client.createReq.GetTokens()[0].GetJwt())
	require.Len(t, client.createReq.GetResources(), 1)
	require.Equal(t, "resource-1", client.createReq.GetResources()[0].GetEphemeralId())
	require.NotNil(t, client.resolveReq)
	require.Len(t, client.resolveReq.GetEntities(), 1)
	require.Equal(t, "typed-user", client.resolveReq.GetEntities()[0].GetEphemeralId())
	require.Equal(t, entity.Entity_CATEGORY_SUBJECT, client.resolveReq.GetEntities()[0].GetCategory())
	require.IsType(t, &entity.Entity_UserName{}, client.resolveReq.GetEntities()[0].GetEntityType())
}

func TestResolveEntitiesFromEntityChainStillUsesERS(t *testing.T) {
	client := &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolutionV2.EntityRepresentation{{OriginalId: "alice"}},
	}}
	pdp := testJITPDP(client)
	chain := &entity.EntityChain{Entities: []*entity.Entity{{
		EphemeralId: "alice",
		EntityType:  &entity.Entity_UserName{UserName: "alice"},
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}}}

	_, err := pdp.resolveEntitiesFromEntityChain(t.Context(), chain, true)
	require.NoError(t, err)
	require.Equal(t, 1, client.resolveCalls)
	require.Zero(t, client.createCalls)
	require.NotNil(t, client.resolveReq)
	require.Len(t, client.resolveReq.GetEntities(), 1)
	require.Equal(t, "alice", client.resolveReq.GetEntities()[0].GetEphemeralId())
}

func TestEntityRepresentationsFromResolvedChain(t *testing.T) {
	claimsAny := claimsAnyForTest(t, map[string]interface{}{"username": "alice", "department": "engineering"})
	chain := &entity.EntityChain{
		EphemeralId: "token-alice",
		Entities: []*entity.Entity{
			{
				EphemeralId: "user-strategy-token-alice",
				EntityType:  &entity.Entity_Claims{Claims: claimsAny},
				Category:    entity.Entity_CATEGORY_SUBJECT,
			},
			{
				EphemeralId: "client-strategy-token-alice",
				EntityType:  &entity.Entity_Claims{Claims: claimsAny},
				Category:    entity.Entity_CATEGORY_ENVIRONMENT,
			},
		},
	}

	reps, err := entityRepresentationsFromResolvedChain(chain, true)
	require.NoError(t, err)
	require.Len(t, reps, 1)

	asMap := reps[0].GetAdditionalProps()[0].AsMap()
	require.Equal(t, "alice", asMap["username"])
	require.Equal(t, "engineering", asMap["department"])
}

func TestEntityRepresentationsFromResolvedChainRejectsTypedEntity(t *testing.T) {
	chain := &entity.EntityChain{Entities: []*entity.Entity{{
		EphemeralId: "typed-user",
		EntityType:  &entity.Entity_UserName{UserName: "alice"},
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}}}

	_, err := entityRepresentationsFromResolvedChain(chain, false)
	require.Error(t, err)
}

func testJITPDP(client *recordingERSV2Client) *JustInTimePDP {
	return &JustInTimePDP{
		logger: logger.CreateTestLogger(),
		sdk:    &otdfSDK.SDK{EntityResolutionV2: client},
	}
}

func claimsAnyForTest(t *testing.T, claims map[string]interface{}) *anypb.Any {
	t.Helper()
	claimsStruct, err := structpb.NewStruct(claims)
	require.NoError(t, err)
	claimsAny, err := anypb.New(claimsStruct)
	require.NoError(t, err)
	return claimsAny
}
