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

// TestResolveEntitiesFromTokenAlwaysCallsResolveEntities pins the contract that the PDP never
// builds an EntityRepresentation itself. A claims-bearing chain looks fully resolved, but only
// ERS can project fields such as DirectEntitlements onto the representation, so the token path
// must round-trip regardless of what the chain carries. Any no-rehydrate optimization belongs
// inside the ERS that produced the chain.
func TestResolveEntitiesFromTokenAlwaysCallsResolveEntities(t *testing.T) {
	claimsAny := claimsAnyForTest(t, map[string]interface{}{"username": "alice", "department": "engineering"})
	client := &recordingERSV2Client{
		createResponse: &entityresolutionV2.CreateEntityChainsFromTokensResponse{
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
		},
		resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
			EntityRepresentations: []*entityresolutionV2.EntityRepresentation{{
				OriginalId: "resolved-alice",
				AdditionalProps: []*structpb.Struct{mustStruct(t, map[string]interface{}{
					"username":   "alice",
					"department": "engineering",
				})},
			}},
		},
	}
	pdp := testJITPDP(client)
	resources := []*authzV2.Resource{{EphemeralId: "resource-1"}}
	token := &entity.Token{EphemeralId: "alice-token", Jwt: "token"}

	reps, err := pdp.resolveEntitiesFromToken(t.Context(), token, true, resources)
	require.NoError(t, err)
	require.Len(t, reps, 1)
	require.Equal(t, 1, client.createCalls)
	require.Equal(t, 1, client.resolveCalls, "PDP must not build EntityRepresentation itself")
	require.NotNil(t, client.createReq)
	require.Len(t, client.createReq.GetTokens(), 1)
	require.Equal(t, token.GetEphemeralId(), client.createReq.GetTokens()[0].GetEphemeralId())
	require.Equal(t, token.GetJwt(), client.createReq.GetTokens()[0].GetJwt())
	require.Len(t, client.createReq.GetResources(), 1)
	require.Equal(t, "resource-1", client.createReq.GetResources()[0].GetEphemeralId())

	// Environment entities are still filtered out before ERS sees the chain.
	require.NotNil(t, client.resolveReq)
	require.Len(t, client.resolveReq.GetEntities(), 1)
	require.Equal(t, "resolved-alice", client.resolveReq.GetEntities()[0].GetEphemeralId())

	require.Len(t, reps[0].GetAdditionalProps(), 1)
	require.Equal(t, "alice", reps[0].GetAdditionalProps()[0].AsMap()["username"])
	require.Equal(t, "engineering", reps[0].GetAdditionalProps()[0].AsMap()["department"])
}

func TestResolveEntitiesFromTokenCallsResolveEntitiesForTypedChain(t *testing.T) {
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

func testJITPDP(client *recordingERSV2Client) *JustInTimePDP {
	return &JustInTimePDP{
		logger: logger.CreateTestLogger(),
		sdk:    &otdfSDK.SDK{EntityResolutionV2: client},
	}
}

func claimsAnyForTest(t *testing.T, claims map[string]interface{}) *anypb.Any {
	t.Helper()
	claimsStruct := mustStruct(t, claims)
	claimsAny, err := anypb.New(claimsStruct)
	require.NoError(t, err)
	return claimsAny
}

func mustStruct(t *testing.T, m map[string]interface{}) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return s
}

// TestResolveEntitiesFromTokenPreservesDirectEntitlements is the end-to-end regression for the
// no-rehydrate shortcut silently dropping direct entitlements. Only ERS can project the inline
// `direct_entitlements` claim onto EntityRepresentation.DirectEntitlements; building the
// representation in the PDP leaves the field empty and every direct-entitlement decision denies.
func TestResolveEntitiesFromTokenPreservesDirectEntitlements(t *testing.T) {
	directEntitlements := []*entityresolutionV2.DirectEntitlement{{
		AttributeValueFqn: "https://example.com/attr/workspace/value/sdk-test",
		Actions:           []string{"read", "view"},
	}}
	claimsAny := claimsAnyForTest(t, map[string]interface{}{
		"username": "alice",
		"direct_entitlements": []interface{}{
			map[string]interface{}{
				"attribute_value_fqn": "https://example.com/attr/workspace/value/sdk-test",
				"actions":             []interface{}{"read", "view"},
			},
		},
	})
	client := &recordingERSV2Client{
		createResponse: &entityresolutionV2.CreateEntityChainsFromTokensResponse{
			EntityChains: []*entity.EntityChain{{Entities: []*entity.Entity{{
				EphemeralId: "jwtentity-claims",
				EntityType:  &entity.Entity_Claims{Claims: claimsAny},
				Category:    entity.Entity_CATEGORY_SUBJECT,
			}}}},
		},
		resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
			EntityRepresentations: []*entityresolutionV2.EntityRepresentation{{
				OriginalId:         "jwtentity-claims",
				DirectEntitlements: directEntitlements,
			}},
		},
	}
	pdp := testJITPDP(client)

	reps, err := pdp.resolveEntitiesFromToken(t.Context(), &entity.Token{EphemeralId: "alice-token", Jwt: "token"}, true, nil)
	require.NoError(t, err)
	require.Len(t, reps, 1)

	// Must defer to ERS so the claim is projected onto the representation.
	require.Equal(t, 1, client.resolveCalls, "direct entitlements require ERS hydration")
	require.Len(t, reps[0].GetDirectEntitlements(), 1, "direct entitlements must survive token resolution")
	require.Equal(t, "https://example.com/attr/workspace/value/sdk-test", reps[0].GetDirectEntitlements()[0].GetAttributeValueFqn())
	require.ElementsMatch(t, []string{"read", "view"}, reps[0].GetDirectEntitlements()[0].GetActions())
}
