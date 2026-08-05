package access

import (
	"context"
	"errors"
	"testing"

	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type typedChainERSClient struct {
	createCalls  int
	resolveCalls int
}

func (c *typedChainERSClient) CreateEntityChainsFromTokens(_ context.Context, _ *entityresolutionV2.CreateEntityChainsFromTokensRequest) (*entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	c.createCalls++
	return &entityresolutionV2.CreateEntityChainsFromTokensResponse{EntityChains: []*entity.EntityChain{{
		Entities: []*entity.Entity{{
			EphemeralId: "typed-user",
			EntityType:  &entity.Entity_UserName{UserName: "alice"},
			Category:    entity.Entity_CATEGORY_SUBJECT,
		}},
	}}}, nil
}

func (c *typedChainERSClient) ResolveEntities(_ context.Context, _ *entityresolutionV2.ResolveEntitiesRequest) (*entityresolutionV2.ResolveEntitiesResponse, error) {
	c.resolveCalls++
	return &entityresolutionV2.ResolveEntitiesResponse{EntityRepresentations: []*entityresolutionV2.EntityRepresentation{{OriginalId: "typed-user"}}}, nil
}

type claimsChainERSClient struct {
	createCalls  int
	resolveCalls int
	claims       *anypb.Any
}

func (c *claimsChainERSClient) CreateEntityChainsFromTokens(_ context.Context, _ *entityresolutionV2.CreateEntityChainsFromTokensRequest) (*entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	c.createCalls++
	return &entityresolutionV2.CreateEntityChainsFromTokensResponse{EntityChains: []*entity.EntityChain{{
		Entities: []*entity.Entity{{
			EphemeralId: "claims-user",
			EntityType:  &entity.Entity_Claims{Claims: c.claims},
			Category:    entity.Entity_CATEGORY_SUBJECT,
		}},
	}}}, nil
}

func (c *claimsChainERSClient) ResolveEntities(_ context.Context, _ *entityresolutionV2.ResolveEntitiesRequest) (*entityresolutionV2.ResolveEntitiesResponse, error) {
	c.resolveCalls++
	return nil, errors.New("unexpected ResolveEntities call")
}

func TestResolveEntitiesFromTokenUsesResolvedClaimsWithoutHydration(t *testing.T) {
	claimsStruct, err := structpb.NewStruct(map[string]interface{}{
		"username":   "alice",
		"department": "engineering",
	})
	require.NoError(t, err)
	claimsAny, err := anypb.New(claimsStruct)
	require.NoError(t, err)

	client := &claimsChainERSClient{claims: claimsAny}
	pdp := &JustInTimePDP{
		logger: logger.CreateTestLogger(),
		sdk:    &otdfSDK.SDK{EntityResolutionV2: client},
	}

	reps, err := pdp.resolveEntitiesFromToken(t.Context(), &entity.Token{EphemeralId: "token", Jwt: "token"}, true, nil)
	require.NoError(t, err)
	require.Len(t, reps, 1)
	require.Equal(t, 1, client.createCalls)
	require.Zero(t, client.resolveCalls)
	require.Len(t, reps[0].GetAdditionalProps(), 1)
	require.Equal(t, "alice", reps[0].GetAdditionalProps()[0].AsMap()["username"])
	require.Equal(t, "engineering", reps[0].GetAdditionalProps()[0].AsMap()["department"])
}

func TestResolveEntitiesFromTokenFallsBackToHydrationForTypedChain(t *testing.T) {
	client := &typedChainERSClient{}
	pdp := &JustInTimePDP{
		logger: logger.CreateTestLogger(),
		sdk:    &otdfSDK.SDK{EntityResolutionV2: client},
	}

	reps, err := pdp.resolveEntitiesFromToken(t.Context(), &entity.Token{EphemeralId: "token", Jwt: "token"}, true, nil)
	if err != nil {
		t.Fatalf("resolveEntitiesFromToken() error = %v", err)
	}
	if len(reps) != 1 {
		t.Fatalf("expected 1 representation, got %d", len(reps))
	}
	if client.createCalls != 1 {
		t.Fatalf("expected 1 CreateEntityChainsFromTokens call, got %d", client.createCalls)
	}
	if client.resolveCalls != 1 {
		t.Fatalf("expected 1 fallback ResolveEntities call, got %d", client.resolveCalls)
	}
}

func TestEntityRepresentationsFromResolvedChain(t *testing.T) {
	claimsStruct, err := structpb.NewStruct(map[string]interface{}{
		"username":   "alice",
		"department": "engineering",
	})
	if err != nil {
		t.Fatalf("structpb.NewStruct() error = %v", err)
	}

	claimsAny, err := anypb.New(claimsStruct)
	if err != nil {
		t.Fatalf("anypb.New() error = %v", err)
	}

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
	if err != nil {
		t.Fatalf("entityRepresentationsFromResolvedChain() error = %v", err)
	}

	if got := len(reps); got != 1 {
		t.Fatalf("expected 1 subject representation after skipping environment entities, got %d", got)
	}

	props := reps[0].GetAdditionalProps()
	if len(props) != 1 {
		t.Fatalf("expected 1 additional props entry, got %d", len(props))
	}

	asMap := props[0].AsMap()
	if got := asMap["username"]; got != "alice" {
		t.Fatalf("expected username alice, got %v", got)
	}
	if got := asMap["department"]; got != "engineering" {
		t.Fatalf("expected department engineering, got %v", got)
	}
}

func TestEntityRepresentationsFromResolvedChainRejectsTypedEntity(t *testing.T) {
	chain := &entity.EntityChain{
		Entities: []*entity.Entity{{
			EphemeralId: "typed-user",
			EntityType:  &entity.Entity_UserName{UserName: "alice"},
			Category:    entity.Entity_CATEGORY_SUBJECT,
		}},
	}

	_, err := entityRepresentationsFromResolvedChain(chain, false)
	if err == nil {
		t.Fatal("expected typed token-chain entity to be rejected")
	}
}
