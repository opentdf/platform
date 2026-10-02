package multistrategy

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestResolveEntities_ClaimsProviderUsesInlineClaimsContext(t *testing.T) {
	erService, err := NewERS(t.Context(), types.MultiStrategyConfig{
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

	resp, err := erService.ResolveEntities(t.Context(), connect.NewRequest(&entityresolution.ResolveEntitiesRequest{
		Entities: []*authorization.Entity{
			{
				Id:         "diana-claims",
				EntityType: &authorization.Entity_Claims{Claims: claimsAny},
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
	erService, err := NewERS(t.Context(), types.MultiStrategyConfig{
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

	resp, err := erService.ResolveEntities(t.Context(), connect.NewRequest(&entityresolution.ResolveEntitiesRequest{
		Entities: []*authorization.Entity{{
			Id:         "alice-user-name",
			EntityType: &authorization.Entity_UserName{UserName: "alice"},
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
