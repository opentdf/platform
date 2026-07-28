package multistrategy

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestResolveEntities_ClaimsProviderUsesInlineClaimsContext(t *testing.T) {
	t.Helper()

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
	if err != nil {
		t.Fatalf("NewERS() error = %v", err)
	}

	claimsStruct, err := structpb.NewStruct(map[string]interface{}{
		"sub":   "diana",
		"email": "diana@example.com",
	})
	if err != nil {
		t.Fatalf("structpb.NewStruct() error = %v", err)
	}

	claimsAny, err := anypb.New(claimsStruct)
	if err != nil {
		t.Fatalf("anypb.New() error = %v", err)
	}

	resp, err := erService.ResolveEntities(t.Context(), connect.NewRequest(&entityresolution.ResolveEntitiesRequest{
		Entities: []*authorization.Entity{
			{
				Id:         "diana-claims",
				EntityType: &authorization.Entity_Claims{Claims: claimsAny},
			},
		},
	}))
	if err != nil {
		t.Fatalf("ResolveEntities() error = %v", err)
	}

	if got := len(resp.Msg.GetEntityRepresentations()); got != 1 {
		t.Fatalf("expected 1 entity representation, got %d", got)
	}

	props := resp.Msg.GetEntityRepresentations()[0].GetAdditionalProps()
	if len(props) != 1 {
		t.Fatalf("expected 1 additional props entry, got %d", len(props))
	}

	result := props[0].AsMap()
	if got := result["subject"]; got != "diana" {
		t.Fatalf("expected subject diana, got %v", got)
	}
	if got := result["email_address"]; got != "diana@example.com" {
		t.Fatalf("expected email_address diana@example.com, got %v", got)
	}
	if got := result["metadata_source"]; got != "jwt_claims" {
		t.Fatalf("expected metadata_source jwt_claims, got %v", got)
	}
	if _, hasError := result["error"]; hasError {
		t.Fatalf("expected successful resolution, got error payload: %v", result["error"])
	}
}
