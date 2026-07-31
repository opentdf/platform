package multistrategy

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestClaimsToResultData(t *testing.T) {
	type profile struct {
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}

	tests := []struct {
		name   string
		claims map[string]interface{}
		want   map[string]interface{}
	}{
		{
			name:   "nil claims",
			claims: nil,
			want:   map[string]interface{}{},
		},
		{
			name: "all claims are normalized in one pass",
			claims: map[string]interface{}{
				"groups":    []string{"engineering", "platform"},
				"group_ids": []int{1, 2},
				"attributes": map[string][]bool{
					"enabled": {true, false},
				},
				"profile": profile{Name: "alice", Groups: []string{"engineering"}},
				"age":     42,
			},
			want: map[string]interface{}{
				"groups":    []interface{}{"engineering", "platform"},
				"group_ids": []interface{}{float64(1), float64(2)},
				"attributes": map[string]interface{}{
					"enabled": []interface{}{true, false},
				},
				"profile": map[string]interface{}{
					"name":   "alice",
					"groups": []interface{}{"engineering"},
				},
				"age": float64(42),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := claimsToResultData(tt.claims)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestClaimsToResultDataReturnsMarshalError(t *testing.T) {
	claims := map[string]interface{}{"unsupported": make(chan int)}

	_, err := claimsToResultData(claims)
	require.Error(t, err)
}

// TestERSV2_ResolveEntities_PopulatesRepresentations is spec item 4: the
// v2 handler's direct symptom test. When ResolveEntity succeeds but its
// Metadata contains a value structpb.NewValue rejects, the handler drops
// the entity via `continue` on line 134 of registration.go, and the client
// sees EntityRepresentations = []. This test asserts the opposite: a
// successfully resolved entity flows all the way through the handler's
// structpb serialization and appears in the response, with
// metadata_attempted_strategies as a ListValue (not missing, not stringified).
//
// Runs the real ERSV2 handler against a real Service with a claims
// provider — no HTTP transport, no fake service. That's still a unit test
// (in-process, no external deps) and exercises the exact serialization
// path where the bug lives.
func TestERSV2_ResolveEntities_PopulatesRepresentations(t *testing.T) {
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "jwt_strategy",
				Provider:   "jwt",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{Claim: "sub", Operator: "exists"},
					},
				},
				OutputMapping: []types.OutputMapping{
					{SourceClaim: "sub", ClaimName: "username"},
					{SourceClaim: "email", ClaimName: "email_address"},
				},
			},
		},
	}

	ers, err := NewERSV2(t.Context(), config, logger.CreateTestLogger())
	if err != nil {
		t.Fatalf("Failed to create ERSV2: %v", err)
	}

	claimsStruct, err := structpb.NewStruct(map[string]interface{}{
		"sub":   "alice",
		"email": "alice@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to build claims struct: %v", err)
	}
	claimsAny, err := anypb.New(claimsStruct)
	if err != nil {
		t.Fatalf("Failed to wrap claims in anypb.Any: %v", err)
	}

	req := connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{
			{
				EphemeralId: "entity-1",
				EntityType:  &entity.Entity_Claims{Claims: claimsAny},
			},
		},
	})

	resp, err := ers.ResolveEntities(t.Context(), req)
	if err != nil {
		t.Fatalf("ResolveEntities returned error: %v", err)
	}

	reps := resp.Msg.GetEntityRepresentations()
	if len(reps) != 1 {
		t.Fatalf("EntityRepresentations length = %d, want 1 (empty response means the handler silently dropped the entity via structpb.NewStruct failure)", len(reps))
	}
	if got := reps[0].GetOriginalId(); got != "entity-1" {
		t.Errorf("OriginalId = %q, want %q", got, "entity-1")
	}

	props := reps[0].GetAdditionalProps()
	if len(props) != 1 {
		t.Fatalf("AdditionalProps length = %d, want 1", len(props))
	}
	fields := props[0].GetFields()

	// The resolved claim should be present.
	if got := fields["username"].GetStringValue(); got != "alice" {
		t.Errorf("username in AdditionalProps = %q, want %q", got, "alice")
	}

	// metadata_attempted_strategies MUST serialize to a ListValue. If the
	// source-level fix regresses and the field is stored as []string again,
	// structpb.NewStruct will drop the whole entity and this assertion (and
	// the length assertion above) will fail.
	metaAttempted, ok := fields["metadata_attempted_strategies"]
	if !ok {
		t.Fatalf("metadata_attempted_strategies missing from AdditionalProps; the handler likely dropped the entity")
	}
	list := metaAttempted.GetListValue()
	if list == nil {
		t.Fatalf("metadata_attempted_strategies must be a ListValue, got kind %T", metaAttempted.GetKind())
	}
	if got, want := len(list.GetValues()), 1; got != want {
		t.Errorf("metadata_attempted_strategies length = %d, want %d", got, want)
	}
	if got := list.GetValues()[0].GetStringValue(); got != "jwt_strategy" {
		t.Errorf("metadata_attempted_strategies[0] = %q, want %q", got, "jwt_strategy")
	}
}

func TestResolveEntities_ClaimsProviderUsesInlineClaimsContext(t *testing.T) {
	t.Helper()

	erService, err := NewERSV2(t.Context(), types.MultiStrategyConfig{
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
		t.Fatalf("NewERSV2() error = %v", err)
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

	resp, err := erService.ResolveEntities(t.Context(), connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{
			{
				EphemeralId: "diana-claims",
				EntityType:  &entity.Entity_Claims{Claims: claimsAny},
				Category:    entity.Entity_CATEGORY_SUBJECT,
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

func TestResolveEntities_UserNameEntityDoesNotSeedClaimsContext(t *testing.T) {
	t.Helper()

	erService, err := NewERSV2(t.Context(), types.MultiStrategyConfig{
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
	if err != nil {
		t.Fatalf("NewERSV2() error = %v", err)
	}

	resp, err := erService.ResolveEntities(t.Context(), connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{{
			EphemeralId: "alice-user-name",
			EntityType:  &entity.Entity_UserName{UserName: "alice"},
			Category:    entity.Entity_CATEGORY_SUBJECT,
		}},
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
	if _, hasError := result["error"]; !hasError {
		t.Fatalf("expected claims provider to fail without middleware claims for user_name entity, got %v", result)
	}
	if got := result["entity_id"]; got != "alice-user-name" {
		t.Fatalf("expected entity_id alice-user-name, got %v", got)
	}
}
