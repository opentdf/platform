package multistrategy

import (
	"context"
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

	// The claims provider reads JWT claims from ctx (see
	// providers/claims/claims_provider.go). In production, upstream callers
	// (admin API middleware, JustInTimePDP) populate this before invoking
	// the handler; we mirror that here so the strategy actually succeeds
	// and we exercise the serialization path where the bug lives.
	ctx := context.WithValue(t.Context(), types.JWTClaimsContextKey, types.JWTClaims{
		"sub":   "alice",
		"email": "alice@example.com",
	})
	resp, err := ers.ResolveEntities(ctx, req)
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
