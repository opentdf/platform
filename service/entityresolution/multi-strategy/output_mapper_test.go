package multistrategy

import (
	"reflect"
	"testing"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

func TestOutputMapper_transformPostgresObject(t *testing.T) {
	om := NewOutputMapper()

	var typedNilMap map[string]any

	tests := []struct {
		name     string
		input    any
		expected any
		hasError bool
	}{
		{
			name:     "nil input returns empty map",
			input:    nil,
			expected: map[string]any{},
		},
		{
			name:     "typed nil map[string]any returns empty map",
			input:    typedNilMap,
			expected: map[string]any{},
		},
		{
			name:     "already parsed map returned as-is",
			input:    map[string]any{"foo": "bar", "n": float64(1)},
			expected: map[string]any{"foo": "bar", "n": float64(1)},
		},
		{
			name:     "empty []byte returns empty map",
			input:    []byte{},
			expected: map[string]any{},
		},
		{
			name:     "empty string returns empty map",
			input:    "",
			expected: map[string]any{},
		},
		{
			name:     "JSON null []byte returns empty map",
			input:    []byte(`null`),
			expected: map[string]any{},
		},
		{
			name:     "JSON null string returns empty map",
			input:    `null`,
			expected: map[string]any{},
		},
		{
			name:     "valid JSON []byte is unmarshaled",
			input:    []byte(`{"foo":"bar","n":1}`),
			expected: map[string]any{"foo": "bar", "n": float64(1)},
		},
		{
			name:     "valid JSON string is unmarshaled",
			input:    `{"foo":"bar","nested":{"k":"v"}}`,
			expected: map[string]any{"foo": "bar", "nested": map[string]any{"k": "v"}},
		},
		{
			name:     "invalid JSON []byte returns error",
			input:    []byte(`{not json`),
			hasError: true,
		},
		{
			name:     "invalid JSON string returns error",
			input:    `{not json`,
			hasError: true,
		},
		{
			name:     "JSON array []byte is not an object and returns error",
			input:    []byte(`[1,2,3]`),
			hasError: true,
		},
		{
			name:     "unsupported type returns error",
			input:    42,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := om.transformPostgresObject(tt.input)

			if tt.hasError {
				if err == nil {
					t.Fatalf("expected error but got none (result=%v)", result)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("transformPostgresObject(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestOutputMapper_MapResult_FlatClaims(t *testing.T) {
	om := NewOutputMapper()

	raw := &types.RawResult{
		Data: map[string]interface{}{
			"sub":    "user-1",
			"email":  "user@example.com",
			"groups": []string{"admin", "staff"},
			"absent": nil,
		},
		Metadata: map[string]interface{}{"provider_type": "claims"},
	}

	mappings := []types.OutputMapping{
		{SourceClaim: "sub", ClaimName: "user_id"},
		{SourceClaim: "email", ClaimName: "email_address"},
		{SourceClaim: "groups", ClaimName: "user_groups", Transformation: "array"},
		{SourceClaim: "absent", ClaimName: "never_set"},
		{SourceClaim: "missing", ClaimName: "also_never_set"},
	}

	result, err := om.MapResult(raw, mappings, "entity-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]interface{}{
		"user_id":       "user-1",
		"email_address": "user@example.com",
		"user_groups":   []interface{}{"admin", "staff"},
	}
	if !reflect.DeepEqual(result.Claims, expected) {
		t.Errorf("claims = %v, expected %v", result.Claims, expected)
	}

	if result.OriginalID != "entity-1" {
		t.Errorf("original ID = %q, expected %q", result.OriginalID, "entity-1")
	}
	if result.Metadata["provider_type"] != "claims" {
		t.Errorf("provider_type metadata not copied from raw result")
	}
	if result.Metadata["output_mappings_applied"] != len(mappings) {
		t.Errorf("output_mappings_applied = %v, expected %d", result.Metadata["output_mappings_applied"], len(mappings))
	}
	if result.Metadata["claims_mapped"] != len(expected) {
		t.Errorf("claims_mapped = %v, expected %d", result.Metadata["claims_mapped"], len(expected))
	}
	if got := result.Metadata["output_mappings_applied_transformations"]; got != ",,array,," {
		t.Errorf("transformations metadata = %q, expected %q", got, ",,array,,")
	}
}

func TestOutputMapper_MapResult_NilRawResult(t *testing.T) {
	om := NewOutputMapper()

	if _, err := om.MapResult(nil, nil, "entity-1"); err == nil {
		t.Fatal("expected an error for a nil raw result")
	}
}

// TestOutputMapper_MapResult_NestedClaimName pins the end-to-end contract: a dotted
// claim_name must produce output that a subject mapping selector actually matches.
func TestOutputMapper_MapResult_NestedClaimName(t *testing.T) {
	om := NewOutputMapper()

	raw := &types.RawResult{
		Data:     map[string]interface{}{"nationality": "USA"},
		Metadata: map[string]interface{}{},
	}
	mappings := []types.OutputMapping{
		{SourceClaim: "nationality", ClaimName: "attributes.nationality", Transformation: "array"},
	}

	result, err := om.MapResult(raw, mappings, "entity-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]interface{}{
		"attributes": map[string]any{"nationality": []interface{}{"USA"}},
	}
	if !reflect.DeepEqual(result.Claims, expected) {
		t.Fatalf("claims = %v, expected %v", result.Claims, expected)
	}

	flat, err := flattening.Flatten(result.Claims)
	if err != nil {
		t.Fatalf("failed to flatten claims: %v", err)
	}
	selected := flattening.GetFromFlattened(flat, ".attributes.nationality[]")
	if !reflect.DeepEqual(selected, []interface{}{"USA"}) {
		t.Errorf("selector .attributes.nationality[] returned %v, expected [USA]", selected)
	}
}

func TestOutputMapper_MapResult_NestedClaimNamesShareParent(t *testing.T) {
	om := NewOutputMapper()

	raw := &types.RawResult{
		Data:     map[string]interface{}{"nationality": "USA", "clearance": "SECRET"},
		Metadata: map[string]interface{}{},
	}
	mappings := []types.OutputMapping{
		{SourceClaim: "nationality", ClaimName: "attributes.nationality"},
		{SourceClaim: "clearance", ClaimName: "attributes.clearance"},
	}

	result, err := om.MapResult(raw, mappings, "entity-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]interface{}{
		"attributes": map[string]any{"nationality": "USA", "clearance": "SECRET"},
	}
	if !reflect.DeepEqual(result.Claims, expected) {
		t.Errorf("claims = %v, expected %v", result.Claims, expected)
	}

	// Both mappings land under one top-level key, so claims_mapped counts 1.
	if result.Metadata["claims_mapped"] != 1 {
		t.Errorf("claims_mapped = %v, expected 1", result.Metadata["claims_mapped"])
	}
}

func TestOutputMapper_MapResult_PathCollision(t *testing.T) {
	om := NewOutputMapper()

	raw := &types.RawResult{
		Data:     map[string]interface{}{"a": "scalar", "b": "value"},
		Metadata: map[string]interface{}{},
	}
	mappings := []types.OutputMapping{
		{SourceClaim: "a", ClaimName: "attributes"},
		{SourceClaim: "b", ClaimName: "attributes.nationality"},
	}

	if _, err := om.MapResult(raw, mappings, "entity-1"); err == nil {
		t.Fatal("expected a path collision error")
	}
}

// TestOutputMapper_MapResult_DottedClaimNameNests pins the intentional behavior change:
// a literal dot in claim_name used to produce a flat key and now nests.
func TestOutputMapper_MapResult_DottedClaimNameNests(t *testing.T) {
	om := NewOutputMapper()

	raw := &types.RawResult{
		Data:     map[string]interface{}{"id": "user-1"},
		Metadata: map[string]interface{}{},
	}
	mappings := []types.OutputMapping{{SourceClaim: "id", ClaimName: "user.id"}}

	result, err := om.MapResult(raw, mappings, "entity-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, flat := result.Claims["user.id"]; flat {
		t.Error(`claim "user.id" was written as a flat key; it should nest`)
	}
	expected := map[string]interface{}{"user": map[string]any{"id": "user-1"}}
	if !reflect.DeepEqual(result.Claims, expected) {
		t.Errorf("claims = %v, expected %v", result.Claims, expected)
	}
}
