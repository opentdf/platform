package multistrategy

import (
	"reflect"
	"testing"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

func TestIsEmptyValue(t *testing.T) {
	var nilMap map[string]interface{}
	var nilSlice []interface{}

	tests := []struct {
		name     string
		value    interface{}
		expected bool
	}{
		{name: "nil", value: nil, expected: true},
		{name: "empty string", value: "", expected: true},
		{name: "empty slice", value: []interface{}{}, expected: true},
		{name: "empty string slice", value: []string{}, expected: true},
		{name: "empty map", value: map[string]interface{}{}, expected: true},
		{name: "typed nil map", value: nilMap, expected: true},
		{name: "typed nil slice", value: nilSlice, expected: true},
		{name: "zero int", value: 0, expected: false},
		{name: "false", value: false, expected: false},
		{name: "zero string", value: "0", expected: false},
		{name: "whitespace string", value: " ", expected: false},
		{name: "slice holding nil", value: []interface{}{nil}, expected: false},
		{name: "non-empty string", value: "USA", expected: false},
		{name: "non-empty map", value: map[string]interface{}{"a": 1}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEmptyValue(tt.value); got != tt.expected {
				t.Errorf("isEmptyValue(%#v) = %v, expected %v", tt.value, got, tt.expected)
			}
		})
	}
}

func TestCloneValue_DeepCopiesContainers(t *testing.T) {
	original := map[string]interface{}{
		"list":   []interface{}{"a", map[string]interface{}{"nested": "v"}},
		"scalar": "s",
	}

	clone, ok := cloneValue(original).(map[string]interface{})
	if !ok {
		t.Fatal("clone is not a map")
	}
	if !reflect.DeepEqual(clone, original) {
		t.Fatalf("clone = %v, expected %v", clone, original)
	}

	clone["scalar"] = "mutated"
	cloneList, _ := clone["list"].([]interface{})
	cloneList[0] = "mutated"
	nested, _ := cloneList[1].(map[string]interface{})
	nested["nested"] = "mutated"

	expected := map[string]interface{}{
		"list":   []interface{}{"a", map[string]interface{}{"nested": "v"}},
		"scalar": "s",
	}
	if !reflect.DeepEqual(original, expected) {
		t.Errorf("mutating the clone changed the original: %v", original)
	}
}

func TestSanitizeClaimValue(t *testing.T) {
	var nilMap map[string]interface{}
	var nilStringSlice []string
	var nilPtr *string

	tests := []struct {
		name     string
		value    interface{}
		expected interface{}
		kept     bool
	}{
		{name: "top-level nil is dropped", value: nil, kept: false},
		{name: "nil pointer is dropped", value: nilPtr, kept: false},
		{name: "typed nil map becomes an empty map", value: nilMap, expected: map[string]interface{}{}, kept: true},
		{name: "typed nil slice becomes an empty slice", value: nilStringSlice, expected: []interface{}{}, kept: true},
		{name: "scalar is kept", value: "USA", expected: "USA", kept: true},
		{name: "empty map is kept", value: map[string]interface{}{}, expected: map[string]interface{}{}, kept: true},
		{name: "empty slice is kept", value: []interface{}{}, expected: []interface{}{}, kept: true},
		{
			name:     "nil map values are dropped",
			value:    map[string]interface{}{"a": "v", "b": nil},
			expected: map[string]interface{}{"a": "v"},
			kept:     true,
		},
		{
			name:     "nil slice elements are dropped",
			value:    []interface{}{"a", nil, "b"},
			expected: []interface{}{"a", "b"},
			kept:     true,
		},
		{
			name:     "nulls are dropped recursively",
			value:    map[string]interface{}{"a": map[string]interface{}{"b": nil, "c": []interface{}{nil, "v"}}},
			expected: map[string]interface{}{"a": map[string]interface{}{"c": []interface{}{"v"}}},
			kept:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, kept := sanitizeClaimValue(tt.value)

			if kept != tt.kept {
				t.Fatalf("sanitizeClaimValue(%#v) kept = %v, expected %v", tt.value, kept, tt.kept)
			}
			if kept && !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("sanitizeClaimValue(%#v) = %v, expected %v", tt.value, got, tt.expected)
			}
		})
	}
}

// TestOutputMapper_MapResult_SanitizedClaimsFlatten guards the reason sanitizing
// exists: a single null anywhere would fail Flatten for the whole entity.
func TestOutputMapper_MapResult_SanitizedClaimsFlatten(t *testing.T) {
	om := NewOutputMapper()

	raw := &types.RawResult{
		Data: map[string]interface{}{
			"profile": map[string]interface{}{"name": "Alice", "middle": nil},
			"absent":  nil,
		},
		Metadata: map[string]interface{}{},
	}
	mappings := []types.OutputMapping{
		{SourceClaim: "profile", ClaimName: "attributes.profile"},
		{SourceClaim: "absent", ClaimName: "attributes.absent"},
	}

	result, err := om.MapResult(raw, mappings, "entity-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]interface{}{
		"attributes": map[string]any{"profile": map[string]interface{}{"name": "Alice"}},
	}
	if !reflect.DeepEqual(result.Claims, expected) {
		t.Fatalf("claims = %v, expected %v", result.Claims, expected)
	}

	if _, err := flattening.Flatten(result.Claims); err != nil {
		t.Errorf("claims containing a stripped null failed to flatten: %v", err)
	}
}

func TestOutputMapper_MapResult_Defaults(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		mapping  types.OutputMapping
		expected map[string]interface{}
	}{
		{
			name:     "default fills an absent source",
			data:     map[string]interface{}{},
			mapping:  types.OutputMapping{SourceClaim: "nationality", ClaimName: "n", Default: []interface{}{"UNKNOWN"}},
			expected: map[string]interface{}{"n": []interface{}{"UNKNOWN"}},
		},
		{
			name:     "default fills a nil source",
			data:     map[string]interface{}{"nationality": nil},
			mapping:  types.OutputMapping{SourceClaim: "nationality", ClaimName: "n", Default: "UNKNOWN"},
			expected: map[string]interface{}{"n": "UNKNOWN"},
		},
		{
			name:     "default fills an empty string source",
			data:     map[string]interface{}{"nationality": ""},
			mapping:  types.OutputMapping{SourceClaim: "nationality", ClaimName: "n", Default: "UNKNOWN"},
			expected: map[string]interface{}{"n": "UNKNOWN"},
		},
		{
			name:     "default fills an empty array source",
			data:     map[string]interface{}{"roles": []interface{}{}},
			mapping:  types.OutputMapping{SourceClaim: "roles", ClaimName: "r", Default: []interface{}{"none"}},
			expected: map[string]interface{}{"r": []interface{}{"none"}},
		},
		{
			name:     "present source ignores the default",
			data:     map[string]interface{}{"nationality": "USA"},
			mapping:  types.OutputMapping{SourceClaim: "nationality", ClaimName: "n", Default: "UNKNOWN", Transformation: "array"},
			expected: map[string]interface{}{"n": []interface{}{"USA"}},
		},
		{
			name: "default is not transformed",
			data: map[string]interface{}{},
			// csv_to_array would error on a slice, proving the transformation is skipped
			mapping:  types.OutputMapping{SourceClaim: "roles", ClaimName: "r", Default: []interface{}{"a", "b"}, Transformation: "csv_to_array"},
			expected: map[string]interface{}{"r": []interface{}{"a", "b"}},
		},
		{
			name:     "empty source without a default is still written",
			data:     map[string]interface{}{"nationality": ""},
			mapping:  types.OutputMapping{SourceClaim: "nationality", ClaimName: "n"},
			expected: map[string]interface{}{"n": ""},
		},
		{
			name:     "absent source without a default is skipped",
			data:     map[string]interface{}{},
			mapping:  types.OutputMapping{SourceClaim: "nationality", ClaimName: "n"},
			expected: map[string]interface{}{},
		},
		{
			name:     "bool default",
			data:     map[string]interface{}{},
			mapping:  types.OutputMapping{SourceClaim: "x", ClaimName: "c", Default: false},
			expected: map[string]interface{}{"c": false},
		},
		{
			name:     "int default",
			data:     map[string]interface{}{},
			mapping:  types.OutputMapping{SourceClaim: "x", ClaimName: "c", Default: 3},
			expected: map[string]interface{}{"c": 3},
		},
		{
			name:     "float default",
			data:     map[string]interface{}{},
			mapping:  types.OutputMapping{SourceClaim: "x", ClaimName: "c", Default: 1.5},
			expected: map[string]interface{}{"c": 1.5},
		},
		{
			name:     "map default",
			data:     map[string]interface{}{},
			mapping:  types.OutputMapping{SourceClaim: "x", ClaimName: "c", Default: map[string]interface{}{"k": "v"}},
			expected: map[string]interface{}{"c": map[string]interface{}{"k": "v"}},
		},
		{
			name:     "default under a dotted claim name",
			data:     map[string]interface{}{},
			mapping:  types.OutputMapping{SourceClaim: "nationality", ClaimName: "attributes.nationality", Default: []interface{}{"UNKNOWN"}},
			expected: map[string]interface{}{"attributes": map[string]any{"nationality": []interface{}{"UNKNOWN"}}},
		},
	}

	om := NewOutputMapper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := &types.RawResult{Data: tt.data, Metadata: map[string]interface{}{}}

			result, err := om.MapResult(raw, []types.OutputMapping{tt.mapping}, "entity-1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(result.Claims, tt.expected) {
				t.Errorf("claims = %#v, expected %#v", result.Claims, tt.expected)
			}
		})
	}
}

// TestOutputMapper_MapResult_DefaultNotAliased guards against a caller mutating an
// emitted claim and corrupting the shared strategy config.
func TestOutputMapper_MapResult_DefaultNotAliased(t *testing.T) {
	om := NewOutputMapper()

	mappings := []types.OutputMapping{
		{SourceClaim: "roles", ClaimName: "roles", Default: []interface{}{"none"}},
	}
	raw := &types.RawResult{Data: map[string]interface{}{}, Metadata: map[string]interface{}{}}

	first, err := om.MapResult(raw, mappings, "entity-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	emitted, ok := first.Claims["roles"].([]interface{})
	if !ok {
		t.Fatal("claim is not a slice")
	}
	emitted[0] = "mutated"

	second, err := om.MapResult(raw, mappings, "entity-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(second.Claims["roles"], []interface{}{"none"}) {
		t.Errorf("mutating an emitted claim corrupted the config default: %v", second.Claims["roles"])
	}
	if !reflect.DeepEqual(mappings[0].Default, []interface{}{"none"}) {
		t.Errorf("config default was mutated: %v", mappings[0].Default)
	}
}
