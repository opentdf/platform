package multistrategy

import (
	"reflect"
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

func TestLookupSourceField(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		field    string
		expected interface{}
		found    bool
	}{
		{
			name:     "flat key",
			data:     map[string]interface{}{"sub": "user-1"},
			field:    "sub",
			expected: "user-1",
			found:    true,
		},
		{
			name:  "flat key wins over dotted path",
			field: "a.b",
			data: map[string]interface{}{
				"a.b": "flat",
				"a":   map[string]interface{}{"b": "nested"},
			},
			expected: "flat",
			found:    true,
		},
		{
			name:     "dotted path",
			data:     map[string]interface{}{"realm_access": map[string]interface{}{"roles": []string{"admin"}}},
			field:    "realm_access.roles",
			expected: []string{"admin"},
			found:    true,
		},
		{
			name: "deeply dotted path",
			data: map[string]interface{}{
				"resource_access": map[string]interface{}{
					"my-client": map[string]interface{}{"roles": []string{"reader"}},
				},
			},
			field:    "resource_access.my-client.roles",
			expected: []string{"reader"},
			found:    true,
		},
		{
			name:     "nil leaf is found",
			data:     map[string]interface{}{"a": map[string]interface{}{"b": nil}},
			field:    "a.b",
			expected: nil,
			found:    true,
		},
		{
			name:  "absent flat key",
			data:  map[string]interface{}{"sub": "user-1"},
			field: "missing",
			found: false,
		},
		{
			name:  "absent leaf under existing parent",
			data:  map[string]interface{}{"a": map[string]interface{}{"b": "v"}},
			field: "a.c",
			found: false,
		},
		{
			name:  "absent intermediate",
			data:  map[string]interface{}{"a": map[string]interface{}{"b": "v"}},
			field: "x.b",
			found: false,
		},
		{
			name:  "scalar intermediate is not traversable",
			data:  map[string]interface{}{"a": "scalar"},
			field: "a.b",
			found: false,
		},
		{
			name:  "nil intermediate is not traversable",
			data:  map[string]interface{}{"a": nil},
			field: "a.b",
			found: false,
		},
		{
			name:     "map[string]string intermediate",
			data:     map[string]interface{}{"a": map[string]string{"b": "v"}},
			field:    "a.b",
			expected: "v",
			found:    true,
		},
		{
			name:     "JWTClaims intermediate",
			data:     map[string]interface{}{"a": types.JWTClaims{"b": "v"}},
			field:    "a.b",
			expected: "v",
			found:    true,
		},
		{
			name:  "non-string-keyed map intermediate",
			data:  map[string]interface{}{"a": map[int]string{1: "v"}},
			field: "a.b",
			found: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, found := lookupSourceField(tt.data, tt.field)

			if found != tt.found {
				t.Fatalf("lookupSourceField(%q) found = %v, expected %v", tt.field, found, tt.found)
			}
			if found && !reflect.DeepEqual(value, tt.expected) {
				t.Errorf("lookupSourceField(%q) = %v, expected %v", tt.field, value, tt.expected)
			}
		})
	}
}

func TestOutputMapper_getSourceValue_SourcePrecedence(t *testing.T) {
	om := NewOutputMapper()

	raw := &types.RawResult{
		Data: map[string]interface{}{
			"col":  "from-column",
			"attr": "from-attribute",
			"clm":  "from-claim",
			"key":  "from-key",
		},
	}

	tests := []struct {
		name     string
		mapping  types.OutputMapping
		expected interface{}
	}{
		{
			name:     "column wins",
			mapping:  types.OutputMapping{SourceColumn: "col", SourceAttribute: "attr", SourceClaim: "clm", SourceKey: "key"},
			expected: "from-column",
		},
		{
			name:     "attribute beats claim and key",
			mapping:  types.OutputMapping{SourceAttribute: "attr", SourceClaim: "clm", SourceKey: "key"},
			expected: "from-attribute",
		},
		{
			name:     "claim beats key",
			mapping:  types.OutputMapping{SourceClaim: "clm", SourceKey: "key"},
			expected: "from-claim",
		},
		{
			name:     "key is the fallback",
			mapping:  types.OutputMapping{SourceKey: "key"},
			expected: "from-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := om.getSourceValue(raw, tt.mapping)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if value != tt.expected {
				t.Errorf("getSourceValue() = %v, expected %v", value, tt.expected)
			}
		})
	}

	t.Run("no source field is an error", func(t *testing.T) {
		if _, err := om.getSourceValue(raw, types.OutputMapping{ClaimName: "c"}); err == nil {
			t.Fatal("expected an error when no source field is specified")
		}
	})
}

func TestOutputMapper_MapResult_DottedSourceField(t *testing.T) {
	om := NewOutputMapper()

	raw := &types.RawResult{
		Data: map[string]interface{}{
			"realm_access": map[string]interface{}{"roles": []string{"admin", "staff"}},
		},
		Metadata: map[string]interface{}{},
	}
	mappings := []types.OutputMapping{
		{SourceClaim: "realm_access.roles", ClaimName: "attributes.roles", Transformation: "array"},
		{SourceClaim: "realm_access.missing", ClaimName: "attributes.never_set"},
	}

	result, err := om.MapResult(raw, mappings, "entity-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]interface{}{
		"attributes": map[string]any{"roles": []interface{}{"admin", "staff"}},
	}
	if !reflect.DeepEqual(result.Claims, expected) {
		t.Errorf("claims = %v, expected %v", result.Claims, expected)
	}
}
