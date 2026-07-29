package transformation

import (
	"reflect"
	"testing"
)

func TestApplyPostgresObject(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		expected    map[string]any
		expectError bool
	}{
		{
			name:  "JSON string input",
			value: `{"department":"Engineering","level":5,"active":true}`,
			expected: map[string]any{
				"department": "Engineering",
				"level":      float64(5),
				"active":     true,
			},
		},
		{
			name:  "JSONB []byte input",
			value: []byte(`{"role":"admin","groups":["a","b"]}`),
			expected: map[string]any{
				"role":   "admin",
				"groups": []any{"a", "b"},
			},
		},
		{
			name: "Already decoded map[string]any passthrough",
			value: map[string]any{
				"foo": "bar",
			},
			expected: map[string]any{
				"foo": "bar",
			},
		},
		{
			name:  "Nested JSON object",
			value: `{"profile":{"name":"Alice","age":30},"tags":["x","y"]}`,
			expected: map[string]any{
				"profile": map[string]any{
					"name": "Alice",
					"age":  float64(30),
				},
				"tags": []any{"x", "y"},
			},
		},
		{
			name:     "Empty string returns empty map",
			value:    "",
			expected: map[string]any{},
		},
		{
			name:     "Empty []byte returns empty map",
			value:    []byte{},
			expected: map[string]any{},
		},
		{
			name:     "nil returns empty map",
			value:    nil,
			expected: map[string]any{},
		},
		{
			name:        "Invalid JSON returns error",
			value:       `{"not valid`,
			expectError: true,
		},
		{
			name:        "JSON array (not object) returns error",
			value:       `["a","b"]`,
			expectError: true,
		},
		{
			name:        "Unsupported input type returns error",
			value:       12345,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyPostgresObject(tt.value)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none, result=%v", result)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("result mismatch\n got: %#v\nwant: %#v", result, tt.expected)
			}
		})
	}
}

func TestApplySQLTransformation_PostgresObject(t *testing.T) {
	result, err := ApplySQLTransformation(`{"a":1}`, SQLPostgresObject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	obj, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", result)
	}
	if obj["a"] != float64(1) {
		t.Errorf("expected a=1, got %v", obj["a"])
	}
}
