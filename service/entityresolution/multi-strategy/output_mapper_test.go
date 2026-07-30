package multistrategy

import (
	"reflect"
	"testing"
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
