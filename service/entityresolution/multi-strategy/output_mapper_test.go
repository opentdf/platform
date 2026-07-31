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

func TestOutputMapper_transformPostgresObjectArray(t *testing.T) {
	om := NewOutputMapper()

	var typedNilSliceMap []map[string]any
	var typedNilSliceAny []any

	tests := []struct {
		name     string
		input    any
		expected any
		hasError bool
	}{
		{
			name:     "nil input returns empty slice",
			input:    nil,
			expected: []map[string]any{},
		},
		{
			name:     "typed nil []map[string]any returns empty slice",
			input:    typedNilSliceMap,
			expected: []map[string]any{},
		},
		{
			name:     "typed nil []any returns empty slice",
			input:    typedNilSliceAny,
			expected: []map[string]any{},
		},
		{
			name:     "already parsed []map[string]any returned as-is",
			input:    []map[string]any{{"a": float64(1)}, {"b": "x"}},
			expected: []map[string]any{{"a": float64(1)}, {"b": "x"}},
		},
		{
			name:     "empty []map[string]any returned as-is",
			input:    []map[string]any{},
			expected: []map[string]any{},
		},
		{
			name:     "empty []byte returns empty slice",
			input:    []byte{},
			expected: []map[string]any{},
		},
		{
			name:     "empty string returns empty slice",
			input:    "",
			expected: []map[string]any{},
		},
		{
			name:     "JSON null []byte returns empty slice",
			input:    []byte(`null`),
			expected: []map[string]any{},
		},
		{
			name:     "JSON null string returns empty slice",
			input:    `null`,
			expected: []map[string]any{},
		},
		{
			name:     "empty JSON array []byte returns empty slice",
			input:    []byte(`[]`),
			expected: []map[string]any{},
		},
		{
			name:     "empty JSON array string returns empty slice",
			input:    `[]`,
			expected: []map[string]any{},
		},
		{
			name:     "valid JSON []byte is unmarshaled",
			input:    []byte(`[{"foo":"bar"},{"n":1}]`),
			expected: []map[string]any{{"foo": "bar"}, {"n": float64(1)}},
		},
		{
			name:     "valid JSON string is unmarshaled",
			input:    `[{"a":1},{"nested":{"k":"v"}}]`,
			expected: []map[string]any{{"a": float64(1)}, {"nested": map[string]any{"k": "v"}}},
		},
		{
			name: "[]any of parsed maps is coerced",
			input: []any{
				map[string]any{"a": float64(1)},
				map[string]any{"b": "x"},
			},
			expected: []map[string]any{{"a": float64(1)}, {"b": "x"}},
		},
		{
			name: "[]any of JSON []byte elements is coerced",
			input: []any{
				[]byte(`{"a":1}`),
				[]byte(`{"b":"x"}`),
			},
			expected: []map[string]any{{"a": float64(1)}, {"b": "x"}},
		},
		{
			name: "[]any of JSON string elements is coerced",
			input: []any{
				`{"a":1}`,
				`{"b":"x"}`,
			},
			expected: []map[string]any{{"a": float64(1)}, {"b": "x"}},
		},
		{
			name:     "[]any with nil element becomes empty object",
			input:    []any{nil, map[string]any{"a": float64(1)}},
			expected: []map[string]any{{}, {"a": float64(1)}},
		},
		{
			name:     "[]any with unsupported element type returns error",
			input:    []any{42},
			hasError: true,
		},
		{
			name:     "invalid JSON []byte returns error",
			input:    []byte(`[not json`),
			hasError: true,
		},
		{
			name:     "invalid JSON string returns error",
			input:    `[not json`,
			hasError: true,
		},
		{
			name:     "JSON object []byte is not an array and returns error",
			input:    []byte(`{"a":1}`),
			hasError: true,
		},
		{
			name:     "JSON array of scalars returns error",
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
			result, err := om.transformPostgresObjectArray(tt.input)

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
				t.Errorf("transformPostgresObjectArray(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}
