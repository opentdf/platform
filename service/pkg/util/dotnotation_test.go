package util

import (
	"testing"
)

func TestDotnotation(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		key      string
		expected any
	}{
		// Basic cases
		{name: "valid key", input: map[string]any{"a": map[string]any{"b": 1}}, key: "a.b", expected: 1},
		{name: "non-existent key", input: map[string]any{"a": map[string]any{"b": 1}}, key: "a.c", expected: nil},
		{name: "nested map", input: map[string]any{"a": map[string]any{"b": map[string]any{"c": 2}}}, key: "a.b.c", expected: 2},
		{name: "invalid key type", input: map[string]any{"a": 1}, key: "a.b", expected: nil},
		{name: "top level key", input: map[string]any{"a": "value"}, key: "a", expected: "value"},
		{name: "nil map value", input: map[string]any{"a": nil}, key: "a.b", expected: nil},
		// Edge cases for malformed keys
		{name: "empty key", input: map[string]any{"a": 1}, key: "", expected: nil},
		{name: "trailing dot", input: map[string]any{"a": 1}, key: "a.", expected: 1},
		{name: "leading dot", input: map[string]any{"a": 1}, key: ".a", expected: 1},
		{name: "double dot", input: map[string]any{"a": map[string]any{"b": 1}}, key: "a..b", expected: 1},
		{name: "only dots", input: map[string]any{"a": 1}, key: "...", expected: nil},
		{name: "whitespace key", input: map[string]any{" ": 1}, key: " ", expected: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Dotnotation(tt.input, tt.key)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
