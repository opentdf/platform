package auth

import (
	"testing"
)

func TestDotNotation(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		key      string
		expected any
	}{
		{name: "valid key", input: map[string]any{"a": map[string]any{"b": 1}}, key: "a.b", expected: 1},
		{name: "non-existent key", input: map[string]any{"a": map[string]any{"b": 1}}, key: "a.c", expected: nil},
		{name: "nested map", input: map[string]any{"a": map[string]any{"b": map[string]any{"c": 2}}}, key: "a.b.c", expected: 2},
		{name: "invalid key type", input: map[string]any{"a": 1}, key: "a.b", expected: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dotNotation(tt.input, tt.key)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
