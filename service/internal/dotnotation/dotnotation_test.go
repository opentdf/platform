package dotnotation

import "testing"

func TestGet(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		key      string
		expected any
	}{
		{name: "valid key", input: map[string]any{"a": map[string]any{"b": 1}}, key: "a.b", expected: 1},
		{name: "non-existent key", input: map[string]any{"a": map[string]any{"b": 1}}, key: "a.c", expected: nil},
		{name: "nested map", input: map[string]any{"a": map[string]any{"b": map[string]any{"c": 2}}}, key: "a.b.c", expected: 2},
		{name: "map string string", input: map[string]any{"a": map[string]string{"b": "value"}}, key: "a.b", expected: "value"},
		{name: "invalid key type", input: map[string]any{"a": 1}, key: "a.b", expected: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Get(tt.input, tt.key)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSet(t *testing.T) {
	t.Run("creates nested maps", func(t *testing.T) {
		input := map[string]any{}

		err := Set(input, "eventMetaData.requester.sub", "test-user")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := Get(input, "eventMetaData.requester.sub"); got != "test-user" {
			t.Fatalf("expected nested value, got %v", got)
		}
	})

	t.Run("converts string keyed maps", func(t *testing.T) {
		input := map[string]any{
			"eventMetaData": map[string]string{
				"existing": "value",
			},
		}

		err := Set(input, "eventMetaData.requester.sub", "test-user")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := Get(input, "eventMetaData.existing"); got != "value" {
			t.Fatalf("expected existing value, got %v", got)
		}
		if got := Get(input, "eventMetaData.requester.sub"); got != "test-user" {
			t.Fatalf("expected nested value, got %v", got)
		}
	})

	t.Run("fails on non-map collision", func(t *testing.T) {
		input := map[string]any{
			"eventMetaData": "not-a-map",
		}

		err := Set(input, "eventMetaData.requester.sub", "test-user")
		if err == nil {
			t.Fatal("expected collision error")
		}
	})

	t.Run("fails on nil root map", func(t *testing.T) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("Set should not panic, got %v", recovered)
			}
		}()

		if err := Set(nil, "a.b", "value"); err == nil {
			t.Fatal("expected error for nil root map")
		}
	})

	t.Run("fails on malformed paths", func(t *testing.T) {
		for _, path := range []string{"a..b", ".a", "a."} {
			t.Run(path, func(t *testing.T) {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("Set should not panic, got %v", recovered)
					}
				}()

				input := make(map[string]any)
				if err := Set(input, path, "value"); err == nil {
					t.Fatal("expected malformed path error")
				}

				if got := Get(input, "a"); got != nil {
					t.Fatalf("expected no root value for a, got %v", got)
				}
				if got := Get(input, "a."); got != nil {
					t.Fatalf("expected no nested invalid value, got %v", got)
				}
				if _, exists := input[""]; exists {
					t.Fatal("expected no empty-string root key")
				}
			})
		}
	})
}
