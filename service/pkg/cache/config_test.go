package cache

import (
	"testing"
)

func TestRistrettoConfig_MaxCostBytes(t *testing.T) {
	t.Run("parses human-friendly size string", func(t *testing.T) {
		cfg := RistrettoConfig{MaxCost: "512mb"}
		got := cfg.MaxCostBytes()
		want := int64(512 * 1024 * 1024)
		if got != want {
			t.Errorf("expected %d, got %d", want, got)
		}
	})

	t.Run("returns default when value is empty", func(t *testing.T) {
		cfg := RistrettoConfig{MaxCost: ""}
		got := cfg.MaxCostBytes()
		want := defaultCacheMaxCostBytes
		if got != want {
			t.Errorf("expected default %d, got %d", want, got)
		}
	})

	t.Run("returns default when value is invalid", func(t *testing.T) {
		cfg := RistrettoConfig{MaxCost: "notasize"}
		got := cfg.MaxCostBytes()
		want := defaultCacheMaxCostBytes
		if got != want {
			t.Errorf("expected default %d, got %d", want, got)
		}
	})
}
