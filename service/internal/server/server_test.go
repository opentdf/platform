package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMergeStringSlices(t *testing.T) {
	tests := []struct {
		name       string
		base       []string
		additional []string
		want       []string
	}{
		{
			name:       "empty additional returns base",
			base:       []string{"A", "B"},
			additional: nil,
			want:       []string{"A", "B"},
		},
		{
			name:       "empty base returns additional",
			base:       nil,
			additional: []string{"A", "B"},
			want:       []string{"A", "B"},
		},
		{
			name:       "merge without duplicates",
			base:       []string{"A", "B"},
			additional: []string{"C", "D"},
			want:       []string{"A", "B", "C", "D"},
		},
		{
			name:       "merge with duplicates removed",
			base:       []string{"A", "B", "C"},
			additional: []string{"B", "D"},
			want:       []string{"A", "B", "C", "D"},
		},
		{
			name:       "both empty returns nil",
			base:       nil,
			additional: nil,
			want:       nil,
		},
		{
			name:       "preserves order - base first then additional",
			base:       []string{"Z", "A"},
			additional: []string{"M", "B"},
			want:       []string{"Z", "A", "M", "B"},
		},
		{
			name:       "deduplicates within base",
			base:       []string{"A", "B", "A"},
			additional: []string{"C"},
			want:       []string{"A", "B", "C"},
		},
		{
			name:       "case sensitive comparison",
			base:       []string{"Accept"},
			additional: []string{"accept", "ACCEPT"},
			want:       []string{"Accept", "accept", "ACCEPT"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeStringSlices(tt.base, tt.additional)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCORSConfig_EffectiveMethods(t *testing.T) {
	tests := []struct {
		name string
		cfg  CORSConfig
		want []string
	}{
		{
			name: "no additional methods",
			cfg: CORSConfig{
				AllowedMethods:    []string{"GET", "POST"},
				AdditionalMethods: nil,
			},
			want: []string{"GET", "POST"},
		},
		{
			name: "with additional methods",
			cfg: CORSConfig{
				AllowedMethods:    []string{"GET", "POST"},
				AdditionalMethods: []string{"PUT", "DELETE"},
			},
			want: []string{"GET", "POST", "PUT", "DELETE"},
		},
		{
			name: "additional methods with duplicate",
			cfg: CORSConfig{
				AllowedMethods:    []string{"GET", "POST", "PUT"},
				AdditionalMethods: []string{"PUT", "DELETE"},
			},
			want: []string{"GET", "POST", "PUT", "DELETE"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.EffectiveMethods()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMergeHeaderSlices(t *testing.T) {
	tests := []struct {
		name       string
		base       []string
		additional []string
		want       []string
	}{
		{
			name:       "empty additional returns base",
			base:       []string{"Authorization", "Content-Type"},
			additional: nil,
			want:       []string{"Authorization", "Content-Type"},
		},
		{
			name:       "empty base returns additional",
			base:       nil,
			additional: []string{"Authorization", "Content-Type"},
			want:       []string{"Authorization", "Content-Type"},
		},
		{
			name:       "merge without duplicates",
			base:       []string{"Authorization"},
			additional: []string{"Content-Type"},
			want:       []string{"Authorization", "Content-Type"},
		},
		{
			name:       "case-insensitive deduplication preserves first occurrence",
			base:       []string{"Authorization"},
			additional: []string{"authorization", "AUTHORIZATION"},
			want:       []string{"Authorization"},
		},
		{
			name:       "mixed case duplicates - base wins",
			base:       []string{"Content-Type", "Accept"},
			additional: []string{"content-type", "X-Custom"},
			want:       []string{"Content-Type", "Accept", "X-Custom"},
		},
		{
			name:       "both empty returns nil",
			base:       nil,
			additional: nil,
			want:       nil,
		},
		{
			name:       "preserves order - base first then additional",
			base:       []string{"X-First", "X-Second"},
			additional: []string{"X-Third", "X-Fourth"},
			want:       []string{"X-First", "X-Second", "X-Third", "X-Fourth"},
		},
		{
			name:       "deduplicates within base (case-insensitive)",
			base:       []string{"Accept", "accept", "ACCEPT"},
			additional: []string{"Content-Type"},
			want:       []string{"Accept", "Content-Type"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeHeaderSlices(tt.base, tt.additional)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCORSConfig_EffectiveHeaders(t *testing.T) {
	tests := []struct {
		name string
		cfg  CORSConfig
		want []string
	}{
		{
			name: "no additional headers",
			cfg: CORSConfig{
				AllowedHeaders:    []string{"Authorization", "Content-Type"},
				AdditionalHeaders: nil,
			},
			want: []string{"Authorization", "Content-Type"},
		},
		{
			name: "with additional headers",
			cfg: CORSConfig{
				AllowedHeaders:    []string{"Authorization", "Content-Type"},
				AdditionalHeaders: []string{"X-Custom-Header"},
			},
			want: []string{"Authorization", "Content-Type", "X-Custom-Header"},
		},
		{
			name: "additional header already in base is deduplicated",
			cfg: CORSConfig{
				AllowedHeaders:    []string{"Authorization", "Content-Type"},
				AdditionalHeaders: []string{"X-Custom", "Content-Type"},
			},
			want: []string{"Authorization", "Content-Type", "X-Custom"},
		},
		{
			name: "case-insensitive deduplication - base casing preserved",
			cfg: CORSConfig{
				AllowedHeaders:    []string{"Authorization", "Content-Type"},
				AdditionalHeaders: []string{"authorization", "content-type", "X-New"},
			},
			want: []string{"Authorization", "Content-Type", "X-New"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.EffectiveHeaders()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCORSConfig_EffectiveExposedHeaders(t *testing.T) {
	tests := []struct {
		name string
		cfg  CORSConfig
		want []string
	}{
		{
			name: "no additional exposed headers",
			cfg: CORSConfig{
				ExposedHeaders:           []string{"Link"},
				AdditionalExposedHeaders: nil,
			},
			want: []string{"Link"},
		},
		{
			name: "with additional exposed headers",
			cfg: CORSConfig{
				ExposedHeaders:           []string{"Link"},
				AdditionalExposedHeaders: []string{"X-Custom-Exposed"},
			},
			want: []string{"Link", "X-Custom-Exposed"},
		},
		{
			name: "empty base with additional",
			cfg: CORSConfig{
				ExposedHeaders:           nil,
				AdditionalExposedHeaders: []string{"X-Custom-Exposed"},
			},
			want: []string{"X-Custom-Exposed"},
		},
		{
			name: "case-insensitive deduplication for exposed headers",
			cfg: CORSConfig{
				ExposedHeaders:           []string{"Link", "X-Request-Id"},
				AdditionalExposedHeaders: []string{"link", "x-request-id", "X-New-Header"},
			},
			want: []string{"Link", "X-Request-Id", "X-New-Header"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.EffectiveExposedHeaders()
			assert.Equal(t, tt.want, got)
		})
	}
}
