package sdk

import (
	"testing"
)

func TestWithKIDInNano(t *testing.T) {
	tests := []struct {
		name string
		kid  bool
		want bool
	}{
		{
			name: "noKID to be true",
			kid:  false,
			want: true,
		},
		{
			name: "noKID to be false",
			kid:  true,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config{}

			if !tt.kid {
				option := WithNoKIDInNano()
				option(c)
			}

			if c.nanoFeatures.noKID != tt.want {
				t.Errorf("WithKIDInNano() = %v, want %v", c.nanoFeatures.noKID, tt.want)
			}
		})
	}
}
