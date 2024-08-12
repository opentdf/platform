package sdk

import (
	"testing"
)

func TestWithKIDInNano(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{
			name: "nanoKID to be false",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config{}

			option := WithKIDInNano()
			option(c)

			if c.tdfFeatures.nanoKID != tt.want {
				t.Errorf("WithKIDInNano() = %v, want %v", c.tdfFeatures.nanoKID, tt.want)
			}
		})
	}
}
