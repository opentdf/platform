package cache

import (
	"runtime"
	"testing"
)

func TestEstimateRistrettoConfigParams(t *testing.T) {
	tests := []struct {
		name      string
		maxCost   int64
		wantErr   bool
		wantCount int64
		wantBuf   int64
	}{
		{"valid small", 100, false, 1000, 64 * int64(runtime.NumCPU())},
		{"valid large", 100000, false, 1000000, 64 * int64(runtime.NumCPU())},
		{"zero", 0, true, 0, 0},
		{"negative", -1, true, 0, 0},
		{"too large", maxAllowedCost + 1, true, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, buf, err := EstimateRistrettoConfigParams(tt.maxCost)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if count != tt.wantCount {
					t.Errorf("numCounters = %d, want %d", count, tt.wantCount)
				}
				if buf != tt.wantBuf {
					t.Errorf("bufferItems = %d, want %d", buf, tt.wantBuf)
				}
			}
		})
	}
}
