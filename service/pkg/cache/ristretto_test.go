package cache

import (
	"runtime"
	"testing"
)

func TestEstimateRistrettoConfigParams(t *testing.T) {
	tests := []struct {
		name    string
		maxCost int64
		wantErr bool
	}{
		{"valid small", 100, false},
		{"valid large", 100000, false},
		{"zero", 0, true},
		{"negative", -1, true},
		{"too large", maxAllowedCost + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, buf, err := EstimateRistrettoConfigParams(tt.maxCost)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				wantCount := ristrettoComputeNumCounters(tt.maxCost)
				wantBuf := ristrettoComputeBufferItems()
				if count != wantCount {
					t.Errorf("numCounters = %d, want %d", count, wantCount)
				}
				if buf != wantBuf {
					t.Errorf("bufferItems = %d, want %d", buf, wantBuf)
				}
			}
		})
	}
}

func TestRistrettoComputeNumCounters(t *testing.T) {
	tests := []struct {
		name     string
		maxCost  int64
		expected int64
	}{
		{"below minimum", 100, minimumNumCounters},
		{"exact minimum", minimumNumCounters * 1024 / maxCostFactor, minimumNumCounters},
		{"above minimum", 10240, 100 * maxCostFactor},
		{"large value", 1024 * 1024, (1024 * 1024 / 1024) * maxCostFactor},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ristrettoComputeNumCounters(tt.maxCost)
			if got != tt.expected {
				t.Errorf("ristrettoComputeNumCounters(%d) = %d, want %d", tt.maxCost, got, tt.expected)
			}
		})
	}
}

func TestRistrettoComputeBufferItems(t *testing.T) {
	const bufferItemsPerWriter = 64
	want := bufferItemsPerWriter * int64(runtime.NumCPU())
	got := ristrettoComputeBufferItems()
	if got != want {
		t.Errorf("ristrettoComputeBufferItems() = %d, want %d", got, want)
	}
}
