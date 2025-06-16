package cache

import (
	"fmt"
	"runtime"
)

const (
	// minimumNumCounters is the minimum number of counters for Ristretto cache
	minimumNumCounters = 1000
	// maxCostFactor is the maximum cost factor for Ristretto cache
	maxCostFactor = 10 // 10x max items
	// maxAllowedCost is the maximum allowed cost for Ristretto cache (8GB)
	maxAllowedCost = 8 * 1024 * 1024 * 1024 // 8GB
)

// EstimateRistrettoConfigParams estimates Ristretto cache config parameters
// when avg item cost is unknown (assumes cost per item = 1).
func EstimateRistrettoConfigParams(maxCost int64) (int64, int64, error) {
	var numCounters, bufferItems int64
	if maxCost < 1 {
		return 0, 0, fmt.Errorf("maxCost must be greater than 0, got %d", maxCost)
	}
	if maxCost > maxAllowedCost {
		return 0, 0, fmt.Errorf("maxCost is unreasonably high (>%d): %d", maxAllowedCost, maxCost)
	}
	numCounters = maxCost * maxCostFactor
	if numCounters < minimumNumCounters {
		numCounters = minimumNumCounters
	}
	// Set bufferItems dynamically based on number of CPUs (concurrent writers)
	numWriters := int64(runtime.NumCPU())
	const bufferItemsPerWriter = 64
	bufferItems = bufferItemsPerWriter * numWriters
	return numCounters, bufferItems, nil
}
