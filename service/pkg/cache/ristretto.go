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
// Uses a conservative default average item cost (1KB) if the true average is unknown.
func EstimateRistrettoConfigParams(maxCost int64) (int64, int64, error) {
	if maxCost < 1 {
		return 0, 0, fmt.Errorf("maxCost must be greater than 0, got %d", maxCost)
	}
	if maxCost > maxAllowedCost {
		return 0, 0, fmt.Errorf("maxCost is unreasonably high (>%d): %d", maxAllowedCost, maxCost)
	}
	numCounters := ristrettoComputeNumCounters(maxCost)
	bufferItems := ristrettoComputeBufferItems()
	return numCounters, bufferItems, nil
}

// ristrettoComputeNumCounters calculates the recommended number of counters for the Ristretto cache
// based on the provided maximum cache cost (maxCost). It estimates the number of items by dividing
// maxCost by a default average item cost (1KB), then multiplies by a factor to determine the number
// of counters. The function ensures that the returned value is not less than a predefined minimum.
// This helps optimize cache performance and accuracy in eviction policies.
func ristrettoComputeNumCounters(maxCost int64) int64 {
	const defaultAvgItemCost = 1024 // 1KB
	numItems := maxCost / defaultAvgItemCost
	if numItems < 1 {
		numItems = 1
	}
	numCounters := numItems * maxCostFactor
	if numCounters < minimumNumCounters {
		return minimumNumCounters
	}
	return numCounters
}

// ristrettoComputeBufferItems calculates the number of buffer items for the Ristretto cache.
// It multiplies a constant number of buffer items per writer by the number of CPUs available.
// This helps optimize throughput for concurrent cache writes.
func ristrettoComputeBufferItems() int64 {
	const bufferItemsPerWriter = 64
	return bufferItemsPerWriter * int64(runtime.NumCPU())
}
