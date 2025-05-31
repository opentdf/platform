package cache

const (
	// MinimumNumCounters is the minimum number of counters for Ristretto cache
	MinimumNumCounters = 1000
	// DefaultBufferItems is the default number of buffer items for Ristretto cache
	DefaultBufferItems = 64
)

// EstimateRistrettoConfigParams estimates Ristretto cache config parameters
// when avg item cost is unknown (assumes cost per item = 1).
func EstimateRistrettoConfigParams(maxCost int64) (int64, int64) {
	const maxCostFactor = int64(10) // 10x max items
	var numCounters, bufferItems int64
	if maxCost < 1 {
		maxCost = 1
	}
	numCounters = maxCost * maxCostFactor
	if numCounters < MinimumNumCounters {
		numCounters = MinimumNumCounters
	}
	bufferItems = DefaultBufferItems
	return numCounters, bufferItems
}
