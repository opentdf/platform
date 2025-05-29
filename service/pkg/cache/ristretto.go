package cache

// EstimateRistrettoConfigParams estimates Ristretto cache config parameters
// when avg item cost is unknown (assumes cost per item = 1).
func EstimateRistrettoConfigParams(maxCost int64) (numCounters, bufferItems int64) {
	if maxCost < 1 {
		maxCost = 1
	}
	numCounters = maxCost * 10
	if numCounters < 1000 {
		numCounters = 1000
	}
	bufferItems = 64
	return
}
