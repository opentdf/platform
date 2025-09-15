package cache

const defaultCacheMaxCostBytes int64 = 1 * 1024 * 1024 * 1024 // 1GB

type Config struct {
	Driver         string          `mapstructure:"driver" json:"driver" default:"ristretto"`
	RistrettoCache RistrettoConfig `mapstructure:"ristretto" json:"ristretto"`
}

// CacheRistrettoConfig supports human-friendly size strings like "1gb", "512mb", etc.
type RistrettoConfig struct {
	// MaxCost is the maximum cost of the cache, can be a number (bytes) or a string like "1gb"
	MaxCost string `mapstructure:"max_cost" json:"max_cost" default:"1gb"`
}

// MaxCostBytes parses MaxCost and returns the value in bytes.
// Supports suffixes: b, kb, mb, gb, tb (case-insensitive).
func (c RistrettoConfig) MaxCostBytes() int64 {
	return relativeFileSizeToBytes(c.MaxCost, defaultCacheMaxCostBytes) // Default to 1GB if parsing fails
}
