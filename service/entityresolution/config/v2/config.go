package config

type ERSConfig struct {
	Mode string `mapstructure:"mode" json:"mode"`

	// Lifetime for which ERS responses should be cached to reduce load on identity provider.
	// Default: cache is disabled with lifetime length set to 0.
	CacheResponseLifetimeSeconds int `mapstructure:"cache_response_lifetime_seconds" default:"0"` // Cache disabled by default
}
