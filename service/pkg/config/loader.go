package config

import "context"

// Loader defines the interface for loading and managing configuration
type Loader interface {
	// Get fetches a particular config value by dot-delimited key
	Get(key string) (any, error)
	// Load is called to load the configuration from its source before being used
	Load(mostRecentConfig Config) error
	// Watch starts watching for configuration changes and invokes an onChange callback
	Watch(ctx context.Context, cfg *Config, onChange func(context.Context) error) error
	// Close closes the configuration loader
	Close() error
	// Name returns the name of the configuration loader
	Name() string
}
