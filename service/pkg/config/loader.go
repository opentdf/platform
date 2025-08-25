package config

import (
	"context"
	"time"
)

const (
	defaultWatchViaPollInterval = 15 * time.Second
)

// Loader defines the interface for loading and managing configuration
type Loader interface {
	// Get fetches a particular config value by dot-delimited key
	Get(key string) (any, error)
	// GetConfigKeys returns all the top-level configuration keys that the loader can provide
	GetConfigKeys() ([]string, error)
	// Load is called to load/refresh the configuration from its source
	Load(mostRecentConfig Config) error
	// Watch starts watching for configuration changes and invokes an onChange callback
	Watch(ctx context.Context, cfg *Config, onChange func(context.Context) error) error
	// Close closes the configuration loader
	Close() error
	// Name returns the name of the configuration loader
	Name() string
}
