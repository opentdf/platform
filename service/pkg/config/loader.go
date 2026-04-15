package config

import (
	"context"
)

// ServiceInfo represents minimal information about a service for configuration loaders
type ServiceInfo struct {
	Namespace string
	Name      string
}

// NamespaceInfo represents minimal information about a namespace for configuration loaders
type NamespaceInfo struct {
	Name     string
	Enabled  bool
	Services []ServiceInfo
}

// Loader defines the interface for loading and managing configuration
type Loader interface {
	// Get fetches a particular config value by dot-delimited key
	Get(key string) (any, error)
	// GetConfigKeys returns all the top-level configuration keys that the loader can provide
	GetConfigKeys() ([]string, error)
	// Load is called to load/refresh the configuration from its source
	Load(mostRecentConfig Config) error
	// Watch starts watching for configuration changes and invokes an onChange callback.
	// It receives information about the registered namespaces and services to determine
	// if watching is required for this loader.
	Watch(ctx context.Context, cfg *Config, onChange func(context.Context) error, namespaces []NamespaceInfo) error
	// Close closes the configuration loader
	Close() error
	// Name returns the name of the configuration loader
	Name() string
}
