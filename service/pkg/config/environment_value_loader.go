package config

import (
	"context"
	"fmt"
	"os"
	"strings"
)

const LoaderNameEnvironmentValue = "environment-value"

// EnvironmentValueLoader implements Loader using Viper
type EnvironmentValueLoader struct {
	allowListMap map[string]struct{}
	envKeyPrefix string
	loadedKeys   []string
	loadedValues map[string]string
}

// NewEnvironmentValueLoader creates a new Viper-based configuration loader
// to load from environment variables, from a default or specified file
// (or k8s config map), or some combination
func NewEnvironmentValueLoader(key string, allowList []string) (*EnvironmentValueLoader, error) {
	var allowListMap map[string]struct{}
	if allowList != nil || len(allowList) > 0 {
		allowListMap = make(map[string]struct{})
		for _, allow := range allowList {
			allowListMap[allow] = struct{}{}
		}
	}

	result := &EnvironmentValueLoader{
		allowListMap: allowListMap,
		envKeyPrefix: strings.ToUpper(key) + "_",
	}
	return result, nil
}

// Get fetches a particular config value by dot-delimited key from the source
func (l *EnvironmentValueLoader) Get(key string) (any, error) {
	if l.allowListMap != nil {
		if _, keyInAllowList := l.allowListMap[key]; !keyInAllowList {
			return nil, fmt.Errorf("environment value %s is not allowed", key)
		}
	}
	value, found := l.loadedValues[key]
	if found {
		return value, nil
	}
	return nil, nil
}

// GetConfigKeys returns all the configuration keys found in the environment variables.
func (l *EnvironmentValueLoader) GetConfigKeys() ([]string, error) {
	return l.loadedKeys, nil
}

// Load loads the configuration into the provided struct
func (l *EnvironmentValueLoader) Load(_ Config) error {
	var loadedKeys []string
	loadedValues := make(map[string]string)

	env := os.Environ()
	for _, kv := range env {
		upperKV := strings.ToUpper(kv)
		if strings.HasPrefix(upperKV, l.envKeyPrefix) {
			eqIdx := strings.Index(upperKV, "=")
			envKey := kv[len(l.envKeyPrefix):eqIdx]
			envValue := kv[eqIdx+1:]
			dottedKey := strings.ToLower(strings.ReplaceAll(envKey, "_", "."))
			if l.allowListMap != nil {
				if _, keyInAllowList := l.allowListMap[dottedKey]; !keyInAllowList {
					// This key is not allowed, skip it
					continue
				}
			}

			loadedKeys = append(loadedKeys, dottedKey)
			loadedValues[dottedKey] = envValue
		}
	}

	if len(loadedKeys) > 0 {
		l.loadedKeys = loadedKeys
		l.loadedValues = loadedValues
	} else {
		l.loadedKeys = nil
		l.loadedValues = nil
	}

	return nil
}

// Watch starts watching the config file for configuration changes
func (l *EnvironmentValueLoader) Watch(_ context.Context, _ *Config, _ func(context.Context) error) error {
	// Environment variables can't be watched.
	return nil
}

// Name returns the name of the environment configuration loader
func (l *EnvironmentValueLoader) Name() string {
	return LoaderNameEnvironmentValue
}

// Close closes the environment configuration loader
func (l *EnvironmentValueLoader) Close() error {
	// No-op on a viper-based loader, which does not provide a close method
	return nil
}
