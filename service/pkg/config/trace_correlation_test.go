package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, yaml string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))
	return path
}

// loadWithDefaults loads yaml backed by the default-settings loader, matching
// the loader priority used at startup (first loader wins).
func loadWithDefaults(t *testing.T, yaml string) *Config {
	t.Helper()

	fileLoader, err := NewConfigFileLoader(configKey, writeConfig(t, yaml))
	require.NoError(t, err)
	defaultsLoader, err := NewDefaultSettingsLoader()
	require.NoError(t, err)

	cfg, err := Load(t.Context(), fileLoader, defaultsLoader)
	require.NoError(t, err)

	return cfg
}

func Test_LoggerTraceCorrelation_DefaultsOn(t *testing.T) {
	cfg := loadWithDefaults(t, "logger:\n  level: debug\n")

	require.Equal(t, "debug", cfg.Logger.Level, "file value must win over defaults")
	require.NotNil(t, cfg.Logger.TraceCorrelation)
	assert.True(t, *cfg.Logger.TraceCorrelation)
}

func Test_LoggerTraceCorrelation_FileOverride(t *testing.T) {
	cfg := loadWithDefaults(t, "logger:\n  trace_correlation: false\n")

	require.NotNil(t, cfg.Logger.TraceCorrelation)
	assert.False(t, *cfg.Logger.TraceCorrelation)
}

// AutomaticEnv only resolves keys the loader already knows about, so this
// depends on the legacy loader registering the key.
func Test_LoggerTraceCorrelation_EnvOverride(t *testing.T) {
	t.Setenv("TEST_LOGGER_TRACE_CORRELATION", "false")

	legacyLoader, err := NewLegacyLoader(configKey, writeConfig(t, "logger:\n  level: debug\n"))
	require.NoError(t, err)
	defaultsLoader, err := NewDefaultSettingsLoader()
	require.NoError(t, err)

	cfg, err := Load(t.Context(), legacyLoader, defaultsLoader)
	require.NoError(t, err)

	require.NotNil(t, cfg.Logger.TraceCorrelation)
	assert.False(t, *cfg.Logger.TraceCorrelation)
}
