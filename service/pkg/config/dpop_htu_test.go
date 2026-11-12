package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDPoPHTUEnvOverrideWithoutFileKey(t *testing.T) {
	t.Setenv("TEST_SERVER_AUTH_DPOP_HTU_STRICT", "true")
	t.Setenv("TEST_SERVER_AUTH_DPOP_HTU_ORIGINS", "https://platform.example.com,http://localhost:8080")

	legacyLoader, err := NewLegacyLoader(configKey, writeConfig(t, "logger:\n  level: debug\n"))
	require.NoError(t, err)
	defaultsLoader, err := NewDefaultSettingsLoader()
	require.NoError(t, err)

	cfg, err := Load(t.Context(), legacyLoader, defaultsLoader)
	require.NoError(t, err)

	assert.True(t, cfg.Server.Auth.DPoP.HTU.Strict)
	assert.Equal(t, []string{"https://platform.example.com", "http://localhost:8080"}, cfg.Server.Auth.DPoP.HTU.Origins)
}

func TestDPoPHTUFromYAML(t *testing.T) {
	yaml := `server:
  auth:
    dpop:
      htu:
        strict: true
        origins:
          - https://platform.example.com
          - http://localhost:8080
`
	legacyLoader, err := NewLegacyLoader(configKey, writeConfig(t, yaml))
	require.NoError(t, err)
	defaultsLoader, err := NewDefaultSettingsLoader()
	require.NoError(t, err)

	cfg, err := Load(t.Context(), legacyLoader, defaultsLoader)
	require.NoError(t, err)

	assert.True(t, cfg.Server.Auth.DPoP.HTU.Strict)
	assert.False(t, cfg.Server.Auth.DPoP.StrictHTU) //nolint:staticcheck // the deprecated field must stay unset
	assert.Equal(t, []string{"https://platform.example.com", "http://localhost:8080"}, cfg.Server.Auth.DPoP.HTU.Origins)
}

func TestDPoPDeprecatedStrictHTUFromYAML(t *testing.T) {
	yaml := `server:
  auth:
    dpop:
      strict_htu: true
`
	legacyLoader, err := NewLegacyLoader(configKey, writeConfig(t, yaml))
	require.NoError(t, err)
	defaultsLoader, err := NewDefaultSettingsLoader()
	require.NoError(t, err)

	cfg, err := Load(t.Context(), legacyLoader, defaultsLoader)
	require.NoError(t, err)

	assert.True(t, cfg.Server.Auth.DPoP.StrictHTU) //nolint:staticcheck // verifying the deprecated field still loads
	assert.False(t, cfg.Server.Auth.DPoP.HTU.Strict)
	assert.Empty(t, cfg.Server.Auth.DPoP.HTU.Origins)
}
