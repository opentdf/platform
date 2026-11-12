package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDPoPTrustedOriginsEnvOverrideWithoutFileKey(t *testing.T) {
	t.Setenv("TEST_SERVER_AUTH_DPOP_TRUSTED_ORIGINS", "https://platform.example.com,http://localhost:8080")

	legacyLoader, err := NewLegacyLoader(configKey, writeConfig(t, "logger:\n  level: debug\n"))
	require.NoError(t, err)
	defaultsLoader, err := NewDefaultSettingsLoader()
	require.NoError(t, err)

	cfg, err := Load(t.Context(), legacyLoader, defaultsLoader)
	require.NoError(t, err)

	assert.Equal(t, []string{"https://platform.example.com", "http://localhost:8080"}, cfg.Server.Auth.DPoP.TrustedOrigins)
}
