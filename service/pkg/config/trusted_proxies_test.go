package config

import (
	"testing"

	"github.com/opentdf/platform/service/internal/server/realip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustedProxiesEnvOverrideWithoutFileKey(t *testing.T) {
	t.Setenv("TEST_SERVER_HTTP_TRUSTEDPROXIES", "10.0.0.0/8,2001:db8:1234::/48")

	legacyLoader, err := NewLegacyLoader(configKey, writeConfig(t, "logger:\n  level: debug\n"))
	require.NoError(t, err)
	defaultsLoader, err := NewDefaultSettingsLoader()
	require.NoError(t, err)

	cfg, err := Load(t.Context(), legacyLoader, defaultsLoader)
	require.NoError(t, err)

	assert.Equal(t, []string{"10.0.0.0/8", "2001:db8:1234::/48"}, cfg.Server.HTTPServerConfig.TrustedProxies)
}

func TestTrustedProxiesEnvTrailingComma(t *testing.T) {
	t.Setenv("TEST_SERVER_HTTP_TRUSTEDPROXIES", "10.0.0.0/8,")

	legacyLoader, err := NewLegacyLoader(configKey, writeConfig(t, "logger:\n  level: debug\n"))
	require.NoError(t, err)
	defaultsLoader, err := NewDefaultSettingsLoader()
	require.NoError(t, err)

	cfg, err := Load(t.Context(), legacyLoader, defaultsLoader)
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0/8", ""}, cfg.Server.HTTPServerConfig.TrustedProxies)
	_, err = realip.ConnectRealIPUnaryInterceptor(cfg.Server.HTTPServerConfig.TrustedProxies)
	require.NoError(t, err)
}
