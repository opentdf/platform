package config

import (
	"testing"

	internalserver "github.com/opentdf/platform/service/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPCTransportConfiguration(t *testing.T) {
	t.Run("default settings select connect v1", func(t *testing.T) {
		cfg := loadWithDefaults(t, "logger:\n  level: debug\n")
		assert.Equal(t, internalserver.IPCTransportConnectV1, cfg.Server.IPC.Transport)
	})

	t.Run("yaml opt in", func(t *testing.T) {
		cfg := loadWithDefaults(t, "server:\n  ipc:\n    transport: local-http-v2\n")
		assert.Equal(t, internalserver.IPCTransportLocalHTTPV2, cfg.Server.IPC.Transport)
	})

	t.Run("legacy environment works when yaml omits ipc", func(t *testing.T) {
		t.Setenv("OPENTDF_SERVER_IPC_TRANSPORT", internalserver.IPCTransportLocalHTTPV2)
		legacy, err := NewLegacyLoader("opentdf", writeConfig(t, "logger:\n  level: debug\n"))
		require.NoError(t, err)
		defaultsLoader, err := NewDefaultSettingsLoader()
		require.NoError(t, err)

		cfg, err := Load(t.Context(), legacy, defaultsLoader)
		require.NoError(t, err)
		assert.Equal(t, internalserver.IPCTransportLocalHTTPV2, cfg.Server.IPC.Transport)
	})

	t.Run("legacy environment takes precedence over yaml", func(t *testing.T) {
		t.Setenv("OPENTDF_SERVER_IPC_TRANSPORT", internalserver.IPCTransportLocalHTTPV2)
		legacy, err := NewLegacyLoader("opentdf", writeConfig(t, "server:\n  ipc:\n    transport: connect-v1\n"))
		require.NoError(t, err)
		defaultsLoader, err := NewDefaultSettingsLoader()
		require.NoError(t, err)

		cfg, err := Load(t.Context(), legacy, defaultsLoader)
		require.NoError(t, err)
		assert.Equal(t, internalserver.IPCTransportLocalHTTPV2, cfg.Server.IPC.Transport)
	})

	t.Run("invalid value is rejected", func(t *testing.T) {
		fileLoader, err := NewConfigFileLoader(configKey, writeConfig(t, "server:\n  ipc:\n    transport: fastest\n"))
		require.NoError(t, err)
		defaultsLoader, err := NewDefaultSettingsLoader()
		require.NoError(t, err)

		_, err = Load(t.Context(), fileLoader, defaultsLoader)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrUnmarshallingConfig)
		require.ErrorContains(t, err, "IPC.Transport")
		require.ErrorContains(t, err, "oneof")
	})
}
