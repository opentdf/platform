package config

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	configKey = "test"
)

// Manual mock implementation of Loader
type MockLoader struct {
	loadFn          func(Config) error
	getFn           func(string) (any, error)
	getConfigKeysFn func() ([]string, error)
	watchFn         func(context.Context, *Config, func(context.Context) error) error
	closeFn         func() error
	getNameFn       func() string

	watchCalled   bool
	closeCalled   bool
	getNameCalled bool

	onChangeCalled bool
}

func (l *MockLoader) Load(mostRecentConfig Config) error {
	if l.loadFn != nil {
		return l.loadFn(mostRecentConfig)
	}
	return nil
}

func (l *MockLoader) Get(key string) (any, error) {
	if l.getFn != nil {
		return l.getFn(key)
	}
	return nil, errors.New("not setup for Get")
}

func (l *MockLoader) GetConfigKeys() ([]string, error) {
	if l.getConfigKeysFn != nil {
		return l.getConfigKeysFn()
	}
	return nil, nil
}

func (l *MockLoader) Watch(ctx context.Context, config *Config, onChange func(context.Context) error) error {
	l.watchCalled = true
	if l.watchFn != nil {
		if err := l.watchFn(ctx, config, onChange); err != nil {
			return err
		}
		l.onChangeCalled = true
	}
	return nil
}

func (l *MockLoader) Close() error {
	l.closeCalled = true
	if l.closeFn != nil {
		return l.closeFn()
	}
	return nil
}

func (l *MockLoader) Name() string {
	l.getNameCalled = true
	if l.getNameFn != nil {
		return l.getNameFn()
	}
	return "mock"
}

func newMockLoader() *MockLoader {
	return &MockLoader{}
}

func TestConfig_AddLoader(t *testing.T) {
	config := &Config{}
	loader := newMockLoader()

	config.AddLoader(loader)

	assert.Len(t, config.loaders, 1)
	assert.Equal(t, loader, config.loaders[0])
}

func TestConfig_AddOnConfigChangeHook(t *testing.T) {
	config := &Config{}
	hookCalled := false
	hook := func(_ ServicesMap) error {
		hookCalled = true
		return nil
	}

	config.AddOnConfigChangeHook(hook)

	assert.Len(t, config.onConfigChangeHooks, 1)

	// Verify hook works
	err := config.onConfigChangeHooks[0](ServicesMap{})
	require.NoError(t, err)
	assert.True(t, hookCalled)
}

func TestConfig_Watch(t *testing.T) {
	ctx := t.Context()

	t.Run("No loaders", func(t *testing.T) {
		config := &Config{}
		err := config.Watch(ctx)
		require.NoError(t, err)
	})

	t.Run("Loader succeeds", func(t *testing.T) {
		config := &Config{}
		loader := newMockLoader()
		// Mock loader to call onChange
		loader.watchFn = func(_ context.Context, _ *Config, _ func(context.Context) error) error {
			return nil
		}
		config.AddLoader(loader)

		err := config.Watch(ctx)

		require.NoError(t, err)
		assert.True(t, loader.watchCalled)
		assert.True(t, loader.onChangeCalled)
	})

	t.Run("Loader fails", func(t *testing.T) {
		config := &Config{}
		expectedErr := errors.New("watch error")
		loader := newMockLoader()
		loader.watchFn = func(_ context.Context, _ *Config, _ func(context.Context) error) error {
			return expectedErr
		}
		config.AddLoader(loader)

		err := config.Watch(ctx)

		assert.Equal(t, expectedErr, err)
		assert.True(t, loader.watchCalled)
		assert.False(t, loader.onChangeCalled)
	})
}

func TestConfig_Close(t *testing.T) {
	ctx := t.Context()

	t.Run("No loaders", func(t *testing.T) {
		config := &Config{}
		err := config.Close(ctx)
		require.NoError(t, err)
	})

	t.Run("Loader succeeds", func(t *testing.T) {
		config := &Config{}
		loader := newMockLoader()
		config.AddLoader(loader)

		err := config.Close(ctx)

		require.NoError(t, err)
		assert.True(t, loader.closeCalled)
	})

	t.Run("Loader fails", func(t *testing.T) {
		config := &Config{}
		expectedErr := errors.New("close error")
		loader := newMockLoader()
		loader.closeFn = func() error {
			return expectedErr
		}
		config.AddLoader(loader)

		err := config.Close(ctx)

		assert.Equal(t, expectedErr, err)
		assert.True(t, loader.closeCalled)
	})
}

func TestConfig_OnChange(t *testing.T) {
	ctx := t.Context()

	t.Run("No hooks", func(t *testing.T) {
		config := &Config{}
		// Need to add a loader for OnChange to do anything
		config.AddLoader(newMockLoader())
		err := config.OnChange(ctx)
		require.NoError(t, err)
	})

	t.Run("Hook succeeds", func(t *testing.T) {
		config := &Config{}
		loader := newMockLoader()
		config.AddLoader(loader)
		hookCalled := false
		hook := func(_ ServicesMap) error {
			hookCalled = true
			return nil
		}
		config.AddOnConfigChangeHook(hook)

		err := config.OnChange(ctx)

		require.NoError(t, err)
		assert.True(t, hookCalled)
	})

	t.Run("Hook fails", func(t *testing.T) {
		config := &Config{}
		config.AddLoader(newMockLoader())
		expectedErr := errors.New("hook error")
		errorHook := func(_ ServicesMap) error {
			return expectedErr
		}
		config.AddOnConfigChangeHook(errorHook)

		err := config.OnChange(ctx)

		assert.Equal(t, expectedErr, err)
	})
}

func TestLoadConfig_NoFileExistsInEnv(t *testing.T) {
	ctx := t.Context()
	envLoader, err := NewEnvironmentValueLoader(configKey, nil)
	require.NoError(t, err)
	configFileLoader, err := NewConfigFileLoader(configKey, "non-existent-file")
	require.NoError(t, err)
	_, err = Load(
		ctx,
		envLoader,
		configFileLoader,
	)
	assert.Error(t, err)
}

func TestLoadConfig_Success(t *testing.T) {
	// Create a temporary config file
	tempFile, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Write valid config content to the temp file
	configContent := `
logger:
  level: debug
  type: text
  output: stderr
mode: core
db:
  host: opentdf
  port: 5555
  user: postgres
  password: test
services:
  service_a:
    value1: abc
    value2: def
server:
  port: 9999
`
	if _, err := tempFile.Write([]byte(configContent)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close()

	// Call LoadConfig with the temp file
	ctx := t.Context()
	envLoader, err := NewEnvironmentValueLoader(configKey, nil)
	require.NoError(t, err)
	configFileLoader, err := NewConfigFileLoader(configKey, tempFile.Name())
	require.NoError(t, err)
	config, err := Load(
		ctx,
		envLoader,
		configFileLoader,
	)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, config)

	// Verify specific config values were loaded correctly
	// mode
	assert.Equal(t, []string{"core"}, config.Mode)
	// db
	assert.Equal(t, "opentdf", config.DB.Host)
	assert.Equal(t, 5555, config.DB.Port)
	assert.Equal(t, "postgres", config.DB.User)
	assert.Equal(t, "test", config.DB.Password)
	// server
	assert.Equal(t, 9999, config.Server.Port)
	// logger
	assert.Equal(t, "debug", config.Logger.Level)
	// services
	assert.Len(t, config.Services, 1)
	assert.Equal(t, "abc", config.Services["service_a"]["value1"])
	assert.Equal(t, "def", config.Services["service_a"]["value2"])
}

// TestLoad_Precedence is a matrix test that verifies the loading order
// and precedence of different configuration sources.
func TestLoad_Precedence(t *testing.T) {
	// Helper to create a temp config file for tests
	newTempConfigFile := func(t *testing.T, content string) string {
		t.Helper()
		f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
		require.NoError(t, err)
		_, err = f.WriteString(content)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		return f.Name()
	}

	testCases := []struct {
		name         string
		setupLoaders func(t *testing.T, configFile string) []Loader
		envVars      map[string]string
		err          error
		fileContent  string
		asserts      func(t *testing.T, cfg *Config)
	}{
		{
			name: "defaults only",
			setupLoaders: func(t *testing.T, _ string) []Loader {
				defaults, err := NewDefaultSettingsLoader()
				require.NoError(t, err)
				return []Loader{defaults}
			},
			asserts: func(t *testing.T, cfg *Config) {
				// Assert values from `default` struct tags
				assert.Equal(t, []string{"all"}, cfg.Mode)
				assert.Equal(t, "info", cfg.Logger.Level)
				assert.Equal(t, 8080, cfg.Server.Port)
			},
		},
		{
			name: "file overrides defaults",
			setupLoaders: func(t *testing.T, configFile string) []Loader {
				file, err := NewConfigFileLoader(configKey, configFile)
				require.NoError(t, err)
				defaults, err := NewDefaultSettingsLoader()
				require.NoError(t, err)
				// File loader comes first, so it has higher priority
				return []Loader{file, defaults}
			},
			fileContent: `
server:
  port: 9090
logger:
  level: warn
`,
			asserts: func(t *testing.T, cfg *Config) {
				// Values from file
				assert.Equal(t, 9090, cfg.Server.Port)
				assert.Equal(t, "warn", cfg.Logger.Level)
				// Value from defaults
				assert.Equal(t, []string{"all"}, cfg.Mode)
			},
		},
		{
			name: "file with extras and defaults",
			setupLoaders: func(t *testing.T, configFile string) []Loader {
				file, err := NewConfigFileLoader(configKey, configFile)
				require.NoError(t, err)
				defaults, err := NewDefaultSettingsLoader()
				require.NoError(t, err)
				// File loader comes first, so it has higher priority
				return []Loader{file, defaults}
			},
			fileContent: `
server:
  port: 9090
  public_hostname: "test.host"
logger:
  level: warn
special_key:
  nested:
    special_value: 123
`,
			asserts: func(t *testing.T, cfg *Config) {
				// Values from file
				assert.Equal(t, "test.host", cfg.Server.PublicHostname)
				assert.Equal(t, 9090, cfg.Server.Port)
				assert.Equal(t, "warn", cfg.Logger.Level)
				// Value from defaults
				assert.Equal(t, []string{"all"}, cfg.Mode)
			},
		},
		{
			name: "env overrides file and defaults except client_id",
			setupLoaders: func(t *testing.T, configFile string) []Loader {
				envLoader, err := NewEnvironmentValueLoader(configKey, nil)
				require.NoError(t, err)

				file, err := NewConfigFileLoader(configKey, configFile)
				require.NoError(t, err)
				defaults, err := NewDefaultSettingsLoader()
				require.NoError(t, err)
				// Order: env > file > defaults
				return []Loader{envLoader, file, defaults}
			},
			envVars: map[string]string{
				"TEST_SERVER_PORT":              "9999",
				"TEST_LOGGER_LEVEL":             "debug",
				"TEST_DB_HOST":                  "env.host",
				"TEST_SDK_CONFIG_CLIENT_ID":     "client-from-env",
				"TEST_SDK_CONFIG_CLIENT_SECRET": "secret-from-env",
				"TEST_SERVICES_FOO_BAR":         "baz",
			},
			fileContent: `
server:
  port: 9090
logger:
  level: warn
db:
  host: file.host
sdk_config:
  client_id: client-from-file
  client_secret: secret-from-file
`,
			asserts: func(t *testing.T, cfg *Config) {
				// Values from env
				assert.Equal(t, 9999, cfg.Server.Port)
				assert.Equal(t, "debug", cfg.Logger.Level)
				assert.Equal(t, "env.host", cfg.DB.Host)

				// Different from the LegacyLoader below
				assert.Equal(t, "client-from-file", cfg.SDKConfig.ClientID)
				assert.Equal(t, "secret-from-file", cfg.SDKConfig.ClientSecret)

				// Value from defaults (not overridden by file or env)
				assert.Equal(t, []string{"all"}, cfg.Mode)

				// Value placed into service map in env
				// Different from the LegacyLoader below
				require.Contains(t, cfg.Services, "foo")
				assert.Equal(t, "baz", cfg.Services["foo"]["bar"])
			},
		},
		{
			name: "env from legacy overrides file and defaults",
			setupLoaders: func(t *testing.T, configFile string) []Loader {
				legacyLoader, err := NewLegacyLoader(configKey, configFile)
				require.NoError(t, err)
				defaults, err := NewDefaultSettingsLoader()
				require.NoError(t, err)
				// Order: env > file > defaults
				return []Loader{legacyLoader, defaults}
			},
			envVars: map[string]string{
				"TEST_SERVER_PORT":              "9999",
				"TEST_LOGGER_LEVEL":             "debug",
				"TEST_DB_HOST":                  "env.host",
				"TEST_SDK_CONFIG_CLIENT_ID":     "client-from-env",
				"TEST_SDK_CONFIG_CLIENT_SECRET": "secret-from-env",
				"TEST_SERVICES_FOO_BAR":         "baz",
			},
			fileContent: `
server:
  port: 9090
logger:
  level: warn
db:
  host: file.host
sdk_config:
  client_id: client-from-file
  client_secret: secret-from-file
`,
			asserts: func(t *testing.T, cfg *Config) {
				// Values from env
				assert.Equal(t, 9999, cfg.Server.Port)
				assert.Equal(t, "debug", cfg.Logger.Level)
				assert.Equal(t, "env.host", cfg.DB.Host)

				// Different from the EnvironmentValueLoader above
				assert.Equal(t, "client-from-env", cfg.SDKConfig.ClientID)
				assert.Equal(t, "secret-from-env", cfg.SDKConfig.ClientSecret)

				// Value from defaults (not overridden by file or env)
				assert.Equal(t, []string{"all"}, cfg.Mode)

				// Value not placed service map in env
				// Different from the EnvironmentValueLoader above
				require.NotContains(t, cfg.Services, "foo")
			},
		},
		{
			name: "env does not override undefined snake-case YAML keys",
			setupLoaders: func(t *testing.T, configFile string) []Loader {
				envLoader, err := NewEnvironmentValueLoader(configKey, nil)
				require.NoError(t, err)

				file, err := NewConfigFileLoader(configKey, configFile)
				require.NoError(t, err)
				defaults, err := NewDefaultSettingsLoader()
				require.NoError(t, err)
				// Order: env > file > defaults
				return []Loader{envLoader, file, defaults}
			},
			envVars: map[string]string{
				"TEST_SDK_CONFIG_CLIENT_ID":     "client-from-env",
				"TEST_SDK_CONFIG_CLIENT_SECRET": "secret-from-env",
			},
			fileContent: `
server:
  port: 9090
logger:
  level: warn
db:
  host: file.host
`,
			asserts: func(t *testing.T, cfg *Config) {
				// Same as the LegacyLoader below
				assert.Empty(t, cfg.SDKConfig.ClientID)
				assert.Empty(t, cfg.SDKConfig.ClientSecret)
			},
		},
		{
			name: "env from legacy does not override undefined snake-case YAML keys",
			setupLoaders: func(t *testing.T, configFile string) []Loader {
				legacyLoader, err := NewLegacyLoader(configKey, configFile)
				require.NoError(t, err)
				defaults, err := NewDefaultSettingsLoader()
				require.NoError(t, err)
				// Order: env > file > defaults
				return []Loader{legacyLoader, defaults}
			},
			envVars: map[string]string{
				"TEST_SDK_CONFIG_CLIENT_ID":     "client-from-env",
				"TEST_SDK_CONFIG_CLIENT_SECRET": "secret-from-env",
			},
			fileContent: `
server:
  port: 9090
logger:
  level: warn
db:
  host: file.host
`,
			asserts: func(t *testing.T, cfg *Config) {
				// Same as the EnvironmentValueLoader above
				assert.Empty(t, cfg.SDKConfig.ClientID)
				assert.Empty(t, cfg.SDKConfig.ClientSecret)
			},
		},
		{
			name: "env with allow list allows key",
			envVars: map[string]string{
				"TEST_SERVER_PORT": "9999", // This should be loaded
			},
			setupLoaders: func(t *testing.T, configFile string) []Loader {
				// Allow list only contains server.port
				allowList := []string{"server.port"}
				envLoader, err := NewEnvironmentValueLoader(configKey, allowList)
				require.NoError(t, err)

				file, err := NewConfigFileLoader(configKey, configFile)
				require.NoError(t, err)
				return []Loader{envLoader, file}
			},
			fileContent: `
server:
  port: 8888
`,
			asserts: func(t *testing.T, cfg *Config) {
				// The allowed env var should override the file value.
				assert.Equal(t, 9999, cfg.Server.Port)
			},
		},
		{
			name: "env with allow list blocks key",
			envVars: map[string]string{
				"TEST_SERVER_PORT":  "9999",  // This should be BLOCKED
				"TEST_LOGGER_LEVEL": "debug", // This should be ALLOWED
			},
			setupLoaders: func(t *testing.T, configFile string) []Loader {
				// Allow list does NOT contain server.port
				allowList := []string{"logger.level"}
				envLoader, err := NewEnvironmentValueLoader(configKey, allowList)
				require.NoError(t, err)

				file, err := NewConfigFileLoader(configKey, configFile)
				require.NoError(t, err)
				defaults, err := NewDefaultSettingsLoader()
				require.NoError(t, err)
				return []Loader{envLoader, file, defaults}
			},
			fileContent: `
server:
  port: 8888
logger:
  level: info
`,
			asserts: func(t *testing.T, cfg *Config) {
				// The server.port env var was blocked, so the value from the file takes precedence.
				assert.Equal(t, 8888, cfg.Server.Port)
				// The logger.level env var was allowed, so it overrides the file value.
				assert.Equal(t, "debug", cfg.Logger.Level)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup env vars
			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}

			// Setup config file
			configFile := ""
			if tc.fileContent != "" {
				configFile = newTempConfigFile(t, tc.fileContent)
			}

			// Setup loaders
			loaders := tc.setupLoaders(t, configFile)

			// Load config
			cfg, err := Load(t.Context(), loaders...)

			// Assertions
			if tc.err != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
			}
			if tc.asserts != nil {
				tc.asserts(t, cfg)
			}
		})
	}
}
