package config

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Manual mock implementation of Loader
type MockLoader struct {
	loadFn          func(Config) error
	getFn           func(string) (any, error)
	getConfigKeysFn func() ([]string, error)
	watchFn         func(context.Context, *Config, func(context.Context) error) error
	closeFn         func() error
	getNameFn       func() string

	loadCalled    bool
	watchCalled   bool
	closeCalled   bool
	getNameCalled bool

	onChangeCalled bool
}

func (l *MockLoader) Load(mostRecentConfig Config) error {
	l.loadCalled = true
	if l.loadFn != nil {
		return l.loadFn(mostRecentConfig)
	}
	return nil
}

func (l *MockLoader) Get(key string) (any, error) {
	l.loadCalled = true
	if l.getFn != nil {
		return l.getFn(key)
	}
	return nil, errors.New("not setup for Get")
}

func (l *MockLoader) GetConfigKeys() ([]string, error) {
	l.loadCalled = true
	if l.loadFn != nil {
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
	return ""
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
	envLoader, err := NewEnvironmentValueLoader("test", nil)
	require.NoError(t, err)
	configFileLoader, err := NewConfigFileLoader("test", "non-existent-file")
	require.NoError(t, err)
	_, err = LoadConfig(ctx, []Loader{
		envLoader,
		configFileLoader,
	})
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
  output: stdout
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
	envLoader, err := NewEnvironmentValueLoader("test", nil)
	require.NoError(t, err)
	configFileLoader, err := NewConfigFileLoader("test", tempFile.Name())
	require.NoError(t, err)
	config, err := LoadConfig(ctx, []Loader{
		envLoader,
		configFileLoader,
	})

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
