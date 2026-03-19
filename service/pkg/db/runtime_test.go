package db

import (
	"context"
	"testing"

	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveRuntime_DefaultNoop(t *testing.T) {
	resolved := resolveRuntime(Config{})
	_, ok := resolved.(NoopRuntime)
	assert.True(t, ok)
}

func TestResolveRuntime_CustomRuntime(t *testing.T) {
	custom := RuntimeFunc(func(_ context.Context, cfg Config, _ *logger.Logger) (Config, func(context.Context) error, error) {
		cfg.Host = "runtime-host"
		return cfg, nil, nil
	})

	resolved := resolveRuntime(Config{Runtime: custom})
	updated, _, err := resolved.Prepare(context.Background(), Config{}, nil)
	require.NoError(t, err)
	assert.Equal(t, "runtime-host", updated.Host)
}

func TestWithRuntime(t *testing.T) {
	base := Config{}
	runtime := NoopRuntime{}

	cfg := WithRuntime(runtime)(base)

	require.NotNil(t, cfg.Runtime)
	assert.Equal(t, runtime, cfg.Runtime)
}
