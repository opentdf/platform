package db

import (
	"context"

	"github.com/opentdf/platform/service/logger"
)

// Runtime prepares DB configuration and lifecycle hooks before opening a pool.
type Runtime interface {
	Prepare(ctx context.Context, cfg Config, log *logger.Logger) (Config, func(context.Context) error, error)
}

// RuntimeFunc allows plain functions to satisfy Runtime.
type RuntimeFunc func(ctx context.Context, cfg Config, log *logger.Logger) (Config, func(context.Context) error, error)

func (f RuntimeFunc) Prepare(ctx context.Context, cfg Config, log *logger.Logger) (Config, func(context.Context) error, error) {
	return f(ctx, cfg, log)
}

// NoopRuntime is the default runtime when no custom runtime is provided.
type NoopRuntime struct{}

func (NoopRuntime) Prepare(_ context.Context, cfg Config, _ *logger.Logger) (Config, func(context.Context) error, error) {
	return cfg, nil, nil
}

func resolveRuntime(cfg Config) Runtime {
	if cfg.Runtime != nil {
		return cfg.Runtime
	}
	return NoopRuntime{}
}
