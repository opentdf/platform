package memhttp

import (
	"context"
	"log"
	"time"
)

type config struct {
	CleanupContext func() (context.Context, context.CancelFunc)
	ErrorLog       *log.Logger
}

// An Option configures a Server.
type Option interface {
	apply(*config)
}

type optionFunc func(*config)

func (f optionFunc) apply(cfg *config) { f(cfg) }

// WithOptions composes multiple Options into one.
func WithOptions(opts ...Option) Option {
	return optionFunc(func(cfg *config) {
		for _, opt := range opts {
			opt.apply(cfg)
		}
	})
}

// WithCleanupTimeout customizes the default five-second timeout for the
// server's Cleanup method. It's most useful with the memhttptest subpackage.
func WithCleanupTimeout(d time.Duration) Option {
	return optionFunc(func(cfg *config) {
		cfg.CleanupContext = func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), d)
		}
	})
}

// WithErrorLog sets [http.Server.ErrorLog].
func WithErrorLog(l *log.Logger) Option {
	return optionFunc(func(cfg *config) {
		cfg.ErrorLog = l
	})
}
