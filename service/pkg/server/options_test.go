package server

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopInterceptor returns a connect.UnaryInterceptorFunc that passes through.
func noopInterceptor() connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			return next(ctx, req)
		}
	})
}

func TestWithConnectInterceptors(t *testing.T) {
	tests := []struct {
		name      string
		apply     func(*StartConfig)
		wantCount int
	}{
		{
			name: "single interceptor is appended",
			apply: func(c *StartConfig) {
				*c = WithConnectInterceptors(noopInterceptor())(*c)
			},
			wantCount: 1,
		},
		{
			name: "multiple interceptors are appended in order",
			apply: func(c *StartConfig) {
				*c = WithConnectInterceptors(noopInterceptor(), noopInterceptor(), noopInterceptor())(*c)
			},
			wantCount: 3,
		},
		{
			name: "calling twice accumulates interceptors",
			apply: func(c *StartConfig) {
				*c = WithConnectInterceptors(noopInterceptor())(*c)
				*c = WithConnectInterceptors(noopInterceptor(), noopInterceptor())(*c)
			},
			wantCount: 3,
		},
		{
			name: "empty call leaves slice nil",
			apply: func(c *StartConfig) {
				*c = WithConnectInterceptors()(*c)
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg StartConfig
			tt.apply(&cfg)

			if tt.wantCount == 0 {
				assert.Nil(t, cfg.extraConnectInterceptors)
			} else {
				require.Len(t, cfg.extraConnectInterceptors, tt.wantCount)
			}
			// Must not affect IPC interceptors
			assert.Nil(t, cfg.extraIPCInterceptors)
		})
	}
}

func TestWithIPCInterceptors(t *testing.T) {
	tests := []struct {
		name      string
		apply     func(*StartConfig)
		wantCount int
	}{
		{
			name: "single interceptor is appended",
			apply: func(c *StartConfig) {
				*c = WithIPCInterceptors(noopInterceptor())(*c)
			},
			wantCount: 1,
		},
		{
			name: "multiple interceptors are appended in order",
			apply: func(c *StartConfig) {
				*c = WithIPCInterceptors(noopInterceptor(), noopInterceptor(), noopInterceptor())(*c)
			},
			wantCount: 3,
		},
		{
			name: "calling twice accumulates interceptors",
			apply: func(c *StartConfig) {
				*c = WithIPCInterceptors(noopInterceptor())(*c)
				*c = WithIPCInterceptors(noopInterceptor(), noopInterceptor())(*c)
			},
			wantCount: 3,
		},
		{
			name: "empty call leaves slice nil",
			apply: func(c *StartConfig) {
				*c = WithIPCInterceptors()(*c)
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg StartConfig
			tt.apply(&cfg)

			if tt.wantCount == 0 {
				assert.Nil(t, cfg.extraIPCInterceptors)
			} else {
				require.Len(t, cfg.extraIPCInterceptors, tt.wantCount)
			}
			// Must not affect Connect interceptors
			assert.Nil(t, cfg.extraConnectInterceptors)
		})
	}
}

func TestWithConnectAndIPCInterceptorsTogether(t *testing.T) {
	var cfg StartConfig
	cfg = WithConnectInterceptors(noopInterceptor(), noopInterceptor())(cfg)
	cfg = WithIPCInterceptors(noopInterceptor())(cfg)

	require.Len(t, cfg.extraConnectInterceptors, 2, "expected 2 connect interceptors")
	require.Len(t, cfg.extraIPCInterceptors, 1, "expected 1 IPC interceptor")

	// Verify slices are independent (not sharing backing array)
	assert.NotSame(t,
		&cfg.extraConnectInterceptors[0],
		&cfg.extraIPCInterceptors[0],
		"connect and IPC interceptor slices must be independent",
	)
}
