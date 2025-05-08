package access

import (
	"context"
	"fmt"
	"log/slog"

	otdfSDK "github.com/opentdf/platform/sdk"

	"github.com/opentdf/platform/service/logger"
)

type ConnectedPDP struct {
	logger *logger.Logger
	sdk    *otdfSDK.SDK
}

// NewConnectedPDP creates a new Policy Decision Point instance with no in-memory policy and a remote connection
// via authenticated SDK.
func NewConnectedPDP(
	ctx context.Context,
	sdk *otdfSDK.SDK,
	l *logger.Logger,
) (*ConnectedPDP, error) {
	var err error

	if sdk == nil {
		l.ErrorContext(ctx, "invalid arguments", slog.String("error", ErrMissingRequiredSDK.Error()))
		return nil, ErrMissingRequiredSDK
	}
	if l == nil {
		l, err = logger.NewLogger(defaultFallbackLoggerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize new PDP logger and none was provided: %w", err)
		}
	}

	return &ConnectedPDP{
		sdk:    sdk,
		logger: l,
	}, nil
}
