package oidc

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/opentdf/platform/service/logger"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type DiscoveryConfiguration = oidc.DiscoveryConfiguration

const discoverRequestTimeout = 10 * 1e9 // 10 seconds

// DiscoverOPENIDConfiguration discovers the openid configuration for the issuer provided
var Discover = func(ctx context.Context, issuer string, logger *logger.Logger) (*DiscoveryConfiguration, error) {
	logger.DebugContext(ctx, "discovering openid configuration", slog.String("issuer", issuer))
	httpClient := &http.Client{
		Timeout: discoverRequestTimeout,
	}
	return client.Discover(ctx, issuer, httpClient)
}
