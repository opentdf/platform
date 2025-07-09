package oidc

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"

	"github.com/opentdf/platform/service/logger"
	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type DiscoveryConfiguration = oidc.DiscoveryConfiguration

const discoverRequestTimeout = 10 * 1e9 // 10 seconds

// DiscoverOPENIDConfiguration discovers the openid configuration for the issuer provided
var Discover = func(ctx context.Context, logger *logger.Logger, issuer string, tlsNoVerify bool) (*DiscoveryConfiguration, error) {
	logger.DebugContext(ctx, "discovering openid configuration", slog.String("issuer", issuer))
	httpClient := &http.Client{
		Timeout: discoverRequestTimeout,
	}
	if tlsNoVerify {
		// #nosec G402 -- This is intentionally set for environments where TLS verification is not required
		tr := &http.Transport{
			//nolint:gosec // InsecureSkipVerify is set intentionally
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}
	return client.Discover(ctx, issuer, httpClient)
}
