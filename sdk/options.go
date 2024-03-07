package sdk

import (
	"log/slog"

	"github.com/opentdf/platform/sdk/internal/oauth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Option func(*config)

// Internal config struct for building SDK options.
type config struct {
	tls               grpc.DialOption
	clientCredentials oauth.ClientCredentials
	tokenEndpoint     string
	scopes            []string
	policyConn        *grpc.ClientConn
	authorizationConn *grpc.ClientConn
	unwrapper         Unwrapper
}

func (c *config) build() []grpc.DialOption {
	return []grpc.DialOption{c.tls}
}

// WithInsecureConn returns an Option that sets up an http connection.
func WithInsecureConn() Option {
	return func(c *config) {
		c.tls = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
}

// WithClientCredentials returns an Option that sets up authentication with client credentials.
func WithClientCredentials(clientID, clientSecret string, scopes []string) Option {
	return func(c *config) {
		c.clientCredentials = oauth.ClientCredentials{ClientId: clientID, ClientAuth: clientSecret}
		c.scopes = scopes
		// Build kas client here to unblock sdk initialization. This will be refactored in the future.
		uw, err := buildKASClient(c)
		if err != nil {
			slog.Error("failed to build KAS client", slog.String("error", err.Error()))
		}
		c.unwrapper = &uw
	}
}

// When we implement service discovery using a .well-known endpoint this option may become deprecated
func WithTokenEndpoint(tokenEndpoint string) Option {
	return func(c *config) {
		c.tokenEndpoint = tokenEndpoint
	}
}

// temporary option to allow the for token exchange and the
// use of REST-ful KASs. this will likely change as we
// make these options more robust
func WithAuthConfig(authConfig AuthConfig) Option {
	return func(c *config) {
		c.unwrapper = &authConfig
	}
}

func WithCustomPolicyConnection(conn *grpc.ClientConn) Option {
	return func(c *config) {
		c.policyConn = conn
	}
}

func WithCustomAuthorizationConnection(conn *grpc.ClientConn) Option {
	return func(c *config) {
		c.authorizationConn = conn
	}
}
