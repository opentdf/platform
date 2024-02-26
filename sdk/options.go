package sdk

import (
	"context"
	"crypto/tls"

	"github.com/opentdf/platform/sdk/internal/oauth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type Option func(*config)

// Internal config struct for building SDK options.
type config struct {
	tls               grpc.DialOption
	subjectToken      string
	clientCredentials oauth.ClientCredentials
	tokenEndpoint     string
	scopes            []string
	ctx               context.Context
	authConfig        *AuthConfig
}

func (c *config) build() []grpc.DialOption {
	opts := make([]grpc.DialOption, 0)

	var tlsOption grpc.DialOption
	if c.tls != nil {
		tlsOption = c.tls
	} else {
		tlsOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
	}

	opts = append(opts, tlsOption)

	return opts
}

// WithInsecureConn returns an Option that sets up an http connection.
func WithInsecureConn() Option {
	return func(c *config) {
		c.tls = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
}

// WithClientCredentials returns an Option that sets up authentication with client credentials.
func WithClientCredentials(clientID, clientSecret string) Option {
	return func(c *config) {
		c.clientCredentials = oauth.ClientCredentials{ClientId: clientID, ClientAuth: clientSecret}
		c.scopes = make([]string, 0)
	}
}

func WithScopedClientCredentials(clientID, clientSecret string, scopes []string) Option {
	return func(c *config) {
		c.clientCredentials = oauth.ClientCredentials{ClientId: clientID, ClientAuth: clientSecret}
		c.scopes = scopes
	}
}

func WithTokenEndpoint(tokenEndpoint string) Option {
	return func(c *config) {
		c.tokenEndpoint = tokenEndpoint
	}
}

func WithAuthConfig(authConfig AuthConfig) Option {
	return func(c *config) {
		c.authConfig = &authConfig
	}
}
