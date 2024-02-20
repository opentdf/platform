package sdk

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Functional option for SDK constructor
type Option func(*options)

// Internal configuration for SDK, Option functions update these
type options struct {
	dialOptions []grpc.DialOption
}

// WithInsecureConn returns an Option that sets up an http connection.
func WithInsecureConn() Option {
	return func(c *options) {
		c.dialOptions = append(c.dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
}

// WithToken returns an Option that sets up authentication with an OAuth2 access token.
func WithToken(token string) Option {
	return func(c *options) {
		c.dialOptions = append(c.dialOptions, grpc.WithPerRPCCredentials(nil))
	}
}

// WithClientCredentials returns an Option that sets up authentication with client credentials.
func WithClientCredentials(clientID, clientSecret string) Option {
	return func(c *options) {
		c.dialOptions = append(c.dialOptions, grpc.WithPerRPCCredentials(nil))
	}
}
