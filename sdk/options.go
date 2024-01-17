package sdk

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Option func(*config)

// Internal config struct for building SDK options.
type config struct {
	token             grpc.DialOption
	clientCredentials grpc.DialOption
	tls               grpc.DialOption
}

func (c *config) build() []grpc.DialOption {
	var opts []grpc.DialOption

	if c.clientCredentials != nil {
		opts = append(opts, c.clientCredentials)
	}

	if c.token != nil {
		opts = append(opts, c.token)
	}

	opts = append(opts, c.tls)

	return opts
}

// WithInsecureConn returns an Option that sets up an http connection.
func WithInsecureConn() Option {
	return func(c *config) {
		c.tls = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
}

// WithToken returns an Option that sets up authentication with a access token.
func WithToken(token string) Option {
	return func(c *config) {
		c.token = grpc.WithPerRPCCredentials(nil)
	}
}

// WithClientCredentials returns an Option that sets up authentication with client credentials.
func WithClientCredentials(clientID, clientSecret string) Option {
	return func(c *config) {
		c.clientCredentials = grpc.WithPerRPCCredentials(nil)
	}
}
