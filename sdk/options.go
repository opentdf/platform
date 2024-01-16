package sdk

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Option func(*config)

type config struct {
	token             grpc.DialOption
	clientCredentials grpc.DialOption
	insecure          grpc.DialOption
}

func (c *config) build() []grpc.DialOption {
	return []grpc.DialOption{
		c.token,
		c.clientCredentials,
		c.insecure,
	}
}

func WithInsecureConn() Option {
	return func(c *config) {
		c.insecure = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
}

func WithToken(token string) Option {
	return func(c *config) {
		c.token = grpc.WithPerRPCCredentials(nil)
	}
}

func WithClientCredentials(clientID, clientSecret string) Option {
	return func(c *config) {

		c.clientCredentials = grpc.WithPerRPCCredentials(nil)
	}
}
