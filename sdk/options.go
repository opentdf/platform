package sdk

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/credentials/oauth"
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
		perRPC := oauth.TokenSource{TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: token,
		})}
		c.dialOptions = append(c.dialOptions, grpc.WithPerRPCCredentials(perRPC))
	}
}

// WithClientCredentials returns an Option that sets up authentication with client credentials.
func WithClientCredentials(ctx context.Context, clientID, clientSecret string, scopes []string, tokenUrl string) Option {
	conf := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		TokenURL:     tokenUrl,
	}
	perRPC := oauth.TokenSource{TokenSource: conf.TokenSource(ctx)}

	return func(c *options) {
		// TODO Use wire in the token. See https://grpc.io/docs/guides/auth/
		c.dialOptions = append(c.dialOptions, grpc.WithPerRPCCredentials(perRPC))
	}
}
