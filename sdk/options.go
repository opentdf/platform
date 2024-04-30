package sdk

import (
	"crypto/tls"

	"github.com/opentdf/platform/sdk/internal/oauth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Option func(*config)

// Internal config struct for building SDK options.
type config struct {
	tls               grpc.DialOption
	clientCredentials *oauth.ClientCredentials
	tokenExchange     *oauth.TokenExchangeInfo
	tokenEndpoint     string
	scopes            []string
	authConfig        *AuthConfig
	policyConn        *grpc.ClientConn
	authorizationConn *grpc.ClientConn
	extraDialOptions  []grpc.DialOption
	certExchange      *oauth.CertExchangeInfo
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
		c.clientCredentials = &oauth.ClientCredentials{ClientID: clientID, ClientAuth: clientSecret}
		c.scopes = scopes
	}
}

func WithTLSCredentials(tls *tls.Config, audience []string) Option {
	return func(c *config) {
		c.certExchange = &oauth.CertExchangeInfo{TLSConfig: tls, Audience: audience}
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
		c.authConfig = &authConfig
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

// WithTokenExchange specifies that the SDK should obtain its
// access token by exchanging the given token for a new one
func WithTokenExchange(subjectToken string, audience []string) Option {
	return func(c *config) {
		c.tokenExchange = &oauth.TokenExchangeInfo{
			SubjectToken: subjectToken,
			Audience:     audience,
		}
	}
}

func WithExtraDialOptions(dialOptions ...grpc.DialOption) Option {
	return func(c *config) {
		c.extraDialOptions = dialOptions
	}
}
