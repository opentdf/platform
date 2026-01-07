package sdk

import (
	"crypto/rsa"
	"crypto/tls"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/auth/oauth"
	"github.com/opentdf/platform/sdk/httputil"
	"golang.org/x/oauth2"
)

type Option func(*config)

type ConnectRPCConnection struct {
	Client   *http.Client
	Endpoint string
	Options  []connect.ClientOption
}

// Internal config struct for building SDK options.
type config struct {
	// Platform configuration structure is subject to change. Consume via accessor methods.
	PlatformConfiguration              PlatformConfiguration
	extraClientOptions                 []connect.ClientOption
	httpClient                         *http.Client
	clientCredentials                  *oauth.ClientCredentials
	tokenExchange                      *oauth.TokenExchangeInfo
	tokenEndpoint                      string
	scopes                             []string
	certExchange                       *oauth.CertExchangeInfo
	kasSessionKey                      *ocrypto.RsaKeyPair
	dpopKey                            *ocrypto.RsaKeyPair
	ipc                                bool
	tdfFeatures                        tdfFeatures
	customAccessTokenSource            auth.AccessTokenSource
	oauthAccessTokenSource             oauth2.TokenSource
	coreConn                           *ConnectRPCConnection
	entityResolutionConn               *ConnectRPCConnection
	shouldValidatePlatformConnectivity bool
	fulfillableObligationFQNs          []string
	logger                             *slog.Logger
}

// Options specific to TDF protocol features
type tdfFeatures struct {
	// For backward compatibility, don't store the KID in the KAO.
	noKID bool
}

type PlatformConfiguration map[string]interface{}

// WithInsecureSkipVerifyConn returns an Option that sets up HTTPS connection without verification.
func WithInsecureSkipVerifyConn() Option {
	return func(c *config) {
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // #nosec G402
		} // used by http client
		c.httpClient = httputil.SafeHTTPClientWithTLSConfig(tlsConfig)
	}
}

// WithInsecurePlaintextConn returns an Option that sets up HTTP connection sent in the clear.
func WithInsecurePlaintextConn() Option {
	return func(c *config) {
		// used by http client
		// FIXME anything to do here
		c.httpClient = httputil.SafeHTTPClient()
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
		c.certExchange = &oauth.CertExchangeInfo{HTTPClient: httputil.SafeHTTPClientWithTLSConfig(tls), Audience: audience}
	}
}

// WithTokenEndpoint When we implement service discovery using a .well-known endpoint this option may become deprecated
// Deprecated: SDK will discover the token endpoint from the platform configuration
func WithTokenEndpoint(tokenEndpoint string) Option {
	return func(c *config) {
		c.tokenEndpoint = tokenEndpoint
	}
}

func withCustomAccessTokenSource(a auth.AccessTokenSource) Option {
	return func(c *config) {
		c.customAccessTokenSource = a
	}
}

// WithOAuthAccessTokenSource directs the SDK to use a standard OAuth2 token source for authentication
func WithOAuthAccessTokenSource(t oauth2.TokenSource) Option {
	return func(c *config) {
		c.oauthAccessTokenSource = t
	}
}

// Deprecated: Use WithCustomCoreConnection instead
func WithCustomPolicyConnection(conn *ConnectRPCConnection) Option {
	return func(c *config) {
		c.coreConn = conn
	}
}

// Deprecated: Use WithCustomCoreConnection instead
func WithCustomAuthorizationConnection(conn *ConnectRPCConnection) Option {
	return func(c *config) {
		c.coreConn = conn
	}
}

func WithCustomEntityResolutionConnection(conn *ConnectRPCConnection) Option {
	return func(c *config) {
		c.entityResolutionConn = conn
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

// The session key pair is used to encrypt responses from KAS for a given session
// and can be reused across an entire session.
// Please use with caution.
func WithSessionEncryptionRSA(key *rsa.PrivateKey) Option {
	return func(c *config) {
		okey := ocrypto.FromRSA(key)
		c.kasSessionKey = &okey
	}
}

// The DPoP key pair is used to implement sender constrained tokens from the identity provider,
// and should be associated with the lifetime of a session for a given identity.
// Please use with caution.
func WithSessionSignerRSA(key *rsa.PrivateKey) Option {
	return func(c *config) {
		okey := ocrypto.FromRSA(key)
		c.dpopKey = &okey
	}
}

func WithCustomWellknownConnection(conn *ConnectRPCConnection) Option {
	return func(c *config) {
		c.coreConn = conn
	}
}

// WithPlatformConfiguration allows you to override the remote platform configuration
// Use this option with caution, as it may lead to unexpected behavior
func WithPlatformConfiguration(platformConfiguration PlatformConfiguration) Option {
	return func(c *config) {
		c.PlatformConfiguration = platformConfiguration
	}
}

// WithConnectionValidation will validate connection to a healthy, running platform
func WithConnectionValidation() Option {
	return func(c *config) {
		c.shouldValidatePlatformConnectivity = true
	}
}

// WithIPC returns an Option that indicates the SDK should use IPC for communication
// this will allow the platform endpoint to be an empty string
func WithIPC() Option {
	return func(c *config) {
		c.ipc = true
	}
}

// WithNoKIDInKAO disables storing the KID in the KAO. This allows generating
// TDF files that are compatible with legacy file formats (no KID).
func WithNoKIDInKAO() Option {
	return func(c *config) {
		c.tdfFeatures.noKID = true
	}
}

// WithCoreConnection returns an Option that sets up a connection to the core platform
func WithCustomCoreConnection(conn *ConnectRPCConnection) Option {
	return func(c *config) {
		c.coreConn = conn
	}
}

// WithExtraClientOptions returns an Option that adds extra connect rpc client options to the conect rpc clients
func WithExtraClientOptions(opts ...connect.ClientOption) Option {
	return func(c *config) {
		c.extraClientOptions = opts
	}
}

// WithFulfillableObligationFQNs sets the list of obligation FQNs that can
func WithFulfillableObligationFQNs(fqns []string) Option {
	return func(c *config) {
		c.fulfillableObligationFQNs = fqns
	}
}

// WithLogger returns an Option that sets a custom slog.Logger for all SDK logging.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		c.logger = logger
	}
}
