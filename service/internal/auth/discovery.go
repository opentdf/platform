package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/opentdf/platform/service/logger"
)

const (
	// DiscoveryPath is the path to the discovery endpoint
	DiscoveryPath = "/.well-known/openid-configuration"
)

// OIDCConfiguration holds the openid configuration for the issuer.
// Currently only required fields are included (https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata),
// plus two CWT-related extension fields advertised by Arkavo-compatible IdPs.
type OIDCConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// AccessTokenFormat is the IANA media type of the issuer's access tokens.
	// Arkavo IdPs set this to "application/cwt" to signal that bearer tokens
	// are CWTs (RFC 8392) rather than JWTs. Extension field — not part of the
	// OIDC Discovery spec.
	AccessTokenFormat string `json:"access_token_format,omitempty"`

	// CoseKeysURI is the URL of the COSE Key Set used to verify CWT bearer
	// tokens (RFC 8392 / RFC 9052). Extension field — not part of the OIDC
	// Discovery spec. Empty when the IdP does not issue CWTs.
	CoseKeysURI string `json:"cose_keys_uri,omitempty"`
}

// DiscoverOPENIDConfiguration discovers the openid configuration for the issuer provided
func DiscoverOIDCConfiguration(ctx context.Context, issuer string, logger *logger.Logger) (*OIDCConfiguration, error) {
	logger.DebugContext(ctx, "discovering openid configuration", slog.String("issuer", issuer))
	discoveryURL, err := url.JoinPath(issuer, DiscoveryPath)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URL %q: %w", issuer, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to discover idp at %s: %s", discoveryURL, resp.Status)
	}
	defer resp.Body.Close()

	cfg := &OIDCConfiguration{}
	err = json.NewDecoder(resp.Body).Decode(&cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
