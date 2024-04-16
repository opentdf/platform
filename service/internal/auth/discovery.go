package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	// DiscoveryPath is the path to the discovery endpoint
	DiscoveryPath = "/.well-known/openid-configuration"
)

// OIDCConfiguration holds the openid configuration for the issuer.
// Currently only required fields are included (https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
type OIDCConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	RequireRequestURIRegistration    bool     `json:"require_request_uri_registration"`
}

// DiscoverOPENIDConfiguration discovers the openid configuration for the issuer provided
func DiscoverOIDCConfiguration(ctx context.Context, issuer string) (*OIDCConfiguration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s%s", issuer, DiscoveryPath), nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to discover idp at %s: %s", req.RequestURI, resp.Status)
	}
	defer resp.Body.Close()

	cfg := &OIDCConfiguration{}
	err = json.NewDecoder(resp.Body).Decode(&cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
