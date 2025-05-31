package oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

// For testing purposes only
var skipValidation = false

// SetSkipValidationForTest sets the skipValidation flag for testing
// This should only be used in tests
func SetSkipValidationForTest(skip bool) {
	skipValidation = skip
}

// ValidateClientCredentials checks if the provided client credentials are valid by making a request to the token endpoint
func ValidateClientCredentials(ctx context.Context, issuer, clientID, clientSecret string, tlsNoVerify bool, timeout time.Duration) error {
	// Skip validation if flag is set (for testing)
	if skipValidation {
		return nil
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				//nolint:gosec // skip tls verification allowed if requested
				InsecureSkipVerify: tlsNoVerify,
			},
		},
		Timeout: timeout,
	}
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, issuer, clientID, clientSecret, "", nil, rp.WithHTTPClient(httpClient))
	if err != nil {
		return fmt.Errorf("failed to create OIDC client: %w", err)
	}
	tok, err := rp.ClientCredentials(ctx, relyingParty, nil)
	if err != nil {
		return fmt.Errorf("failed to obtain client credentials: %w", err)
	}
	if tok == nil || tok.AccessToken == "" {
		return errors.New("invalid client credentials: no access token received")
	}
	return nil
}
