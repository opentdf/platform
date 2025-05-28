package oidc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/zitadel/oidc/v3/pkg/client/tokenexchange"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// ExchangeToken performs OAuth2 token exchange (RFC 8693) using Zitadel's OIDC library.
// actorToken and actorTokenType may be empty if not used.
func ExchangeToken(ctx context.Context, issuer, clientID, clientSecret, subjectToken string) (string, error) {
	// Create a logger for debugging
	logger := log.New(os.Stderr, "[TOKEN_EXCHANGE] ", log.LstdFlags)
	logger.Printf("Starting token exchange: issuer=%s, clientID=%s", issuer, clientID)

	// Create a debug client with a custom transport that logs requests and responses
	httpClient := &http.Client{
		Timeout: 30 * 1e9, // 30 seconds
	}

	// Create the token exchanger with our debug client
	te, err := tokenexchange.NewTokenExchangerClientCredentials(
		ctx,
		issuer,
		clientID,
		clientSecret,
		tokenexchange.WithHTTPClient(httpClient),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create token exchanger: %w", err)
	}

	// Not needed for client credentials flow
	actorToken := ""
	actorTokenType := ""

	resource := []string{}
	audience := []string{clientID}
	// Always include "openid" scope for UserInfo requests to work properly with Keycloak
	scopes := []string{"openid", "profile"}

	resp, err := tokenexchange.ExchangeToken(
		ctx,
		te,
		subjectToken,
		oidc.AccessTokenType,
		actorToken,
		oidc.TokenType(actorTokenType),
		resource,
		audience,
		scopes,
		oidc.AccessTokenType,
	)
	if err != nil {
		logger.Printf("Token exchange failed: %v", err)
		return "", fmt.Errorf("token exchange failed: %w", err)
	}
	if resp == nil || resp.AccessToken == "" {
		logger.Printf("No access token in token exchange response")
		return "", errors.New("no access_token in token exchange response")
	}

	logger.Printf("Token exchange successful: scope=%v", resp.Scopes)
	return resp.AccessToken, nil
}
