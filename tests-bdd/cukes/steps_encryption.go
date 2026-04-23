package cukes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	otdf "github.com/opentdf/platform/sdk"
	"golang.org/x/oauth2"
)

const (
	// Admin client used for both the platform SDK and as the exchanger in
	// RFC 8693 user-impersonation token exchange. keycloak_base.template
	// grants its service account the `impersonation` role on
	// realm-management so it may obtain user-scoped tokens.
	exchangeClientID     = "opentdf"
	exchangeClientSecret = "secret"
	// Target audience of the exchanged token; matches the token_exchanges
	// policy wired in keycloak_base.template (start_client: opentdf,
	// target_client: opentdf-sdk).
	exchangeTargetClientID = "opentdf-sdk"
	// Standard OAuth grant-type and token-type URNs from RFC 8693 — not credentials.
	tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // URN identifier, not a credential
	accessTokenType    = "urn:ietf:params:oauth:token-type:access_token"   //nolint:gosec // URN identifier, not a credential

	tokenEndpointTimeout = 10 * time.Second
)

// decryptResult captures whether a decrypt attempt succeeded, and if not,
// whether it was denied (rewrap forbidden) or failed for another reason.
type decryptResult struct {
	plaintext []byte
	err       error
	denied    bool
}

type EncryptionStepDefinitions struct{}

// userTokenForStoredAs mints a user-scoped SDK via RFC 8693 token exchange:
// the admin client authenticates with client_credentials, then exchanges
// that token for one representing the target user. Stashes the resulting
// SDK under the given reference key.
func (s *EncryptionStepDefinitions) userTokenForStoredAs(ctx context.Context, username, ref string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	localPlatformGlue, ok := (*scenarioContext.TestSuiteContext.PlatformGlue).(*LocalDevPlatformGlue)
	if !ok {
		return ctx, errors.New("failed to load local platform glue")
	}

	kcHostPort := net.JoinHostPort(localPlatformGlue.Options.Hostname, strconv.Itoa(localPlatformGlue.Options.keycloakPort))
	tokenURL := fmt.Sprintf("http://%s/auth/realms/%s/protocol/openid-connect/token",
		kcHostPort,
		scenarioContext.ScenarioOptions.KeycloakRealm,
	)

	adminToken, err := fetchAdminAccessToken(ctx, tokenURL)
	if err != nil {
		return ctx, fmt.Errorf("fetch admin token for exchange: %w", err)
	}
	token, err := exchangeForUserToken(ctx, tokenURL, adminToken.AccessToken, username)
	if err != nil {
		return ctx, fmt.Errorf("exchange admin token for user %q: %w", username, err)
	}

	userSDK, err := otdf.New(
		scenarioContext.ScenarioOptions.PlatformEndpoint,
		otdf.WithInsecureSkipVerifyConn(),
		otdf.WithOAuthAccessTokenSource(oauth2.StaticTokenSource(token)),
	)
	if err != nil {
		return ctx, fmt.Errorf("build user SDK for %q: %w", username, err)
	}
	scenarioContext.RecordObject(ref, userSDK)
	return ctx, nil
}

// encryptPlaintextStoredAs encrypts the given text using the admin SDK, binds
// it to the comma-separated attribute FQNs, and stashes the resulting TDF bytes
// under the given reference key. The platform's own KAS is used as the default;
// its public key is fetched on demand by the SDK.
func (s *EncryptionStepDefinitions) encryptPlaintextStoredAs(ctx context.Context, plaintext, attributeFQNs, ref string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	fqns := splitAndTrim(attributeFQNs, ",")

	kasURL := scenarioContext.ScenarioOptions.PlatformEndpoint
	var tdfBuf bytes.Buffer
	_, err := scenarioContext.SDK.CreateTDFContext(
		ctx,
		&tdfBuf,
		strings.NewReader(plaintext),
		otdf.WithKasInformation(otdf.KASInfo{URL: kasURL, Default: true}),
		otdf.WithDataAttributes(fqns...),
	)
	if err != nil {
		return ctx, fmt.Errorf("encrypt: %w", err)
	}
	scenarioContext.RecordObject(ref, tdfBuf.Bytes())
	return ctx, nil
}

// userDecryptsStoredAs pulls the user SDK and TDF bytes from scenario state,
// attempts decrypt, and stashes a decryptResult under the plaintext ref.
func (s *EncryptionStepDefinitions) userDecryptsStoredAs(ctx context.Context, tokenRef, tdfRef, plainRef string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)

	userSDKAny := scenarioContext.GetObject(tokenRef)
	userSDK, ok := userSDKAny.(*otdf.SDK)
	if !ok || userSDK == nil {
		return ctx, fmt.Errorf("no user SDK stored under %q; did you run `a user token for ... stored as %q`?", tokenRef, tokenRef)
	}

	tdfBytesAny := scenarioContext.GetObject(tdfRef)
	tdfBytes, ok := tdfBytesAny.([]byte)
	if !ok {
		return ctx, fmt.Errorf("no TDF bytes stored under %q", tdfRef)
	}

	reader, err := userSDK.LoadTDF(bytes.NewReader(tdfBytes))
	if err != nil {
		scenarioContext.RecordObject(plainRef, &decryptResult{err: err, denied: errors.Is(err, otdf.ErrRewrapForbidden)})
		return ctx, nil
	}

	var plainBuf bytes.Buffer
	if _, err := io.Copy(&plainBuf, reader); err != nil {
		scenarioContext.RecordObject(plainRef, &decryptResult{err: err, denied: errors.Is(err, otdf.ErrRewrapForbidden)})
		return ctx, nil
	}
	scenarioContext.RecordObject(plainRef, &decryptResult{plaintext: plainBuf.Bytes()})
	return ctx, nil
}

func (s *EncryptionStepDefinitions) decryptionShouldSucceedWithPlaintext(ctx context.Context, plainRef, expected string) (context.Context, error) {
	result, err := getDecryptResult(ctx, plainRef)
	if err != nil {
		return ctx, err
	}
	if result.err != nil {
		return ctx, fmt.Errorf("decryption %q failed: %w", plainRef, result.err)
	}
	if got := string(result.plaintext); got != expected {
		return ctx, fmt.Errorf("decryption %q plaintext mismatch: got %q, want %q", plainRef, got, expected)
	}
	return ctx, nil
}

func (s *EncryptionStepDefinitions) decryptionShouldBeDenied(ctx context.Context, plainRef string) (context.Context, error) {
	result, err := getDecryptResult(ctx, plainRef)
	if err != nil {
		return ctx, err
	}
	if result.err == nil {
		return ctx, fmt.Errorf("decryption %q unexpectedly succeeded (plaintext: %q)", plainRef, string(result.plaintext))
	}
	if !result.denied {
		return ctx, fmt.Errorf("decryption %q failed but not with access-denied: %w", plainRef, result.err)
	}
	return ctx, nil
}

func getDecryptResult(ctx context.Context, ref string) (*decryptResult, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	v := scenarioContext.GetObject(ref)
	if v == nil {
		return nil, fmt.Errorf("no decryption result stored under %q", ref)
	}
	result, ok := v.(*decryptResult)
	if !ok {
		return nil, fmt.Errorf("object stored under %q is not a decryptResult (%T)", ref, v)
	}
	return result, nil
}

// fetchAdminAccessToken mints an admin service-account token via the
// client_credentials grant against the exchange client.
func fetchAdminAccessToken(ctx context.Context, tokenURL string) (*oauth2.Token, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {exchangeClientID},
		"client_secret": {exchangeClientSecret},
	}
	return postForTokenEndpoint(ctx, tokenURL, form, "client_credentials")
}

// exchangeForUserToken takes a valid admin token and asks Keycloak for a
// user-scoped token via RFC 8693 token exchange with `requested_subject`.
// Requires the exchange client to have the realm-management `impersonation`
// role. `audience` routes the exchange through the opentdf->opentdf-sdk
// policy configured in keycloak_base.template so the returned token is
// minted for opentdf-sdk, matching the SDK's own token-exchange flow
// (see sdk/auth/oauth/oauth.go).
func exchangeForUserToken(ctx context.Context, tokenURL, adminAccessToken, username string) (*oauth2.Token, error) {
	form := url.Values{
		"grant_type":           {tokenExchangeGrant},
		"client_id":            {exchangeClientID},
		"client_secret":        {exchangeClientSecret},
		"subject_token":        {adminAccessToken},
		"subject_token_type":   {accessTokenType},
		"requested_token_type": {accessTokenType},
		"audience":             {exchangeTargetClientID},
		"requested_subject":    {username},
	}
	return postForTokenEndpoint(ctx, tokenURL, form, "token-exchange")
}

// postForTokenEndpoint POSTs a token-endpoint form and decodes the standard
// access_token response.
func postForTokenEndpoint(ctx context.Context, tokenURL string, form url.Values, kind string) (*oauth2.Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := &http.Client{Timeout: tokenEndpointTimeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: token endpoint returned %d: %s", kind, resp.StatusCode, string(body))
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%s: decode token response: %w", kind, err)
	}
	if payload.AccessToken == "" {
		return nil, fmt.Errorf("%s: token endpoint response missing access_token", kind)
	}
	return &oauth2.Token{
		AccessToken: payload.AccessToken,
		TokenType:   payload.TokenType,
		Expiry:      time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second),
	}, nil
}

func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func RegisterEncryptionStepDefinitions(ctx *godog.ScenarioContext) {
	stepDefs := EncryptionStepDefinitions{}
	ctx.Step(`^a user token for "([^"]*)" stored as "([^"]*)"$`, stepDefs.userTokenForStoredAs)
	ctx.Step(`^I encrypt plaintext "([^"]*)" with attributes "([^"]*)" stored as "([^"]*)"$`, stepDefs.encryptPlaintextStoredAs)
	ctx.Step(`^using token "([^"]*)", decrypt "([^"]*)" stored as "([^"]*)"$`, stepDefs.userDecryptsStoredAs)
	ctx.Step(`^the decryption stored as "([^"]*)" should succeed with plaintext "([^"]*)"$`, stepDefs.decryptionShouldSucceedWithPlaintext)
	ctx.Step(`^the decryption stored as "([^"]*)" should be denied$`, stepDefs.decryptionShouldBeDenied)
}
