package cukes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"
	otdf "github.com/opentdf/platform/sdk"
	"golang.org/x/oauth2"
)

const (
	defaultUserPassword = "testuser123" // matches aUser step in steps_localplatform.go and sample-user in keycloak_base.template
	ropcClientID        = "opentdf-sdk" // confidential client; direct-access-grants enabled by default on confidential clients in Keycloak
	ropcClientSecret    = "secret"      // matches keycloak_base.template
)

// decryptResult captures whether a decrypt attempt succeeded, and if not,
// whether it was denied (rewrap forbidden) or failed for another reason.
type decryptResult struct {
	plaintext []byte
	err       error
	denied    bool
}

type EncryptionStepDefinitions struct{}

// userTokenForStoredAs mints a user-scoped SDK via Keycloak ROPC (password grant)
// against the public cli-client and stashes it under the given reference key.
func (s *EncryptionStepDefinitions) userTokenForStoredAs(ctx context.Context, username, ref string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	localPlatformGlue, ok := (*scenarioContext.TestSuiteContext.PlatformGlue).(*LocalDevPlatformGlue)
	if !ok {
		return ctx, errors.New("failed to load local platform glue")
	}

	token, err := fetchUserAccessToken(ctx,
		localPlatformGlue.Options.Hostname,
		localPlatformGlue.Options.keycloakPort,
		scenarioContext.ScenarioOptions.KeycloakRealm,
		username,
		defaultUserPassword,
	)
	if err != nil {
		return ctx, fmt.Errorf("fetch user token for %q: %w", username, err)
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

// fetchUserAccessToken performs a Keycloak ROPC (password) grant against the
// public cli-client and returns the resulting access token as an oauth2.Token.
func fetchUserAccessToken(ctx context.Context, hostname string, kcPort int, realm, username, password string) (*oauth2.Token, error) {
	tokenURL := fmt.Sprintf("http://%s:%d/auth/realms/%s/protocol/openid-connect/token", hostname, kcPort, realm)
	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {ropcClientID},
		"client_secret": {ropcClientSecret},
		"username":      {username},
		"password":      {password},
		"scope":         {"openid"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := &http.Client{Timeout: 10 * time.Second}
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
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if payload.AccessToken == "" {
		return nil, errors.New("token endpoint response missing access_token")
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
