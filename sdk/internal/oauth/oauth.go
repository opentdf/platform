package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	tokenExpirationBuffer = 10 * time.Second
)

type CertExchangeInfo struct {
	TLSConfig *tls.Config
	Audience  []string
}

type ClientCredentials struct {
	ClientAuth interface{} // the supported types for this are a JWK (implying jwt-bearer auth) or a string (implying client secret auth)
	ClientID   string
}

type TokenExchangeInfo struct {
	SubjectToken string
	Audience     []string
}

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`
	received    time.Time
}

func (t Token) Expired() bool {
	if t.ExpiresIn == 0 {
		return false
	}

	expirationTime := t.received.Add(time.Second * time.Duration(t.ExpiresIn))

	return time.Now().After(expirationTime.Add(-tokenExpirationBuffer))
}

func getAccessTokenRequest(tokenEndpoint, dpopNonce string, scopes []string, clientCredentials ClientCredentials, privateJWK *jwk.Key) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, nil) //nolint: noctx // TODO(#455): AccessToken methods should take contexts
	if err != nil {
		return nil, err
	}
	dpop, err := getDPoPAssertion(*privateJWK, http.MethodPost, tokenEndpoint, dpopNonce)
	if err != nil {
		return nil, err
	}
	req.Header.Set("dpop", dpop)
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", clientCredentials.ClientID)
	if len(scopes) > 0 {
		formData.Set("scope", strings.Join(scopes, " "))
	}

	err = setClientAuth(clientCredentials, &formData, req, tokenEndpoint)
	if err != nil {
		return nil, err
	}

	req.Body = io.NopCloser(strings.NewReader(formData.Encode()))

	return req, nil
}

func setClientAuth(cc ClientCredentials, formData *url.Values, req *http.Request, tokenEndpoint string) error {
	switch ca := cc.ClientAuth.(type) {
	case string:
		req.SetBasicAuth(cc.ClientID, ca)
	case jwk.Key:
		signedToken, err := getSignedToken(cc.ClientID, tokenEndpoint, ca)
		if err != nil {
			return fmt.Errorf("error building signed auth token to authenticate with IDP: %w", err)
		}
		formData.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		formData.Set("client_assertion", string(signedToken))
	default:
		return fmt.Errorf("unsupported type for ClientAuth: %T", ca)
	}

	return nil
}

func getSignedToken(clientID, tokenEndpoint string, key jwk.Key) ([]byte, error) {
	const tokenExpiration = 5 * time.Minute

	tok, err := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{tokenEndpoint}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(tokenExpiration)).
		JwtID(uuid.NewString()).
		Build()
	if err != nil {
		slog.Error("failed to build assertion payload", slog.Any("error", err))
		return nil, err
	}
	headers := jws.NewHeaders()

	if key.KeyID() != "" {
		err = headers.Set("kid", key.KeyID())
		if err != nil {
			return nil, fmt.Errorf("jws field invalid [kid]: %w", err)
		}
	}

	alg := key.Algorithm()
	if alg == nil {
		slog.Warn("using RS256 as the IDP key algorithm wasn't specified. To use another algorithm set the algorithm on the key")
		alg = jwa.RS256
	}

	return jwt.Sign(tok, jwt.WithKey(alg, key, jws.WithProtectedHeaders(headers)))
}

// this misses the flow where the Authorization server can tell us the next nonce to use.
// missing this flow costs us a bit in efficiency (a round trip per access token) but this is
// still correct because
func GetAccessToken(tokenEndpoint string, scopes []string, clientCredentials ClientCredentials, dpopPrivateKey jwk.Key) (*Token, error) {
	req, err := getAccessTokenRequest(tokenEndpoint, "", scopes, clientCredentials, &dpopPrivateKey)
	if err != nil {
		return nil, err
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to IdP with dpop nonce: %w", err)
	}

	defer resp.Body.Close()

	if nonceHeader := resp.Header.Get("dpop-nonce"); nonceHeader != "" && resp.StatusCode == http.StatusBadRequest {
		nonceReq, err := getAccessTokenRequest(tokenEndpoint, nonceHeader, scopes, clientCredentials, &dpopPrivateKey)
		if err != nil {
			return nil, err
		}
		nonceResp, err := client.Do(nonceReq)
		if err != nil {
			return nil, fmt.Errorf("error making request to IdP with dpop nonce: %w", err)
		}

		defer nonceResp.Body.Close()

		return processResponse(nonceResp)
	}

	return processResponse(resp)
}

func processResponse(resp *http.Response) (*Token, error) {
	respBytes, err := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("got status %d when making request to IdP: %s", resp.StatusCode, string(respBytes))
	}

	if err != nil {
		return nil, fmt.Errorf("error reading bytes from response: %w", err)
	}

	var token *Token
	if err := json.Unmarshal(respBytes, &token); err != nil {
		return nil, fmt.Errorf("error unmarshaling token from response: %w", err)
	}

	token.received = time.Now()

	return token, nil
}

func getDPoPAssertion(dpopJWK jwk.Key, method string, endpoint string, nonce string) (string, error) {
	slog.Debug("Building DPoP Proof")
	publicKey, err := jwk.PublicKeyOf(dpopJWK)
	const expirationTime = 5 * time.Minute

	if err != nil {
		panic(err)
	}

	tokenBuilder := jwt.NewBuilder().
		Claim("jti", uuid.NewString()).
		Claim("htm", method).
		Claim("htu", endpoint).
		Claim("iat", time.Now().Unix()).
		Claim("exp", time.Now().Add(expirationTime).Unix())

	if nonce != "" {
		tokenBuilder.Claim("nonce", nonce)
	}

	token, err := tokenBuilder.Build()
	if err != nil {
		return "", err
	}

	// Protected headers
	headers := jws.NewHeaders()
	err = headers.Set("jwk", publicKey)
	if err != nil {
		return "", fmt.Errorf("jws field invalid [jwk]: %w", err)
	}

	err = headers.Set("typ", "dpop+jwt")
	if err != nil {
		return "", fmt.Errorf("jws field invalid [typ]: %w", err)
	}

	var alg jwa.SignatureAlgorithm
	if err := alg.Accept(dpopJWK.Algorithm()); err != nil {
		return "", fmt.Errorf("error reading signature algorithm from JWK %s: %w", dpopJWK.Algorithm(), err)
	}

	opts := jwt.WithKey(alg, dpopJWK, jws.WithProtectedHeaders(headers))

	proof, err := jwt.Sign(token, opts)
	if err != nil {
		return "", fmt.Errorf("error signing DPoP JWT: %w", err)
	}

	return string(proof), nil
}

func DoTokenExchange(ctx context.Context, tokenEndpoint string, scopes []string, clientCredentials ClientCredentials, tokenExchange TokenExchangeInfo, key jwk.Key) (*Token, error) {
	req, err := getTokenExchangeRequest(ctx, tokenEndpoint, "", scopes, clientCredentials, tokenExchange, &key)
	if err != nil {
		return nil, err
	}
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to IdP for token exchange: %w", err)
	}
	defer resp.Body.Close()

	if nonceHeader := resp.Header.Get("dpop-nonce"); nonceHeader != "" && resp.StatusCode == http.StatusBadRequest {
		nonceReq, err := getTokenExchangeRequest(ctx, tokenEndpoint, nonceHeader, scopes, clientCredentials, tokenExchange, &key)
		if err != nil {
			return nil, err
		}
		nonceResp, err := client.Do(nonceReq)
		if err != nil {
			return nil, fmt.Errorf("error making request to IdP with dpop nonce: %w", err)
		}

		defer nonceResp.Body.Close()

		return processResponse(nonceResp)
	}

	return processResponse(resp)
}

func getTokenExchangeRequest(ctx context.Context, tokenEndpoint, dpopNonce string, scopes []string, clientCredentials ClientCredentials, tokenExchange TokenExchangeInfo, privateJWK *jwk.Key) (*http.Request, error) {
	data := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {tokenExchange.SubjectToken},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}

	for _, a := range tokenExchange.Audience {
		data.Add("audience", a)
	}

	if len(scopes) > 0 {
		data.Set("scopes", strings.Join(scopes, " "))
	}

	body := strings.NewReader(data.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, body)
	if err != nil {
		return nil, fmt.Errorf("error getting HTTP request: %w", err)
	}
	dpop, err := getDPoPAssertion(*privateJWK, http.MethodPost, tokenEndpoint, dpopNonce)
	if err != nil {
		return nil, err
	}
	req.Header.Set("dpop", dpop)
	req.Header.Set("accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err = setClientAuth(clientCredentials, &data, req, tokenEndpoint)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func DoCertExchange(ctx context.Context, tokenEndpoint string, exchangeInfo CertExchangeInfo, clientCredentials ClientCredentials, key jwk.Key) (*Token, error) {
	req, err := getCertExchangeRequest(ctx, tokenEndpoint, clientCredentials, exchangeInfo, key)
	if err != nil {
		return nil, err
	}
	client := http.Client{Transport: &http.Transport{TLSClientConfig: exchangeInfo.TLSConfig}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to IdP for certificate exchange: %w", err)
	}
	defer resp.Body.Close()

	return processResponse(resp)
}

func getCertExchangeRequest(ctx context.Context, tokenEndpoint string, clientCredentials ClientCredentials, exchangeInfo CertExchangeInfo, key jwk.Key) (*http.Request, error) {
	data := url.Values{"grant_type": {"password"}, "client_id": {clientCredentials.ClientID}, "username": {""}, "password": {""}}

	for _, a := range exchangeInfo.Audience {
		data.Add("audience", a)
	}

	body := strings.NewReader(data.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, body)
	if err != nil {
		return nil, err
	}

	dpop, err := getDPoPAssertion(key, http.MethodPost, tokenEndpoint, "")
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("dpop", dpop)
	if err = setClientAuth(clientCredentials, &data, req, tokenEndpoint); err != nil {
		return nil, err
	}

	return req, nil
}
