package oauth

import (
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
	"github.com/opentdf/platform/sdk/internal/crypto"
	"golang.org/x/oauth2"
)

type ClientCredentials struct {
	ClientAuth interface{} // the supported types for this are a JWK (implying jwt-bearer auth) or a string (implying client secret auth)
	ClientId   string
}

func getRequest(tokenEndpoint, dpopNonce string, scopes []string, clientCredentials ClientCredentials, privateJWK *jwk.Key) (*http.Request, error) {
	req, err := http.NewRequest("POST", tokenEndpoint, nil)
	if err != nil {
		return nil, err
	}
	dpop, err := getDPoPAssertion(*privateJWK, "POST", tokenEndpoint, dpopNonce)
	if err != nil {
		return nil, err
	}
	req.Header.Set("dpop", dpop)
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", clientCredentials.ClientId)
	if len(scopes) > 0 {
		formData.Set("scope", strings.Join(scopes, " "))
	}

	setClientAuth(clientCredentials, &formData, tokenEndpoint)

	req.Body = io.NopCloser(strings.NewReader(formData.Encode()))

	return req, nil
}

func setClientAuth(cc ClientCredentials, formData *url.Values, tokenEndpoint string) error {
	switch ca := cc.ClientAuth.(type) {
	case string:
		formData.Set("client_secret", ca)
	case jwk.Key:
		signedToken, err := getSignedToken(cc.ClientId, tokenEndpoint, ca)
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
	tok, err := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{tokenEndpoint}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		JwtID(uuid.NewString()).
		Build()
	if err != nil {
		slog.Error("failed to build assertion payload", slog.Any("error", err))
		return nil, err
	}
	headers := jws.NewHeaders()

	if key.KeyID() != "" {
		headers.Set("kid", key.KeyID())
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
func GetAccessToken(tokenEndpoint string, scopes []string, clientCredentials ClientCredentials, dpopPrivateKey jwk.Key) (*oauth2.Token, error) {
	req, err := getRequest(tokenEndpoint, "", scopes, clientCredentials, &dpopPrivateKey)
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
		nonceReq, err := getRequest(tokenEndpoint, nonceHeader, scopes, clientCredentials, &dpopPrivateKey)
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

func processResponse(resp *http.Response) (*oauth2.Token, error) {
	respBytes, err := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("got status %d when making request to IdP: %s", resp.StatusCode, string(respBytes))
	}

	if err != nil {
		return nil, fmt.Errorf("error reading bytes from response: %w", err)
	}

	var token *oauth2.Token
	if err := json.Unmarshal(respBytes, &token); err != nil {
		return nil, fmt.Errorf("error unmarshaling token from response: %w", err)
	}

	return token, nil
}

func getDPoPAssertion(dpopJWK jwk.Key, method string, endpoint string, nonce string) (string, error) {
	slog.Debug("Building DPoP Proof")
	publicKey, err := jwk.PublicKeyOf(dpopJWK)
	if err != nil {
		panic(err)
	}

	tokenBuilder := jwt.NewBuilder().
		Claim("jti", uuid.NewString()).
		Claim("htm", method).
		Claim("htu", endpoint).
		Claim("iat", time.Now().Unix()).
		Claim("exp", time.Now().Add(5*time.Minute).Unix())

	if nonce != "" {
		tokenBuilder.Claim("nonce", nonce)
	}

	token, err := tokenBuilder.Build()
	if err != nil {
		return "", err
	}

	//Protected headers
	headers := jws.NewHeaders()
	headers.Set("jwk", publicKey)
	headers.Set("typ", "dpop+jwt")

	var alg jwa.SignatureAlgorithm
	if err := alg.Accept(dpopJWK.Algorithm()); err != nil {
		return "", fmt.Errorf("error reading signature algorithm from JWK %s: %v", dpopJWK.Algorithm(), err)
	}

	opts := jwt.WithKey(alg, dpopJWK, jws.WithProtectedHeaders(headers))

	proof, err := jwt.Sign(token, opts)
	if err != nil {
		return "", fmt.Errorf("error signing DPoP JWT: %v", err)
	}

	return string(proof), nil
}

func ExchangeToken(clientCredentials ClientCredentials, tokenExchangeEndpoint, subjectToken, dpopPEM string) (*oauth2.Token, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", subjectToken)
	data.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	setClientAuth(clientCredentials, &data, tokenExchangeEndpoint)

	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest(http.MethodPost, tokenExchangeEndpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	certB64 := crypto.Base64Encode([]byte(dpopPEM))
	req.Header.Set("X-VirtruPubKey", string(certB64))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to exchange token: %w", err)
	}

	return processResponse(resp)
}
