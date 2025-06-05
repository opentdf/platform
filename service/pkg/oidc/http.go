package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	DPoPExpirationTime = 5 * time.Minute

	ErrGenDPoPECKey      = errors.New("failed to generate DPoP ECDSA key")
	ErrConvertECKey      = errors.New("failed to convert ECDSA key to JWK")
	ErrDPoPJWKNil        = errors.New("dpopJWK is nil")
	ErrDPoPNonceRequired = errors.New("nonce is required for DPoP proof")
)

type httpClient struct {
	*http.Client
	dpopJWK jwk.Key
}

type httpRequestFactory struct {
	httpClient *httpClient

	// requestFactory generates a new *http.Request for each attempt. The string parameter is for internal use (e.g., DPoP nonce).
	requestFactory func(string) (*http.Request, error)
}

type httpClientOption func(*httpClient) error

func WithDPoPKey(dpopJWK jwk.Key) httpClientOption {
	return func(c *httpClient) error {
		if dpopJWK == nil {
			return fmt.Errorf("DPoP key cannot be nil")
		}
		c.dpopJWK = dpopJWK
		return nil
	}
}

func WithGeneratedDPoPKey() httpClientOption {
	return func(c *httpClient) error {
		var err error
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return ErrGenDPoPECKey
		}
		jwkKey, err := jwk.FromRaw(ecdsaKey)
		if err != nil {
			return ErrConvertECKey
		}
		if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
			return err
		}
		c.dpopJWK = jwkKey
		return nil
	}
}

func NewHTTPClient(client *http.Client, options ...httpClientOption) (*httpClient, error) {
	if client == nil {
		client = &http.Client{}
	}
	c := &httpClient{Client: client}

	for _, opt := range options {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// NewOAuthFormRequestFactory creates a factory for OAuth form requests.
func (c *httpClient) NewOAuthFormRequestFactory(ctx context.Context, key jwk.Key, endpoint string, params OAuthFormParams) *httpRequestFactory {
	return &httpRequestFactory{
		httpClient: c,
		requestFactory: func(nonce string) (*http.Request, error) {
			// Always copy params to avoid mutating the original and to ensure a fresh JWT per request
			localParams := params
			jwtAssertion, err := c.buildSignedJWTAssertion(key, localParams.ClientID, endpoint)
			if err != nil {
				return nil, fmt.Errorf("failed to build signed JWT assertion: %w", err)
			}
			localParams.ClientAssertion = jwtAssertion
			form := BuildOAuthForm(localParams)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
			if err != nil {
				return nil, fmt.Errorf("failed to create token request: %w", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return req, nil
		},
	}
}

// Do executes a request, automatically handling DPoP nonce retry if dpopJWK is set.
func (f *httpRequestFactory) Do(endpoint string) (*http.Response, error) {
	req, err := f.requestFactory("")
	if err != nil {
		return nil, err
	}

	// No DPoP: just send the request
	if f.httpClient.dpopJWK == nil {
		return f.httpClient.Do(req)
	}

	// DPoP is enabled: attach header and send request
	if err := f.httpClient.attachDPoPHeader(req, f.httpClient.dpopJWK, endpoint, ""); err != nil {
		return nil, fmt.Errorf("failed to attach DPoP header: %w", err)
	}
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return resp, err
	}

	// Check for DPoP nonce error (400 Bad Request)
	nonce := resp.Header.Get("DPoP-Nonce")
	if resp.StatusCode == 400 && nonce != "" {
		resp.Body.Close()
		req, err := f.requestFactory(nonce)
		if err != nil {
			return nil, err
		}
		if err := f.httpClient.attachDPoPHeader(req, f.httpClient.dpopJWK, endpoint, nonce); err != nil {
			return nil, fmt.Errorf("failed to attach DPoP header: %w", err)
		}
		return f.httpClient.Do(req)
	}
	return resp, err
}

func (c *httpClient) attachDPoPHeader(req *http.Request, jwkKey jwk.Key, endpoint, nonce string) error {
	if jwkKey == nil {
		return ErrDPoPJWKNil
	}

	publicKey, err := jwk.PublicKeyOf(jwkKey)
	if err != nil {
		return err
	}

	tokenBuilder := jwt.NewBuilder().
		Claim("jti", uuid.NewString()).
		Claim("htm", http.MethodPost).
		Claim("htu", endpoint).
		Claim("iat", time.Now().Unix()).
		Claim("exp", time.Now().Add(DPoPExpirationTime).Unix())

	if nonce != "" {
		tokenBuilder.Claim("nonce", nonce)
	}

	token, err := tokenBuilder.Build()
	if err != nil {
		return err
	}

	headers := jws.NewHeaders()
	err = headers.Set("jwk", publicKey)
	if err != nil {
		return err
	}
	err = headers.Set("typ", "dpop+jwt")
	if err != nil {
		return err
	}

	alg := jwkKey.Algorithm()
	if alg == nil {
		alg = jwa.ES256 // Default to ES256 if not set
	}

	proof, err := jwt.Sign(token, jwt.WithKey(alg, jwkKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return err
	}

	req.Header.Set("DPoP", string(proof))
	return nil
}

func (c *httpClient) buildSignedJWTAssertion(key jwk.Key, clientID, endpoint string) (string, error) {
	// Create JWT assertion for private_key_jwt
	now := time.Now()
	jwtBuilder := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{endpoint}).
		IssuedAt(now).
		Expiration(now.Add(JWTAssertionExpiration)).
		JwtID(uuid.NewString())
	jwtAssertion, err := jwtBuilder.Build()
	if err != nil {
		return "", fmt.Errorf("failed to build private_key_jwt assertion: %w", err)
	}

	// Sign assertion with the provided key
	kid, _ := key.Get("kid")
	headers := jws.NewHeaders()
	_ = headers.Set(jws.AlgorithmKey, jwa.RS256)
	if kid != nil {
		_ = headers.Set(jws.KeyIDKey, kid)
	}
	signedJWT, err := jwt.Sign(jwtAssertion, jwt.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("failed to sign private_key_jwt assertion: %w", err)
	}
	return string(signedJWT), nil
}
