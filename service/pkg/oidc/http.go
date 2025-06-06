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
	JWTAssertionExpiration = 5 * time.Minute
	DPoPExpirationTime     = 5 * time.Minute

	ErrGenDPoPECKey      = errors.New("failed to generate DPoP ECDSA key")
	ErrConvertECKey      = errors.New("failed to convert ECDSA key to JWK")
	ErrDPoPJWKNil        = errors.New("dpopJWK is nil")
	ErrDPoPNonceRequired = errors.New("nonce is required for DPoP proof")
)

type clientMode int

const (
	modeDefault clientMode = iota
	modeOAuthFlow
	modeDPoPResourceRequest
)

type DPoPHeaderFunc func(req *http.Request, jwkKey jwk.Key, endpoint, nonce string) error

type HTTPClient struct {
	*http.Client
	DPoPJWK                  jwk.Key
	mode                     clientMode
	attachDPoPHeaderOverride DPoPHeaderFunc // optional override for attachDPoPHeader
}

type HTTPRequestFactory struct {
	httpClient *HTTPClient
	endpoint   string

	// requestFactory generates a new *http.Request for each attempt.
	requestFactory func() (*http.Request, error)
}

type HTTPClientOption func(*HTTPClient) error

func WithDPoPKey(dpopJWK jwk.Key) HTTPClientOption {
	return func(c *HTTPClient) error {
		if dpopJWK == nil {
			return errors.New("DPoP key cannot be nil")
		}
		c.DPoPJWK = dpopJWK
		return nil
	}
}

func WithGeneratedDPoPKey() HTTPClientOption {
	return func(c *HTTPClient) error {
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
		c.DPoPJWK = jwkKey
		return nil
	}
}

func WithOAuthFlow() HTTPClientOption {
	return func(c *HTTPClient) error {
		c.mode = modeOAuthFlow
		return nil
	}
}

// Option to override attachDPoPHeader (for testing)
func WithAttachDPoPHeaderOverride(f DPoPHeaderFunc) HTTPClientOption {
	return func(c *HTTPClient) error {
		c.attachDPoPHeaderOverride = f
		return nil
	}
}

func NewHTTPClient(client *http.Client, options ...HTTPClientOption) (*HTTPClient, error) {
	if client == nil {
		client = &http.Client{}
	}
	c := &HTTPClient{Client: client, mode: modeDefault}

	for _, opt := range options {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (f *HTTPRequestFactory) Do() (*http.Response, error) {
	req, err := f.requestFactory()
	if err != nil {
		return nil, err
	}

	// No DPoP: just send the request
	if f.httpClient.DPoPJWK == nil {
		return f.httpClient.Do(req)
	}

	// DPoP is enabled: attach header and send request
	if err := f.httpClient.attachDPoPHeader(req, f.httpClient.DPoPJWK, f.endpoint, ""); err != nil {
		return nil, fmt.Errorf("failed to attach DPoP header: %w", err)
	}
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return resp, err
	}

	// Check for DPoP nonce error (400 Bad Request)
	nonce := resp.Header.Get("DPoP-Nonce")
	if resp.StatusCode == http.StatusBadRequest && nonce != "" {
		resp.Body.Close()
		reqWithNonce, err := f.requestFactory()
		if err != nil {
			return nil, err
		}
		if err := f.httpClient.attachDPoPHeader(reqWithNonce, f.httpClient.DPoPJWK, f.endpoint, nonce); err != nil {
			return nil, fmt.Errorf("failed to attach DPoP header: %w", err)
		}
		return f.httpClient.Do(reqWithNonce)
	}
	return resp, err
}

type OAuthFormRequest interface {
	Do() (*http.Response, error)
}

func (c *HTTPClient) NewOAuthFormRequest(ctx context.Context, key jwk.Key, endpoint string, params OAuthFormParams) *HTTPRequestFactory {
	return &HTTPRequestFactory{
		httpClient: c,
		endpoint:   endpoint,
		requestFactory: func() (*http.Request, error) {
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

type ResourceRequest interface {
	Do() (*http.Response, error)
}

func (c *HTTPClient) NewResourceRequest(ctx context.Context, userInfoEndpoint, tokenRaw string) ResourceRequest {
	return &HTTPRequestFactory{
		httpClient: c,
		requestFactory: func() (*http.Request, error) {
			if c.mode != modeDPoPResourceRequest {
				panic("NewResourceRequestFactory called in non-resource-request mode; use WithDPoPResourceRequest when constructing httpClient for resource/userinfo requests")
			}
			dpopJWK := c.DPoPJWK
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoEndpoint, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create userinfo request: %w", err)
			}
			if dpopJWK != nil {
				req.Header.Set("Authorization", "DPoP "+tokenRaw)
				if err := c.attachDPoPHeader(req, dpopJWK, userInfoEndpoint, ""); err != nil {
					return nil, fmt.Errorf("failed to attach DPoP header: %w", err)
				}
			} else {
				req.Header.Set("Authorization", "Bearer "+tokenRaw)
			}
			return req, nil
		},
	}
}

func (c *HTTPClient) attachDPoPHeader(req *http.Request, jwkKey jwk.Key, endpoint, nonce string) error {
	if c.attachDPoPHeaderOverride != nil {
		return c.attachDPoPHeaderOverride(req, jwkKey, endpoint, nonce)
	}
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

func (c *HTTPClient) buildSignedJWTAssertion(key jwk.Key, clientID, endpoint string) (string, error) {
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
