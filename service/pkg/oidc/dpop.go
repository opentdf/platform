package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	DPoPExpirationTime = 5 * time.Minute

	ErrDPoPJWKNil        = errors.New("dpopJWK is nil")
	ErrDPoPNonceRequired = errors.New("nonce is required for DPoP proof")
	ErrGenDPoPECKey      = errors.New("failed to generate DPoP EC key")
	ErrConvertECKey      = errors.New("failed to convert EC key to JWK")
)

// GetDPoPProof generates a DPoP proof for the given endpoint and nonce using the provided JWK key.
// This is a wrapper for getDPoPAssertion to make DPoP logic reusable.
func GetDPoPProof(jwkKey jwk.Key, endpoint, nonce string) (string, error) {
	if jwkKey == nil {
		return "", ErrDPoPJWKNil
	}

	publicKey, err := jwk.PublicKeyOf(jwkKey)
	if err != nil {
		return "", err
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
		return "", err
	}

	headers := jws.NewHeaders()
	err = headers.Set("jwk", publicKey)
	if err != nil {
		return "", err
	}
	err = headers.Set("typ", "dpop+jwt")
	if err != nil {
		return "", err
	}

	alg := jwkKey.Algorithm()
	if alg == nil {
		alg = jwa.ES256 // Default to ES256 if not set
	}

	proof, err := jwt.Sign(token, jwt.WithKey(alg, jwkKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", err
	}

	return string(proof), nil
}

// GenerateDPoPKey generates a new EC P-256 key and returns it as a JWK.
func GenerateDPoPKey() (jwk.Key, error) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrGenDPoPECKey
	}
	jwkKey, err := jwk.FromRaw(ecdsaKey)
	if err != nil {
		return nil, ErrConvertECKey
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return nil, err
	}
	return jwkKey, nil
}

// AttachDPoPHeader adds a DPoP proof header to the request if dpopJWK is not nil.
func AttachDPoPHeader(req *http.Request, dpopJWK jwk.Key, endpoint, nonce string) error {
	if dpopJWK == nil {
		return nil
	}
	dpopProof, err := GetDPoPProof(dpopJWK, endpoint, nonce)
	if err != nil {
		return fmt.Errorf("failed to generate DPoP proof: %w", err)
	}
	req.Header.Set("DPoP", dpopProof)
	return nil
}
