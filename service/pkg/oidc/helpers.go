package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// ParseJWKFromPEM strips comments and parses a JWK from a PEM-encoded []byte
func ParseJWKFromPEM(privateKeyPEM []byte) (jwk.Key, error) {
	jwkStr := string(privateKeyPEM)
	lines := strings.Split(jwkStr, "\n")
	var jsonLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "//") && line != "" {
			jsonLines = append(jsonLines, line)
		}
	}
	jwkJSON := strings.Join(jsonLines, "\n")
	return jwk.ParseKey([]byte(jwkJSON), jwk.WithPEM(false))
}

// BuildJWTAssertion builds a JWT assertion for OAuth2 client authentication
func BuildJWTAssertion(clientID, audience string) (jwt.Token, error) {
	now := time.Now()
	jwtBuilder := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute)).
		JwtID(uuid.NewString())
	return jwtBuilder.Build()
}

// SignJWTAssertion signs a JWT assertion with the given key and algorithm
func SignJWTAssertion(assertion jwt.Token, key jwk.Key, alg jwa.SignatureAlgorithm) ([]byte, error) {
	kid, _ := key.Get("kid")
	headers := jws.NewHeaders()
	_ = headers.Set(jws.AlgorithmKey, alg)
	if kid != nil {
		_ = headers.Set(jws.KeyIDKey, kid)
	}
	return jwt.Sign(assertion, jwt.WithKey(alg, key, jws.WithProtectedHeaders(headers)))
}

// GenerateDPoPKey generates a new EC P-256 key and returns it as a JWK.
func GenerateDPoPKey() (jwk.Key, error) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DPoP EC key: %w", err)
	}
	jwkKey, err := jwk.FromRaw(ecdsaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert EC key to JWK: %w", err)
	}
	jwkKey.Set(jwk.AlgorithmKey, jwa.ES256)
	return jwkKey, nil
}

// getDPoPAssertion generates a DPoP proof JWT for the given method and endpoint using the provided JWK.
func getDPoPAssertion(dpopJWK jwk.Key, method, endpoint, nonce string) (string, error) {
	const expirationTime = 5 * time.Minute

	publicKey, err := jwk.PublicKeyOf(dpopJWK)
	if err != nil {
		return "", err
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

	headers := jws.NewHeaders()
	err = headers.Set("jwk", publicKey)
	if err != nil {
		return "", err
	}
	err = headers.Set("typ", "dpop+jwt")
	if err != nil {
		return "", err
	}

	alg := dpopJWK.Algorithm()
	if alg == nil {
		alg = jwa.ES256 // Default to ES256 if not set
	}

	proof, err := jwt.Sign(token, jwt.WithKey(alg, dpopJWK, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", err
	}

	return string(proof), nil
}
