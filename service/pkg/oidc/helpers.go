package oidc

import (
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
