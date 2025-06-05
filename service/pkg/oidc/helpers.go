package oidc

import (
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	JWTAssertionExpiration = 5 * time.Minute
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
