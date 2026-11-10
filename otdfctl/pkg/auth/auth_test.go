package auth

import (
	"encoding/base64"
	"errors"
	"testing"
)

func Test_ParseClaimsJWT_AcceptsAllowedAlgorithm(t *testing.T) {
	token := compactJWT(`{"alg":"RS256"}`, `{"exp":123}`, "signature")

	claims, err := ParseClaimsJWT(token)
	if err != nil {
		t.Fatalf("ParseClaimsJWT() error = %v", err)
	}
	if claims.Expiration != 123 {
		t.Fatalf("ParseClaimsJWT() expiration = %d, want 123", claims.Expiration)
	}
}

func Test_ParseClaimsJWT_RejectsDisallowedAlgorithm(t *testing.T) {
	token := compactJWT(`{"alg":"none"}`, `{"exp":123}`, "")

	_, err := ParseClaimsJWT(token)
	if !errors.Is(err, ErrParsingAccessToken) {
		t.Fatalf("ParseClaimsJWT() error = %v, want %v", err, ErrParsingAccessToken)
	}
}

func compactJWT(header, claims, signature string) string {
	encode := base64.RawURLEncoding.EncodeToString
	return encode([]byte(header)) + "." + encode([]byte(claims)) + "." + encode([]byte(signature))
}
