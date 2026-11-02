package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

func TestParseClaimsJWTSigningAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	want := JWTClaims{Expiration: 1900000000}
	for _, tt := range []struct {
		algorithm jose.SignatureAlgorithm
		key       any
	}{
		{jose.RS256, rsaKey},
		{jose.PS256, rsaKey},
		{jose.ES256, ecKey},
		{jose.HS256, []byte("0123456789abcdef0123456789abcdef")},
		{jose.EdDSA, edKey},
	} {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: tt.algorithm, Key: tt.key}, nil)
			require.NoError(t, err)
			token, err := jwt.Signed(signer).Claims(want).Serialize()
			require.NoError(t, err)

			got, err := ParseClaimsJWT(token)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestParseClaimsJWTRejectsUnsupportedAlgorithms(t *testing.T) {
	for _, algorithm := range []string{"none", "unknown"} {
		t.Run(algorithm, func(t *testing.T) {
			header := fmt.Sprintf(`{"alg":%q}`, algorithm)
			token := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
				base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1900000000}`)) + "."

			_, err := ParseClaimsJWT(token)
			require.ErrorIs(t, err, ErrParsingAccessToken)
			var algorithmErr *jose.ErrUnexpectedSignatureAlgorithm
			require.ErrorAs(t, err, &algorithmErr)
			require.Equal(t, jose.SignatureAlgorithm(algorithm), algorithmErr.Got)
		})
	}
}
