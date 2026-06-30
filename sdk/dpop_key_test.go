package sdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwkToPEMForTest converts a jwk.Key to PEM for round-trip testing.
func jwkToPEMForTest(t *testing.T, key interface{ Raw(any) error }) []byte {
	t.Helper()
	var raw any
	require.NoError(t, key.Raw(&raw), "failed to get raw key")
	der, err := x509.MarshalPKCS8PrivateKey(raw)
	require.NoError(t, err, "failed to marshal key to PKCS8")
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestGenerateDPoPKeyForAlg_EC(t *testing.T) {
	tests := []struct {
		alg     string
		wantAlg jwa.SignatureAlgorithm
		curve   elliptic.Curve
	}{
		{dpopAlgES256, jwa.ES256, elliptic.P256()},
		{dpopAlgES384, jwa.ES384, elliptic.P384()},
		{dpopAlgES512, jwa.ES512, elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			key, err := generateDPoPKeyForAlg(tt.alg)
			require.NoErrorf(t, err, "generateDPoPKeyForAlg(%q)", tt.alg)
			assert.Equal(t, tt.wantAlg, key.Algorithm(), "algorithm")
			var rawKey *ecdsa.PrivateKey
			require.NoError(t, key.Raw(&rawKey), "failed to get raw EC key")
			assert.Equal(t, tt.curve, rawKey.Curve, "curve")
		})
	}
}

func TestGenerateDPoPKeyForAlg_RSA(t *testing.T) {
	tests := []struct {
		alg     string
		wantAlg jwa.SignatureAlgorithm
	}{
		{dpopAlgRS256, jwa.RS256},
		{dpopAlgRS384, jwa.RS384},
		{dpopAlgRS512, jwa.RS512},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			key, err := generateDPoPKeyForAlg(tt.alg)
			require.NoErrorf(t, err, "generateDPoPKeyForAlg(%q)", tt.alg)
			assert.Equal(t, tt.wantAlg, key.Algorithm(), "algorithm")
			var rawKey *rsa.PrivateKey
			require.NoError(t, key.Raw(&rawKey), "failed to get raw RSA key")
		})
	}
}

func TestGenerateDPoPKeyForAlg_Invalid(t *testing.T) {
	for _, alg := range []string{"INVALID", "", "HS256", "PS256"} {
		t.Run(alg, func(t *testing.T) {
			_, err := generateDPoPKeyForAlg(alg)
			assert.Errorf(t, err, "expected error for alg %q", alg)
		})
	}
}

func TestLoadDPoPKeyFromPEM_RSA(t *testing.T) {
	generated, err := generateDPoPKeyForAlg(dpopAlgRS256)
	require.NoError(t, err, "failed to generate RSA test key")
	pemBytes := jwkToPEMForTest(t, generated)

	loaded, err := loadDPoPKeyFromPEM(pemBytes)
	require.NoError(t, err, "loadDPoPKeyFromPEM")
	assert.Equal(t, jwa.RS256, loaded.Algorithm(), "algorithm")
}

func TestLoadDPoPKeyFromPEM_EC(t *testing.T) {
	tests := []struct {
		alg     string
		wantAlg jwa.SignatureAlgorithm
	}{
		{dpopAlgES256, jwa.ES256},
		{dpopAlgES384, jwa.ES384},
		{dpopAlgES512, jwa.ES512},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			generated, err := generateDPoPKeyForAlg(tt.alg)
			require.NoError(t, err, "failed to generate EC test key")
			pemBytes := jwkToPEMForTest(t, generated)

			loaded, err := loadDPoPKeyFromPEM(pemBytes)
			require.NoError(t, err, "loadDPoPKeyFromPEM")
			assert.Equal(t, tt.wantAlg, loaded.Algorithm(), "algorithm")
		})
	}
}

func TestLoadDPoPKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := loadDPoPKeyFromPEM([]byte("not valid PEM"))
	assert.Error(t, err, "expected error for invalid PEM")
}

func TestResolveDPoPKey(t *testing.T) {
	ecKey, err := generateDPoPKeyForAlg(dpopAlgES256)
	require.NoError(t, err, "generate EC key")
	ecPEM := jwkToPEMForTest(t, ecKey)

	t.Run("empty config returns nil sentinel", func(t *testing.T) {
		key, err := resolveDPoPKey(&config{})
		require.NoError(t, err)
		assert.Nil(t, key, "expected nil key for empty config")
	})

	t.Run("preset JWK validated and returned", func(t *testing.T) {
		key, err := resolveDPoPKey(&config{dpopJWK: ecKey})
		require.NoError(t, err)
		require.NotNil(t, key, "expected key")
	})

	t.Run("PEM path resolves without mutating config", func(t *testing.T) {
		c := &config{dpopKeyPEM: ecPEM}
		key, err := resolveDPoPKey(c)
		require.NoError(t, err)
		assert.Equal(t, jwa.ES256, key.Algorithm(), "alg")
		assert.Nil(t, c.dpopJWK, "resolveDPoPKey must be pure and not cache into dpopJWK")
	})

	t.Run("PEM with algorithm override", func(t *testing.T) {
		rsaKey, err := generateDPoPKeyForAlg(dpopAlgRS256)
		require.NoError(t, err, "generate RSA key")
		c := &config{dpopKeyPEM: jwkToPEMForTest(t, rsaKey), dpopAlgorithm: dpopAlgRS512}
		key, err := resolveDPoPKey(c)
		require.NoError(t, err)
		assert.Equal(t, jwa.RS512, key.Algorithm(), "alg override")
	})

	t.Run("generate from algorithm", func(t *testing.T) {
		key, err := resolveDPoPKey(&config{dpopAlgorithm: dpopAlgES384})
		require.NoError(t, err)
		assert.Equal(t, jwa.ES384, key.Algorithm(), "alg")
	})

	t.Run("RSA key pair resolves to RS256 JWK", func(t *testing.T) {
		rsaKeyPair, err := ocrypto.NewRSAKeyPair(dpopKeySize)
		require.NoError(t, err, "generate RSA key pair")
		key, err := resolveDPoPKey(&config{dpopKey: &rsaKeyPair})
		require.NoError(t, err)
		require.NotNil(t, key, "expected key for RSA key pair")
		assert.Equal(t, jwa.RS256, key.Algorithm(), "alg")
	})
}

func TestValidateDPoPKeyAlgorithm(t *testing.T) {
	t.Run("missing algorithm errors", func(t *testing.T) {
		raw, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "generate key")
		k, err := jwk.FromRaw(raw)
		require.NoError(t, err, "jwk.FromRaw")
		_, err = resolveDPoPKey(&config{dpopJWK: k})
		assert.Error(t, err, "expected error for JWK without algorithm")
	})

	t.Run("unsupported algorithm errors", func(t *testing.T) {
		raw, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "generate key")
		k, err := jwk.FromRaw(raw)
		require.NoError(t, err, "jwk.FromRaw")
		require.NoError(t, k.Set(jwk.AlgorithmKey, jwa.HS256), "set alg")
		_, err = resolveDPoPKey(&config{dpopJWK: k})
		assert.Error(t, err, "expected error for unsupported algorithm")
	})
}
