package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/require"
)

func pemBlockForKey(t *testing.T, pub interface{}) []byte {
	t.Helper()
	var der []byte
	var err error
	switch k := pub.(type) {
	case *rsa.PublicKey:
		der, err = x509.MarshalPKIXPublicKey(k)
		require.NoError(t, err)
	case *ecdsa.PublicKey:
		der, err = x509.MarshalPKIXPublicKey(k)
		require.NoError(t, err)
	default:
		t.Fatalf("unsupported key type")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestValidatePublicKeyPEM_RSA2048_OK(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := &k.PublicKey
	pemBytes := pemBlockForKey(t, pub)

	err = ValidatePublicKeyPEM(pemBytes, policy.Algorithm_ALGORITHM_RSA_2048)
	require.NoError(t, err)
}

func TestValidatePublicKeyPEM_RSA_SizeMismatch(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pemBlockForKey(t, &k.PublicKey)

	err = ValidatePublicKeyPEM(pemBytes, policy.Algorithm_ALGORITHM_RSA_4096)
	require.Error(t, err)
	require.Contains(t, err.Error(), "algorithm mismatch")
}

func TestValidatePublicKeyPEM_RSA4096_OK(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	pub := &k.PublicKey
	pemBytes := pemBlockForKey(t, pub)

	err = ValidatePublicKeyPEM(pemBytes, policy.Algorithm_ALGORITHM_RSA_4096)
	require.NoError(t, err)
}

func TestValidatePublicKeyPEM_EC_P256_OK(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pemBytes := pemBlockForKey(t, &k.PublicKey)

	err = ValidatePublicKeyPEM(pemBytes, policy.Algorithm_ALGORITHM_EC_P256)
	require.NoError(t, err)
}

func TestValidatePublicKeyPEM_EC_P384_OK(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	pemBytes := pemBlockForKey(t, &k.PublicKey)

	err = ValidatePublicKeyPEM(pemBytes, policy.Algorithm_ALGORITHM_EC_P384)
	require.NoError(t, err)
}

func TestValidatePublicKeyPEM_EC_P521_OK(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	pemBytes := pemBlockForKey(t, &k.PublicKey)

	err = ValidatePublicKeyPEM(pemBytes, policy.Algorithm_ALGORITHM_EC_P521)
	require.NoError(t, err)
}

func TestValidatePublicKeyPEM_EC_Mismatch(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	pemBytes := pemBlockForKey(t, &k.PublicKey)

	err = ValidatePublicKeyPEM(pemBytes, policy.Algorithm_ALGORITHM_EC_P256)
	require.Error(t, err)
	require.Contains(t, err.Error(), "algorithm mismatch")
}

func TestValidatePublicKeyPEM_InvalidPEM(t *testing.T) {
	err := ValidatePublicKeyPEM([]byte("not a pem"), policy.Algorithm_ALGORITHM_RSA_2048)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid public key pem")
}

func TestValidatePublicKeyPEM_EmptyPEM(t *testing.T) {
	err := ValidatePublicKeyPEM([]byte(""), policy.Algorithm_ALGORITHM_RSA_2048)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty pem input")
}

func TestValidatePublicKeyPEM_UnsupportedAlgorithm(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pemBlockForKey(t, &k.PublicKey)

	err = ValidatePublicKeyPEM(pemBytes, policy.Algorithm_ALGORITHM_UNSPECIFIED)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported or unspecified algorithm")
}
