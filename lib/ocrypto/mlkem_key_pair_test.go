package ocrypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMLKEMKeyPair(t *testing.T) {
	kp, err := NewMLKEMKeyPair()
	require.NoError(t, err)
	assert.Equal(t, MLKEM768Key, kp.GetKeyType())

	pubPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)
	assert.Contains(t, pubPEM, "ML-KEM-768 PUBLIC KEY")

	privPEM, err := kp.PrivateKeyInPemFormat()
	require.NoError(t, err)
	assert.Contains(t, privPEM, "ML-KEM-768 PRIVATE KEY")
}

func TestMLKEMRoundtrip(t *testing.T) {
	kp, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	pubPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)

	privPEM, err := kp.PrivateKeyInPemFormat()
	require.NoError(t, err)

	// Generate a random DEK to wrap
	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	// Encapsulate (SDK side)
	wrappedKey, err := MLKEMEncapsulateAndWrap([]byte(pubPEM), dek)
	require.NoError(t, err)
	assert.Len(t, wrappedKey, MLKEM768CiphertextSize+12+32+16, "wrappedKey should be ciphertext + nonce + dek + gcm-tag")

	// Decapsulate (KAS side)
	recovered, err := MLKEMDecapsulateAndUnwrap([]byte(privPEM), wrappedKey)
	require.NoError(t, err)
	assert.Equal(t, dek, recovered)
}

func TestMLKEMDecapsulateWrongKey(t *testing.T) {
	kp1, err := NewMLKEMKeyPair()
	require.NoError(t, err)
	kp2, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	pubPEM1, err := kp1.PublicKeyInPemFormat()
	require.NoError(t, err)
	privPEM2, err := kp2.PrivateKeyInPemFormat()
	require.NoError(t, err)

	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	wrappedKey, err := MLKEMEncapsulateAndWrap([]byte(pubPEM1), dek)
	require.NoError(t, err)

	// Decapsulating with a different key should fail
	_, err = MLKEMDecapsulateAndUnwrap([]byte(privPEM2), wrappedKey)
	assert.Error(t, err)
}

func TestMLKEMDecapsulateTooShort(t *testing.T) {
	kp, err := NewMLKEMKeyPair()
	require.NoError(t, err)
	privPEM, err := kp.PrivateKeyInPemFormat()
	require.NoError(t, err)

	_, err = MLKEMDecapsulateAndUnwrap([]byte(privPEM), make([]byte, 100))
	assert.Error(t, err)
}

func TestIsMLKEMKeyType(t *testing.T) {
	assert.True(t, IsMLKEMKeyType(MLKEM768Key))
	assert.False(t, IsMLKEMKeyType(RSA2048Key))
	assert.False(t, IsMLKEMKeyType(EC256Key))
}

func TestNewKeyPairMLKEM(t *testing.T) {
	kp, err := NewKeyPair(MLKEM768Key)
	require.NoError(t, err)
	assert.Equal(t, MLKEM768Key, kp.GetKeyType())
}
