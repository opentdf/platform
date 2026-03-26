package ocrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHybridXWingRoundtrip(t *testing.T) {
	// Generate key pair
	kp, err := NewHybridXWingKeyPair()
	require.NoError(t, err)
	require.NotNil(t, kp)

	publicKeyPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)
	require.NotEmpty(t, publicKeyPEM)

	privateKeyPEM, err := kp.PrivateKeyInPemFormat()
	require.NoError(t, err)
	require.NotEmpty(t, privateKeyPEM)

	// Create encryptor and decryptor
	encryptor, err := HybridEncryptorFromPEM(publicKeyPEM)
	require.NoError(t, err)
	require.NotNil(t, encryptor)

	decryptor, err := HybridDecryptorFromPEM(privateKeyPEM)
	require.NoError(t, err)
	require.NotNil(t, decryptor)

	// Encapsulate
	ssEnc, ct, err := encryptor.Encapsulate()
	require.NoError(t, err)
	require.NotEmpty(t, ssEnc)
	require.NotEmpty(t, ct)

	// Decapsulate
	ssDec, err := decryptor.Decapsulate(ct)
	require.NoError(t, err)
	require.Equal(t, ssEnc, ssDec)
}

func TestHybridXWingAsymEncryptionRoundtrip(t *testing.T) {
	// Generate key pair
	kp, err := NewHybridXWingKeyPair()
	require.NoError(t, err)

	publicKeyPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)

	privateKeyPEM, err := kp.PrivateKeyInPemFormat()
	require.NoError(t, err)

	// Create encryptor and decryptor via common interfaces
	encryptor, err := FromPublicPEM(publicKeyPEM)
	require.NoError(t, err)
	assert.Equal(t, Hybrid, encryptor.Type())
	assert.Equal(t, HybridXWingKey, encryptor.KeyType())

	decryptor, err := FromPrivatePEM(privateKeyPEM)
	require.NoError(t, err)

	// Data to encrypt
	data := []byte("hello world, hybrid style")

	// Encrypt
	ciphertext, err := encryptor.Encrypt(data)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	// Get ephemeral key (ciphertext from KEM)
	ephemeral := encryptor.EphemeralKey()
	require.NotEmpty(t, ephemeral)

	// Decrypt
	plaintext, err := decryptor.DecryptWithEphemeralKey(ciphertext, ephemeral)
	require.NoError(t, err)
	assert.Equal(t, data, plaintext)
}
