package ocrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXWingRoundTrip(t *testing.T) {
	keyPair, err := NewXWingKeyPair()
	require.NoError(t, err)

	publicKeyPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)

	privateKeyPEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	encryptor, err := FromPublicPEM(publicKeyPEM)
	require.NoError(t, err)
	assert.Equal(t, Hybrid, encryptor.Type())
	assert.Equal(t, HybridXWingKey, encryptor.KeyType())

	decryptor, err := FromPrivatePEM(privateKeyPEM)
	require.NoError(t, err)

	plaintext := []byte("xwing hybrid wrap test payload")
	ciphertext, err := encryptor.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := decryptor.DecryptWithEphemeralKey(ciphertext, encryptor.EphemeralKey())
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
