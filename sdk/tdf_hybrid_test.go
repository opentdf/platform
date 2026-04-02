package sdk

import (
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateKeyAccessWithHybridKey(t *testing.T) {
	keyPair, err := ocrypto.NewXWingKeyPair()
	require.NoError(t, err)

	publicKeyPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)

	privateKeyPEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	symKey := []byte("0123456789abcdef0123456789abcdef")
	keyAccess, err := createKeyAccess(KASInfo{
		URL:       "https://kas.example.com",
		KID:       "xwing-kid",
		Algorithm: string(ocrypto.HybridXWingKey),
		PublicKey: publicKeyPEM,
	}, symKey, PolicyBinding{}, "", "")
	require.NoError(t, err)

	assert.Equal(t, kHybridWrapped, keyAccess.KeyType)
	assert.Empty(t, keyAccess.EphemeralPublicKey)
	assert.NotEmpty(t, keyAccess.WrappedKey)

	privateKey, err := ocrypto.XWingPrivateKeyFromPem([]byte(privateKeyPEM))
	require.NoError(t, err)

	wrappedKey, err := ocrypto.Base64Decode([]byte(keyAccess.WrappedKey))
	require.NoError(t, err)

	plaintext, err := ocrypto.XWingUnwrapDEK(privateKey, wrappedKey)
	require.NoError(t, err)
	assert.Equal(t, symKey, plaintext)
}
