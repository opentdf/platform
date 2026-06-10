package sdk

import (
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateKeyAccessWithXWingKey(t *testing.T) {
	symKey := []byte("0123456789abcdef0123456789abcdef")
	keyAccess, err := createKeyAccess(KASInfo{
		URL:       "https://kas.example.com",
		KID:       "xwing-kid",
		Algorithm: string(ocrypto.HybridXWingKey),
		PublicKey: mockHybridXWingPublicKey,
	}, symKey, PolicyBinding{}, "", "")
	require.NoError(t, err)

	assert.Equal(t, kHybridWrapped, keyAccess.KeyType)
	assert.Empty(t, keyAccess.EphemeralPublicKey)
	assert.NotEmpty(t, keyAccess.WrappedKey)

	privateKey, err := ocrypto.XWingPrivateKeyFromPem([]byte(mockHybridXWingPrivateKey))
	require.NoError(t, err)

	wrappedKey, err := ocrypto.Base64Decode([]byte(keyAccess.WrappedKey))
	require.NoError(t, err)

	plaintext, err := ocrypto.XWingUnwrapDEK(privateKey, wrappedKey)
	require.NoError(t, err)
	assert.Equal(t, symKey, plaintext)
}

func TestCreateKeyAccessWithP256MLKEM768Key(t *testing.T) {
	symKey := []byte("0123456789abcdef0123456789abcdef")
	keyAccess, err := createKeyAccess(KASInfo{
		URL:       "https://kas.example.com",
		KID:       "p256mlkem768-kid",
		Algorithm: string(ocrypto.HybridSecp256r1MLKEM768Key),
		PublicKey: mockHybridP256MLKEM768PublicKey,
	}, symKey, PolicyBinding{}, "", "")
	require.NoError(t, err)

	assert.Equal(t, kHybridWrapped, keyAccess.KeyType)
	assert.Empty(t, keyAccess.EphemeralPublicKey)
	assert.NotEmpty(t, keyAccess.WrappedKey)

	privateKey, err := ocrypto.P256MLKEM768PrivateKeyFromPem([]byte(mockHybridP256MLKEM768PrivateKey))
	require.NoError(t, err)

	wrappedKey, err := ocrypto.Base64Decode([]byte(keyAccess.WrappedKey))
	require.NoError(t, err)

	plaintext, err := ocrypto.P256MLKEM768UnwrapDEK(privateKey, wrappedKey)
	require.NoError(t, err)
	assert.Equal(t, symKey, plaintext)
}

func TestCreateKeyAccessWithP384MLKEM1024Key(t *testing.T) {
	symKey := []byte("0123456789abcdef0123456789abcdef")
	keyAccess, err := createKeyAccess(KASInfo{
		URL:       "https://kas.example.com",
		KID:       "p384mlkem1024-kid",
		Algorithm: string(ocrypto.HybridSecp384r1MLKEM1024Key),
		PublicKey: mockHybridP384MLKEM1024PublicKey,
	}, symKey, PolicyBinding{}, "", "")
	require.NoError(t, err)

	assert.Equal(t, kHybridWrapped, keyAccess.KeyType)
	assert.Empty(t, keyAccess.EphemeralPublicKey)
	assert.NotEmpty(t, keyAccess.WrappedKey)

	privateKey, err := ocrypto.P384MLKEM1024PrivateKeyFromPem([]byte(mockHybridP384MLKEM1024PrivateKey))
	require.NoError(t, err)

	wrappedKey, err := ocrypto.Base64Decode([]byte(keyAccess.WrappedKey))
	require.NoError(t, err)

	plaintext, err := ocrypto.P384MLKEM1024UnwrapDEK(privateKey, wrappedKey)
	require.NoError(t, err)
	assert.Equal(t, symKey, plaintext)
}
