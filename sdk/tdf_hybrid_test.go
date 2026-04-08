package sdk

import (
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateKeyAccessWithHybridKey(t *testing.T) {
	testCases := []struct {
		name       string
		kid        string
		algorithm  string
		newKeyPair func() (ocrypto.KeyPair, error)
	}{
		{
			name:      "X-Wing",
			kid:       "xwing-kid",
			algorithm: string(ocrypto.HybridXWingKey),
			newKeyPair: func() (ocrypto.KeyPair, error) {
				return ocrypto.NewXWingKeyPair()
			},
		},
		{
			name:      "SecP256r1-MLKEM768",
			kid:       "p256-mlkem768-kid",
			algorithm: string(ocrypto.HybridSecp256r1MLKEM768Key),
			newKeyPair: func() (ocrypto.KeyPair, error) {
				return ocrypto.NewP256MLKEM768KeyPair()
			},
		},
		{
			name:      "SecP384r1-MLKEM1024",
			kid:       "p384-mlkem1024-kid",
			algorithm: string(ocrypto.HybridSecp384r1MLKEM1024Key),
			newKeyPair: func() (ocrypto.KeyPair, error) {
				return ocrypto.NewP384MLKEM1024KeyPair()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyPair, err := tc.newKeyPair()
			require.NoError(t, err)

			publicKeyPEM, err := keyPair.PublicKeyInPemFormat()
			require.NoError(t, err)

			privateKeyPEM, err := keyPair.PrivateKeyInPemFormat()
			require.NoError(t, err)

			symKey := []byte("0123456789abcdef0123456789abcdef")
			keyAccess, err := createKeyAccess(KASInfo{
				URL:       "https://kas.example.com",
				KID:       tc.kid,
				Algorithm: tc.algorithm,
				PublicKey: publicKeyPEM,
			}, symKey, PolicyBinding{}, "", "")
			require.NoError(t, err)

			assert.Equal(t, kHybridWrapped, keyAccess.KeyType)
			assert.Empty(t, keyAccess.EphemeralPublicKey)
			assert.NotEmpty(t, keyAccess.WrappedKey)

			decryptor, err := ocrypto.FromPrivatePEM(privateKeyPEM)
			require.NoError(t, err)

			wrappedKey, err := ocrypto.Base64Decode([]byte(keyAccess.WrappedKey))
			require.NoError(t, err)

			plaintext, err := decryptor.Decrypt(wrappedKey)
			require.NoError(t, err)
			assert.Equal(t, symKey, plaintext)
		})
	}
}
