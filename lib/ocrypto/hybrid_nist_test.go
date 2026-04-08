package ocrypto

import (
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type hybridTestCase struct {
	name           string
	keyType        KeyType
	newKeyPair     func() (HybridECMLKEMKeyPair, error)
	publicFromPEM  func([]byte) ([]byte, error)
	privateFromPEM func([]byte) ([]byte, error)
	wrap           func([]byte, []byte) ([]byte, error)
	unwrap         func([]byte, []byte) ([]byte, error)
	publicKeySize  int
	privateKeySize int
	ciphertextSize int
}

func hybridTestCases() []hybridTestCase {
	return []hybridTestCase{
		{
			name:           "P256-MLKEM768",
			keyType:        HybridSecp256r1MLKEM768Key,
			newKeyPair:     NewP256MLKEM768KeyPair,
			publicFromPEM:  P256MLKEM768PubKeyFromPem,
			privateFromPEM: P256MLKEM768PrivateKeyFromPem,
			wrap:           P256MLKEM768WrapDEK,
			unwrap:         P256MLKEM768UnwrapDEK,
			publicKeySize:  P256MLKEM768PublicKeySize,
			privateKeySize: P256MLKEM768PrivateKeySize,
			ciphertextSize: P256MLKEM768CiphertextSize,
		},
		{
			name:           "P384-MLKEM1024",
			keyType:        HybridSecp384r1MLKEM1024Key,
			newKeyPair:     NewP384MLKEM1024KeyPair,
			publicFromPEM:  P384MLKEM1024PubKeyFromPem,
			privateFromPEM: P384MLKEM1024PrivateKeyFromPem,
			wrap:           P384MLKEM1024WrapDEK,
			unwrap:         P384MLKEM1024UnwrapDEK,
			publicKeySize:  P384MLKEM1024PublicKeySize,
			privateKeySize: P384MLKEM1024PrivateKeySize,
			ciphertextSize: P384MLKEM1024CiphertextSize,
		},
	}
}

func TestHybridNISTKeyPairAndPEM(t *testing.T) {
	for _, tc := range hybridTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			keyPair, err := tc.newKeyPair()
			require.NoError(t, err)

			publicPEM, err := keyPair.PublicKeyInPemFormat()
			require.NoError(t, err)
			privatePEM, err := keyPair.PrivateKeyInPemFormat()
			require.NoError(t, err)

			publicKey, err := tc.publicFromPEM([]byte(publicPEM))
			require.NoError(t, err)
			privateKey, err := tc.privateFromPEM([]byte(privatePEM))
			require.NoError(t, err)

			assert.Len(t, publicKey, tc.publicKeySize)
			assert.Len(t, privateKey, tc.privateKeySize)
			assert.Equal(t, tc.keyType, keyPair.GetKeyType())
			assert.Equal(t, keyPair.publicKey, publicKey)
			assert.Equal(t, keyPair.privateKey, privateKey)
		})
	}
}

func TestNewKeyPairHybridNIST(t *testing.T) {
	for _, tc := range hybridTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			keyPair, err := NewKeyPair(tc.keyType)
			require.NoError(t, err)
			require.NotNil(t, keyPair)
			assert.Equal(t, tc.keyType, keyPair.GetKeyType())
		})
	}
}

func TestHybridNISTWrapUnwrapRoundTrip(t *testing.T) {
	for _, tc := range hybridTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			keyPair, err := tc.newKeyPair()
			require.NoError(t, err)

			dek := []byte("0123456789abcdef0123456789abcdef")
			wrapped, err := tc.wrap(keyPair.publicKey, dek)
			require.NoError(t, err)

			plaintext, err := tc.unwrap(keyPair.privateKey, wrapped)
			require.NoError(t, err)
			assert.Equal(t, dek, plaintext)

			var envelope HybridWrappedKey
			rest, err := asn1.Unmarshal(wrapped, &envelope)
			require.NoError(t, err)
			assert.Empty(t, rest)
			assert.Len(t, envelope.HybridCiphertext, tc.ciphertextSize)
			assert.NotEmpty(t, envelope.EncryptedDEK)
		})
	}
}

func TestHybridNISTWrongKeyFails(t *testing.T) {
	for _, tc := range hybridTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			keyPair, err := tc.newKeyPair()
			require.NoError(t, err)
			wrongKeyPair, err := tc.newKeyPair()
			require.NoError(t, err)

			wrapped, err := tc.wrap(keyPair.publicKey, []byte("top secret dek"))
			require.NoError(t, err)

			_, err = tc.unwrap(wrongKeyPair.privateKey, wrapped)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "AES-GCM decrypt failed")
		})
	}
}

func TestHybridWrappedKeyASN1RoundTrip(t *testing.T) {
	original := HybridWrappedKey{
		HybridCiphertext: []byte("hybrid-ciphertext"),
		EncryptedDEK:     []byte("encrypted-dek"),
	}

	der, err := asn1.Marshal(original)
	require.NoError(t, err)

	var decoded HybridWrappedKey
	rest, err := asn1.Unmarshal(der, &decoded)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, original, decoded)
}

func TestHybridNISTPEMDispatch(t *testing.T) {
	for _, tc := range hybridTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			keyPair, err := tc.newKeyPair()
			require.NoError(t, err)

			publicPEM, err := keyPair.PublicKeyInPemFormat()
			require.NoError(t, err)
			privatePEM, err := keyPair.PrivateKeyInPemFormat()
			require.NoError(t, err)

			encryptor, err := FromPublicPEMWithSalt(publicPEM, []byte("salt"), []byte("info"))
			require.NoError(t, err)

			decryptor, err := FromPrivatePEMWithSalt(privatePEM, []byte("salt"), []byte("info"))
			require.NoError(t, err)

			hybridEncryptor, ok := encryptor.(*HybridECMLKEMEncryptor)
			require.True(t, ok)
			assert.Equal(t, Hybrid, hybridEncryptor.Type())
			assert.Equal(t, tc.keyType, hybridEncryptor.KeyType())
			assert.Nil(t, hybridEncryptor.EphemeralKey())

			metadata, err := hybridEncryptor.Metadata()
			require.NoError(t, err)
			assert.Empty(t, metadata)

			hybridDecryptor, ok := decryptor.(*HybridECMLKEMDecryptor)
			require.True(t, ok)

			wrapped, err := hybridEncryptor.Encrypt([]byte("dispatch-dek"))
			require.NoError(t, err)

			plaintext, err := hybridDecryptor.Decrypt(wrapped)
			require.NoError(t, err)
			assert.Equal(t, []byte("dispatch-dek"), plaintext)
		})
	}
}
