package ocrypto

import (
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestP256MLKEM768KeyPairAndPEM(t *testing.T) {
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)

	publicPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privatePEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	publicKey, err := P256MLKEM768PubKeyFromPem([]byte(publicPEM))
	require.NoError(t, err)
	privateKey, err := P256MLKEM768PrivateKeyFromPem([]byte(privatePEM))
	require.NoError(t, err)

	assert.Len(t, publicKey, P256MLKEM768PublicKeySize)
	assert.Len(t, privateKey, P256MLKEM768PrivateKeySize)
	assert.Equal(t, HybridSecp256r1MLKEM768Key, keyPair.GetKeyType())
}

func TestP384MLKEM1024KeyPairAndPEM(t *testing.T) {
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)

	publicPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privatePEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	publicKey, err := P384MLKEM1024PubKeyFromPem([]byte(publicPEM))
	require.NoError(t, err)
	privateKey, err := P384MLKEM1024PrivateKeyFromPem([]byte(privatePEM))
	require.NoError(t, err)

	assert.Len(t, publicKey, P384MLKEM1024PublicKeySize)
	assert.Len(t, privateKey, P384MLKEM1024PrivateKeySize)
	assert.Equal(t, HybridSecp384r1MLKEM1024Key, keyPair.GetKeyType())
}

func TestNewKeyPairP256MLKEM768(t *testing.T) {
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)
	assert.Equal(t, HybridSecp256r1MLKEM768Key, keyPair.GetKeyType())
}

func TestNewKeyPairP384MLKEM1024(t *testing.T) {
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)
	assert.Equal(t, HybridSecp384r1MLKEM1024Key, keyPair.GetKeyType())
}

func TestP256MLKEM768WrapUnwrapRoundTrip(t *testing.T) {
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)

	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := P256MLKEM768WrapDEK(keyPair.publicKey, dek)
	require.NoError(t, err)

	plaintext, err := P256MLKEM768UnwrapDEK(keyPair.privateKey, wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)
}

func TestP384MLKEM1024WrapUnwrapRoundTrip(t *testing.T) {
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)

	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := P384MLKEM1024WrapDEK(keyPair.publicKey, dek)
	require.NoError(t, err)

	plaintext, err := P384MLKEM1024UnwrapDEK(keyPair.privateKey, wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)
}

func TestP256MLKEM768WrapUnwrapWrongKeyFails(t *testing.T) {
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)
	wrongKeyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)

	wrapped, err := P256MLKEM768WrapDEK(keyPair.publicKey, []byte("top secret dek"))
	require.NoError(t, err)

	_, err = P256MLKEM768UnwrapDEK(wrongKeyPair.privateKey, wrapped)
	require.Error(t, err)
	// Wrong-key failure must surface through AES-GCM authentication, not a
	// parse/size mismatch — ML-KEM uses implicit rejection so DecapsulateTo
	// returns a pseudorandom secret rather than an error.
	assert.ErrorContains(t, err, "AES-GCM decrypt failed")
}

func TestP384MLKEM1024WrapUnwrapWrongKeyFails(t *testing.T) {
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)
	wrongKeyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)

	wrapped, err := P384MLKEM1024WrapDEK(keyPair.publicKey, []byte("top secret dek"))
	require.NoError(t, err)

	_, err = P384MLKEM1024UnwrapDEK(wrongKeyPair.privateKey, wrapped)
	require.Error(t, err)
	assert.ErrorContains(t, err, "AES-GCM decrypt failed")
}

func TestHybridNISTEnvelopeASN1RoundTrip(t *testing.T) {
	original := kemEnvelope{
		KEMCiphertext: []byte("hybrid-ciphertext-data"),
		EncryptedDEK:  []byte("encrypted-dek-data"),
	}

	der, err := asn1.Marshal(original)
	require.NoError(t, err)

	var decoded kemEnvelope
	rest, err := asn1.Unmarshal(der, &decoded)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, original, decoded)
}

func TestP256MLKEM768PEMDispatch(t *testing.T) {
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)

	publicPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privatePEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	encryptor, err := FromPublicPEMWithSalt(publicPEM, []byte("salt"), []byte("info"))
	require.NoError(t, err)

	decryptor, err := FromPrivatePEMWithSalt(privatePEM, []byte("salt"), []byte("info"))
	require.NoError(t, err)

	assert.Equal(t, Hybrid, encryptor.Type())
	assert.Equal(t, HybridSecp256r1MLKEM768Key, encryptor.KeyType())
	assert.Nil(t, encryptor.EphemeralKey())

	metadata, err := encryptor.Metadata()
	require.NoError(t, err)
	assert.Empty(t, metadata)

	wrapped, err := encryptor.Encrypt([]byte("dispatch-dek"))
	require.NoError(t, err)

	plaintext, err := decryptor.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, []byte("dispatch-dek"), plaintext)
}

func TestP384MLKEM1024PEMDispatch(t *testing.T) {
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)

	publicPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privatePEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	encryptor, err := FromPublicPEMWithSalt(publicPEM, []byte("salt"), []byte("info"))
	require.NoError(t, err)

	decryptor, err := FromPrivatePEMWithSalt(privatePEM, []byte("salt"), []byte("info"))
	require.NoError(t, err)

	assert.Equal(t, Hybrid, encryptor.Type())
	assert.Equal(t, HybridSecp384r1MLKEM1024Key, encryptor.KeyType())
	assert.Nil(t, encryptor.EphemeralKey())

	wrapped, err := encryptor.Encrypt([]byte("dispatch-dek-384"))
	require.NoError(t, err)

	plaintext, err := decryptor.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, []byte("dispatch-dek-384"), plaintext)
}

func TestP256MLKEM768Encapsulate(t *testing.T) {
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)

	pubKey, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)

	pubKeyRaw, err := P256MLKEM768PubKeyFromPem([]byte(pubKey))
	require.NoError(t, err)

	combinedSecret, hybridCt, err := nistHybridKEM{params: &p256mlkem768Params}.encapsulate(pubKeyRaw)
	require.NoError(t, err)
	assert.NotEmpty(t, combinedSecret)
	assert.Len(t, hybridCt, P256MLKEM768CiphertextSize)
}

func TestP384MLKEM1024Encapsulate(t *testing.T) {
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)

	pubKey, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)

	pubKeyRaw, err := P384MLKEM1024PubKeyFromPem([]byte(pubKey))
	require.NoError(t, err)

	combinedSecret, hybridCt, err := nistHybridKEM{params: &p384mlkem1024Params}.encapsulate(pubKeyRaw)
	require.NoError(t, err)
	assert.NotEmpty(t, combinedSecret)
	assert.Len(t, hybridCt, P384MLKEM1024CiphertextSize)
}

func TestIsHybridKeyTypeIncludesNewTypes(t *testing.T) {
	assert.True(t, IsHybridKeyType(HybridXWingKey))
	assert.True(t, IsHybridKeyType(HybridSecp256r1MLKEM768Key))
	assert.True(t, IsHybridKeyType(HybridSecp384r1MLKEM1024Key))
	assert.False(t, IsHybridKeyType(EC256Key))
	assert.False(t, IsHybridKeyType(RSA2048Key))
}
