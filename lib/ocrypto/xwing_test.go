package ocrypto

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXWingKeyPairGeneration(t *testing.T) {
	kp, err := NewXWingKeyPair()
	require.NoError(t, err)
	assert.NotNil(t, kp.pk)
	assert.NotNil(t, kp.sk)
	assert.Equal(t, HybridXWingKey, kp.GetKeyType())
}

func TestXWingPEMRoundTrip(t *testing.T) {
	kp, err := NewXWingKeyPair()
	require.NoError(t, err)

	// Public key round-trip
	pubPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)
	assert.Contains(t, pubPEM, PEMBlockXWingPublicKey)

	pubRaw, err := XWingPubKeyFromPem([]byte(pubPEM))
	require.NoError(t, err)
	assert.Len(t, pubRaw, XWingPublicKeySize)

	// Private key round-trip
	privPEM, err := kp.PrivateKeyInPemFormat()
	require.NoError(t, err)
	assert.Contains(t, privPEM, PEMBlockXWingPrivateKey)

	privRaw, err := XWingPrivateKeyFromPem([]byte(privPEM))
	require.NoError(t, err)
	assert.Len(t, privRaw, XWingPrivateKeySize)
}

func TestXWingWrapUnwrapDEK(t *testing.T) {
	kp, err := NewXWingKeyPair()
	require.NoError(t, err)

	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	// Get raw keys
	pubPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)
	pubRaw, err := XWingPubKeyFromPem([]byte(pubPEM))
	require.NoError(t, err)

	privPEM, err := kp.PrivateKeyInPemFormat()
	require.NoError(t, err)
	privRaw, err := XWingPrivateKeyFromPem([]byte(privPEM))
	require.NoError(t, err)

	// Wrap
	wrapped, err := XWingWrapDEK(pubRaw, dek)
	require.NoError(t, err)
	assert.NotEmpty(t, wrapped)

	// Unwrap
	recovered, err := XWingUnwrapDEK(privRaw, wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, recovered)
}

func TestXWingWrapUnwrapDEK_WrongKey(t *testing.T) {
	kp1, err := NewXWingKeyPair()
	require.NoError(t, err)
	kp2, err := NewXWingKeyPair()
	require.NoError(t, err)

	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	pubPEM, err := kp1.PublicKeyInPemFormat()
	require.NoError(t, err)
	pubRaw, err := XWingPubKeyFromPem([]byte(pubPEM))
	require.NoError(t, err)

	privPEM, err := kp2.PrivateKeyInPemFormat()
	require.NoError(t, err)
	wrongPrivRaw, err := XWingPrivateKeyFromPem([]byte(privPEM))
	require.NoError(t, err)

	wrapped, err := XWingWrapDEK(pubRaw, dek)
	require.NoError(t, err)

	_, err = XWingUnwrapDEK(wrongPrivRaw, wrapped)
	require.Error(t, err, "decryption with wrong key should fail")
}

func TestXWingASN1Envelope(t *testing.T) {
	envelope := XWingWrappedKey{
		XWingCiphertext: make([]byte, XWingCiphertextSize),
		EncryptedDEK:    []byte("encrypted-dek-data"),
	}

	der, err := asn1.Marshal(envelope)
	require.NoError(t, err)

	var decoded XWingWrappedKey
	rest, err := asn1.Unmarshal(der, &decoded)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, envelope.XWingCiphertext, decoded.XWingCiphertext)
	assert.Equal(t, envelope.EncryptedDEK, decoded.EncryptedDEK)
}

func TestXWingEncryptorInterface(t *testing.T) {
	kp, err := NewXWingKeyPair()
	require.NoError(t, err)

	pubPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)

	enc, err := FromPublicPEM(pubPEM)
	require.NoError(t, err)

	assert.Equal(t, Hybrid, enc.Type())
	assert.Equal(t, HybridXWingKey, enc.KeyType())
	assert.Nil(t, enc.EphemeralKey())

	meta, err := enc.Metadata()
	require.NoError(t, err)
	assert.Empty(t, meta)
}

func TestXWingDecryptorInterface(t *testing.T) {
	kp, err := NewXWingKeyPair()
	require.NoError(t, err)

	privPEM, err := kp.PrivateKeyInPemFormat()
	require.NoError(t, err)

	dec, err := FromPrivatePEM(privPEM)
	require.NoError(t, err)
	assert.IsType(t, XWingDecryptor{}, dec)
}

func TestXWingEncryptDecryptRoundTrip(t *testing.T) {
	kp, err := NewXWingKeyPair()
	require.NoError(t, err)

	pubPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)
	privPEM, err := kp.PrivateKeyInPemFormat()
	require.NoError(t, err)

	enc, err := FromPublicPEM(pubPEM)
	require.NoError(t, err)

	dec, err := FromPrivatePEM(privPEM)
	require.NoError(t, err)

	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	ciphertext, err := enc.Encrypt(dek)
	require.NoError(t, err)

	recovered, err := dec.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, dek, recovered)
}

func TestXWingPEMBlockTypeDetection(t *testing.T) {
	// Verify that non-XWING PEM blocks are NOT parsed as X-Wing
	_, err := XWingPubKeyFromPem([]byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected PEM block type")

	// Verify invalid size is rejected
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMBlockXWingPublicKey,
		Bytes: []byte("too short"),
	})
	_, err = XWingPubKeyFromPem(badPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key size")
}

func TestNewKeyPairHybrid(t *testing.T) {
	kp, err := NewKeyPair(HybridXWingKey)
	require.NoError(t, err)
	assert.Equal(t, HybridXWingKey, kp.GetKeyType())

	pubPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)
	assert.Contains(t, pubPEM, PEMBlockXWingPublicKey)
}

func TestIsHybridKeyType(t *testing.T) {
	assert.True(t, IsHybridKeyType(HybridXWingKey))
	assert.False(t, IsHybridKeyType(EC256Key))
	assert.False(t, IsHybridKeyType(RSA2048Key))
}
