package ocrypto

import (
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXWingKeyPairAndPEM(t *testing.T) {
	keyPair, err := NewXWingKeyPair()
	require.NoError(t, err)

	publicPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privatePEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	enc, err := FromPublicPEM(publicPEM)
	require.NoError(t, err)
	dec, err := FromPrivatePEM(privatePEM)
	require.NoError(t, err)

	wrapped, err := enc.Encrypt([]byte("round-trip"))
	require.NoError(t, err)
	plaintext, err := dec.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, []byte("round-trip"), plaintext)

	assert.Len(t, keyPair.publicKey, XWingPublicKeySize)
	assert.Len(t, keyPair.privateKey, XWingPrivateKeySize)
	assert.Equal(t, HybridXWingKey, keyPair.GetKeyType())
}

func TestNewKeyPairXWing(t *testing.T) {
	keyPair, err := NewXWingKeyPair()
	require.NoError(t, err)
	assert.Equal(t, HybridXWingKey, keyPair.GetKeyType())
}

func TestXWingWrapUnwrapRoundTrip(t *testing.T) {
	keyPair, err := NewXWingKeyPair()
	require.NoError(t, err)

	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := wrapDEKWithKEM(xwingKEM{}, keyPair.publicKey, dek, nil, nil)
	require.NoError(t, err)

	plaintext, err := unwrapDEKWithKEM(xwingKEM{}, keyPair.privateKey, wrapped, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)
}

func TestXWingWrapUnwrapWrongKeyFails(t *testing.T) {
	keyPair, err := NewXWingKeyPair()
	require.NoError(t, err)
	wrongKeyPair, err := NewXWingKeyPair()
	require.NoError(t, err)

	wrapped, err := wrapDEKWithKEM(xwingKEM{}, keyPair.publicKey, []byte("top secret dek"), nil, nil)
	require.NoError(t, err)

	_, err = unwrapDEKWithKEM(xwingKEM{}, wrongKeyPair.privateKey, wrapped, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AES-GCM decrypt failed")
}

func TestXWingPEMDispatch(t *testing.T) {
	keyPair, err := NewXWingKeyPair()
	require.NoError(t, err)

	publicPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privatePEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	encryptor, err := FromPublicPEMWithSalt(publicPEM, []byte("salt"), []byte("info"))
	require.NoError(t, err)

	decryptor, err := FromPrivatePEMWithSalt(privatePEM, []byte("salt"), []byte("info"))
	require.NoError(t, err)

	xwingEncryptor, ok := encryptor.(*kemEncryptor)
	require.True(t, ok)
	assert.Equal(t, Hybrid, xwingEncryptor.Type())
	assert.Equal(t, HybridXWingKey, xwingEncryptor.KeyType())
	assert.Nil(t, xwingEncryptor.EphemeralKey())

	metadata, err := xwingEncryptor.Metadata()
	require.NoError(t, err)
	assert.Empty(t, metadata)

	xwingDecryptor, ok := decryptor.(*kemDecryptor)
	require.True(t, ok)

	wrapped, err := xwingEncryptor.Encrypt([]byte("dispatch-dek"))
	require.NoError(t, err)

	plaintext, err := xwingDecryptor.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, []byte("dispatch-dek"), plaintext)
}

// TestXWingPEMShape verifies that the emitted PEM blocks carry the X-Wing
// OID inside standard SPKI/PKCS#8 envelopes per draft-connolly-cfrg-xwing-kem-10.
func TestXWingPEMShape(t *testing.T) {
	kp, err := NewXWingKeyPair()
	require.NoError(t, err)

	pubPEM, err := kp.PublicKeyInPemFormat()
	require.NoError(t, err)
	pubBlock, _ := pem.Decode([]byte(pubPEM))
	require.NotNil(t, pubBlock)
	assert.Equal(t, "PUBLIC KEY", pubBlock.Type)
	gotOID, raw, err := parseHybridSPKI(pubBlock.Bytes)
	require.NoError(t, err)
	assert.True(t, gotOID.Equal(oidXWing))
	assert.Len(t, raw, XWingPublicKeySize)

	privPEM, err := kp.PrivateKeyInPemFormat()
	require.NoError(t, err)
	privBlock, _ := pem.Decode([]byte(privPEM))
	require.NotNil(t, privBlock)
	assert.Equal(t, "PRIVATE KEY", privBlock.Type)
	gotOID, raw, err = parseHybridPKCS8(privBlock.Bytes)
	require.NoError(t, err)
	assert.True(t, gotOID.Equal(oidXWing))
	assert.Len(t, raw, XWingPrivateKeySize)
}

func TestXWingEncapsulate(t *testing.T) {
	keyPair, err := NewXWingKeyPair()
	require.NoError(t, err)

	sharedSecret, ciphertext, err := XWingEncapsulate(keyPair.publicKey)
	require.NoError(t, err)
	assert.Len(t, sharedSecret, 32)
	assert.Len(t, ciphertext, XWingCiphertextSize)
}

func TestXWingEncapsulateInvalidKeySize(t *testing.T) {
	_, _, err := XWingEncapsulate([]byte("too-short"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid X-Wing public key size")
}
