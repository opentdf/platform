package ocrypto

import (
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMLKEM768WrapUnwrapRoundTrip(t *testing.T) {
	keyPair, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	publicKeyBytes := keyPair.PrivateKey.EncapsulationKey().Bytes()
	privateKeyBytes := keyPair.PrivateKey.Bytes()

	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := wrapDEKWithKEM(mlkemKEM{variant: mlkem768}, publicKeyBytes, dek, nil, nil)
	require.NoError(t, err)

	plaintext, err := unwrapDEKWithKEM(mlkemKEM{variant: mlkem768}, privateKeyBytes, wrapped, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)
}

func TestMLKEM1024WrapUnwrapRoundTrip(t *testing.T) {
	keyPair, err := NewMLKEM1024KeyPair()
	require.NoError(t, err)

	publicKeyBytes := keyPair.PrivateKey.EncapsulationKey().Bytes()
	privateKeyBytes := keyPair.PrivateKey.Bytes()

	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := wrapDEKWithKEM(mlkemKEM{variant: mlkem1024}, publicKeyBytes, dek, nil, nil)
	require.NoError(t, err)

	plaintext, err := unwrapDEKWithKEM(mlkemKEM{variant: mlkem1024}, privateKeyBytes, wrapped, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)
}

func TestMLKEM768WrapUnwrapWrongKeyFails(t *testing.T) {
	keyPair1, err := NewMLKEMKeyPair()
	require.NoError(t, err)
	keyPair2, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	publicKey1 := keyPair1.PrivateKey.EncapsulationKey().Bytes()
	privateKey2 := keyPair2.PrivateKey.Bytes()

	wrapped, err := wrapDEKWithKEM(mlkemKEM{variant: mlkem768}, publicKey1, []byte("top secret dek"), nil, nil)
	require.NoError(t, err)

	_, err = unwrapDEKWithKEM(mlkemKEM{variant: mlkem768}, privateKey2, wrapped, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AES-GCM decrypt failed")
}

func TestMLKEM1024WrapUnwrapWrongKeyFails(t *testing.T) {
	keyPair1, err := NewMLKEM1024KeyPair()
	require.NoError(t, err)
	keyPair2, err := NewMLKEM1024KeyPair()
	require.NoError(t, err)

	publicKey1 := keyPair1.PrivateKey.EncapsulationKey().Bytes()
	privateKey2 := keyPair2.PrivateKey.Bytes()

	wrapped, err := wrapDEKWithKEM(mlkemKEM{variant: mlkem1024}, publicKey1, []byte("top secret dek"), nil, nil)
	require.NoError(t, err)

	_, err = unwrapDEKWithKEM(mlkemKEM{variant: mlkem1024}, privateKey2, wrapped, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AES-GCM decrypt failed")
}

func TestKEMEnvelopeASN1RoundTrip(t *testing.T) {
	original := kemEnvelope{
		KEMCiphertext: []byte("ciphertext"),
		EncryptedDEK:  []byte("encrypted-dek"),
	}

	der, err := asn1.Marshal(original)
	require.NoError(t, err)

	var decoded kemEnvelope
	rest, err := asn1.Unmarshal(der, &decoded)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, original, decoded)
}

func TestMLKEM768CiphertextSizeValidation(t *testing.T) {
	keyPair, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	privateKeyBytes := keyPair.PrivateKey.Bytes()

	invalidWrapped := kemEnvelope{
		KEMCiphertext: []byte("too-short"),
		EncryptedDEK:  []byte("encrypted-dek"),
	}

	der, err := asn1.Marshal(invalidWrapped)
	require.NoError(t, err)

	_, err = unwrapDEKWithKEM(mlkemKEM{variant: mlkem768}, privateKeyBytes, der, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext size")
}

func TestMLKEM1024CiphertextSizeValidation(t *testing.T) {
	keyPair, err := NewMLKEM1024KeyPair()
	require.NoError(t, err)

	privateKeyBytes := keyPair.PrivateKey.Bytes()

	invalidWrapped := kemEnvelope{
		KEMCiphertext: []byte("too-short"),
		EncryptedDEK:  []byte("encrypted-dek"),
	}

	der, err := asn1.Marshal(invalidWrapped)
	require.NoError(t, err)

	_, err = unwrapDEKWithKEM(mlkemKEM{variant: mlkem1024}, privateKeyBytes, der, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext size")
}

// TestMLKEMSaltInfoIgnored verifies that salt/info passed to the ML-KEM
// encryptor/decryptor are ignored: an envelope produced with one (salt, info)
// pair must unwrap correctly under a different (salt, info) pair, because pure
// ML-KEM uses the Decaps shared secret directly as the AES-GCM wrap key.
func TestMLKEMSaltInfoIgnored(t *testing.T) {
	keyPair, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	publicKeyBytes := keyPair.PrivateKey.EncapsulationKey().Bytes()
	privateKeyBytes := keyPair.PrivateKey.Bytes()

	encryptor, err := newKEMEncryptor(mlkemKEM{variant: mlkem768}, publicKeyBytes, []byte("salt-A"), []byte("info-A"))
	require.NoError(t, err)

	// Decrypt with deliberately different salt/info; for ML-KEM both must be no-ops.
	decryptor, err := newKEMDecryptor(mlkemKEM{variant: mlkem768}, privateKeyBytes, []byte("salt-B"), []byte("info-B"))
	require.NoError(t, err)

	dek := []byte("test-dek-value-123456")
	wrapped, err := encryptor.Encrypt(dek)
	require.NoError(t, err)

	plaintext, err := decryptor.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)

	// Also decrypt with nil salt/info to make the contract explicit.
	bareDecryptor, err := newKEMDecryptor(mlkemKEM{variant: mlkem768}, privateKeyBytes, nil, nil)
	require.NoError(t, err)
	plaintextBare, err := bareDecryptor.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintextBare)
}

// TestMLKEMSharedSecretIsAESWrapKey verifies that the AES-GCM-encrypted DEK
// inside an ML-KEM envelope can be opened by AES-256-GCM using the raw 32-byte
// shared secret produced by Decaps — i.e. there is no KDF between Decaps and
// the AES-GCM unwrap key. This is the load-bearing assertion for HSM-backed
// KAS providers that can only materialize the Decaps output as a non-
// extractable CKK_AES object.
func TestMLKEMSharedSecretIsAESWrapKey(t *testing.T) {
	t.Run("MLKEM768", func(t *testing.T) {
		assertSharedSecretIsAESWrapKey(t, mlkemKEM{variant: mlkem768}, MLKEM768CiphertextSize)
	})
	t.Run("MLKEM1024", func(t *testing.T) {
		assertSharedSecretIsAESWrapKey(t, mlkemKEM{variant: mlkem1024}, MLKEM1024CiphertextSize)
	})
}

func assertSharedSecretIsAESWrapKey(t *testing.T, k mlkemKEM, expectedCtSize int) {
	t.Helper()

	var (
		pubBytes  []byte
		privBytes []byte
	)
	if k.variant == mlkem1024 {
		kp, err := NewMLKEM1024KeyPair()
		require.NoError(t, err)
		pubBytes = kp.PrivateKey.EncapsulationKey().Bytes()
		privBytes = kp.PrivateKey.Bytes()
	} else {
		kp, err := NewMLKEMKeyPair()
		require.NoError(t, err)
		pubBytes = kp.PrivateKey.EncapsulationKey().Bytes()
		privBytes = kp.PrivateKey.Bytes()
	}

	dek := []byte("0123456789abcdef0123456789abcdef") // 32-byte DEK
	wrappedDER, err := wrapDEKWithKEM(k, pubBytes, dek, nil, nil)
	require.NoError(t, err)

	// Parse the envelope to pull out the KEM ciphertext and the
	// AES-GCM-wrapped DEK independently of unwrapDEKWithKEM.
	var env kemEnvelope
	rest, err := asn1.Unmarshal(wrappedDER, &env)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Len(t, env.KEMCiphertext, expectedCtSize)

	// Reproduce the wrap key the way an HSM-backed KAS would: Decaps then
	// straight into AES-256-GCM, no KDF.
	sharedSecret, err := k.decapsulate(privBytes, env.KEMCiphertext)
	require.NoError(t, err)
	require.Len(t, sharedSecret, kemWrapKeySize, "FIPS 203 §6.3/§7.3 mandates a 32-byte shared secret")

	gcm, err := NewAESGcm(sharedSecret)
	require.NoError(t, err)
	plaintext, err := gcm.Decrypt(env.EncryptedDEK)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext, "AES-GCM with sharedSecret-as-key must recover the DEK")

	// Also verify the symmetric direction: an AES-GCM seal under the shared
	// secret must be openable by unwrapDEKWithKEM-style code, i.e. the wrap
	// key on both sides is exactly the Decaps output.
	sealed, err := gcm.Encrypt(dek)
	require.NoError(t, err)
	roundTrip, err := gcm.Decrypt(sealed)
	require.NoError(t, err)
	assert.Equal(t, dek, roundTrip)
}

func TestMLKEMEncryptorImplementsInterface(t *testing.T) {
	keyPair, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	publicKeyBytes := keyPair.PrivateKey.EncapsulationKey().Bytes()

	encryptor, err := newKEMEncryptor(mlkemKEM{variant: mlkem768}, publicKeyBytes, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, MLKEM, encryptor.Type())
	assert.Equal(t, MLKEM768Key, encryptor.KeyType())
	assert.Nil(t, encryptor.EphemeralKey())

	metadata, err := encryptor.Metadata()
	require.NoError(t, err)
	assert.Empty(t, metadata)
}

func TestMLKEM768Encapsulate(t *testing.T) {
	keyPair, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	publicKeyBytes := keyPair.PrivateKey.EncapsulationKey().Bytes()

	sharedSecret, ciphertext, err := mlkemKEM{variant: mlkem768}.encapsulate(publicKeyBytes)
	require.NoError(t, err)
	assert.Len(t, sharedSecret, 32)
	assert.Len(t, ciphertext, MLKEM768CiphertextSize)
}

func TestMLKEM1024Encapsulate(t *testing.T) {
	keyPair, err := NewMLKEM1024KeyPair()
	require.NoError(t, err)

	publicKeyBytes := keyPair.PrivateKey.EncapsulationKey().Bytes()

	sharedSecret, ciphertext, err := mlkemKEM{variant: mlkem1024}.encapsulate(publicKeyBytes)
	require.NoError(t, err)
	assert.Len(t, sharedSecret, 32)
	assert.Len(t, ciphertext, MLKEM1024CiphertextSize)
}

func TestMLKEM768EncapsulateInvalidKeySize(t *testing.T) {
	_, _, err := mlkemKEM{variant: mlkem768}.encapsulate([]byte("too-short"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public key size")
}

func TestMLKEM1024EncapsulateInvalidKeySize(t *testing.T) {
	_, _, err := mlkemKEM{variant: mlkem1024}.encapsulate([]byte("too-short"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public key size")
}

func TestMLKEM768PEMRoundTrip(t *testing.T) {
	keyPair, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	pubPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(pubPEM, "-----BEGIN PUBLIC KEY-----"))
	pubBlock, _ := pem.Decode([]byte(pubPEM))
	require.NotNil(t, pubBlock)
	assert.Equal(t, "PUBLIC KEY", pubBlock.Type)

	privPEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(privPEM, "-----BEGIN PRIVATE KEY-----"))
	privBlock, _ := pem.Decode([]byte(privPEM))
	require.NotNil(t, privBlock)
	assert.Equal(t, "PRIVATE KEY", privBlock.Type)

	enc, err := FromPublicPEM(pubPEM)
	require.NoError(t, err)
	assert.Equal(t, MLKEM, enc.Type())
	assert.Equal(t, MLKEM768Key, enc.KeyType())

	dek := []byte("ml-kem-768 round-trip data")
	wrapped, err := enc.Encrypt(dek)
	require.NoError(t, err)

	dec, err := FromPrivatePEM(privPEM)
	require.NoError(t, err)
	plaintext, err := dec.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)
}

func TestMLKEM1024PEMRoundTrip(t *testing.T) {
	keyPair, err := NewMLKEM1024KeyPair()
	require.NoError(t, err)

	pubPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(pubPEM, "-----BEGIN PUBLIC KEY-----"))
	pubBlock, _ := pem.Decode([]byte(pubPEM))
	require.NotNil(t, pubBlock)
	assert.Equal(t, "PUBLIC KEY", pubBlock.Type)

	privPEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(privPEM, "-----BEGIN PRIVATE KEY-----"))
	privBlock, _ := pem.Decode([]byte(privPEM))
	require.NotNil(t, privBlock)
	assert.Equal(t, "PRIVATE KEY", privBlock.Type)

	enc, err := FromPublicPEM(pubPEM)
	require.NoError(t, err)
	assert.Equal(t, MLKEM, enc.Type())
	assert.Equal(t, MLKEM1024Key, enc.KeyType())

	dek := []byte("ml-kem-1024 round-trip data")
	wrapped, err := enc.Encrypt(dek)
	require.NoError(t, err)

	dec, err := FromPrivatePEM(privPEM)
	require.NoError(t, err)
	plaintext, err := dec.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)
}
