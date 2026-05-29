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
	wrapped, err := MLKEM768WrapDEK(publicKeyBytes, dek)
	require.NoError(t, err)

	plaintext, err := MLKEM768UnwrapDEK(privateKeyBytes, wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)
}

func TestMLKEM1024WrapUnwrapRoundTrip(t *testing.T) {
	keyPair, err := NewMLKEM1024KeyPair()
	require.NoError(t, err)

	publicKeyBytes := keyPair.PrivateKey.EncapsulationKey().Bytes()
	privateKeyBytes := keyPair.PrivateKey.Bytes()

	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := MLKEM1024WrapDEK(publicKeyBytes, dek)
	require.NoError(t, err)

	plaintext, err := MLKEM1024UnwrapDEK(privateKeyBytes, wrapped)
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

	wrapped, err := MLKEM768WrapDEK(publicKey1, []byte("top secret dek"))
	require.NoError(t, err)

	_, err = MLKEM768UnwrapDEK(privateKey2, wrapped)
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

	wrapped, err := MLKEM1024WrapDEK(publicKey1, []byte("top secret dek"))
	require.NoError(t, err)

	_, err = MLKEM1024UnwrapDEK(privateKey2, wrapped)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AES-GCM decrypt failed")
}

func TestMLKEMWrappedKeyASN1RoundTrip(t *testing.T) {
	original := MLKEMWrappedKey{
		MLKEMCiphertext: []byte("ciphertext"),
		EncryptedDEK:    []byte("encrypted-dek"),
	}

	der, err := asn1.Marshal(original)
	require.NoError(t, err)

	var decoded MLKEMWrappedKey
	rest, err := asn1.Unmarshal(der, &decoded)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, original, decoded)
}

func TestMLKEM768CiphertextSizeValidation(t *testing.T) {
	keyPair, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	privateKeyBytes := keyPair.PrivateKey.Bytes()

	invalidWrapped := MLKEMWrappedKey{
		MLKEMCiphertext: []byte("too-short"),
		EncryptedDEK:    []byte("encrypted-dek"),
	}

	der, err := asn1.Marshal(invalidWrapped)
	require.NoError(t, err)

	_, err = MLKEM768UnwrapDEK(privateKeyBytes, der)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ML-KEM-768 ciphertext size")
}

func TestMLKEM1024CiphertextSizeValidation(t *testing.T) {
	keyPair, err := NewMLKEM1024KeyPair()
	require.NoError(t, err)

	privateKeyBytes := keyPair.PrivateKey.Bytes()

	invalidWrapped := MLKEMWrappedKey{
		MLKEMCiphertext: []byte("too-short"),
		EncryptedDEK:    []byte("encrypted-dek"),
	}

	der, err := asn1.Marshal(invalidWrapped)
	require.NoError(t, err)

	_, err = MLKEM1024UnwrapDEK(privateKeyBytes, der)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ML-KEM-1024 ciphertext size")
}

func TestMLKEMCustomSaltInfo(t *testing.T) {
	keyPair, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	publicKeyBytes := keyPair.PrivateKey.EncapsulationKey().Bytes()
	privateKeyBytes := keyPair.PrivateKey.Bytes()

	customSalt := []byte("custom-salt-value")
	customInfo := []byte("custom-info-value")

	encryptor, err := NewMLKEM768Encryptor(publicKeyBytes, customSalt, customInfo)
	require.NoError(t, err)

	decryptor, err := NewSaltedMLKEM768Decryptor(privateKeyBytes, customSalt, customInfo)
	require.NoError(t, err)

	dek := []byte("test-dek-value-123456")
	wrapped, err := encryptor.Encrypt(dek)
	require.NoError(t, err)

	plaintext, err := decryptor.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)
}

func TestMLKEMEncryptorImplementsInterface(t *testing.T) {
	keyPair, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	publicKeyBytes := keyPair.PrivateKey.EncapsulationKey().Bytes()

	encryptor, err := NewMLKEM768Encryptor(publicKeyBytes, nil, nil)
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

	sharedSecret, ciphertext, err := MLKEM768Encapsulate(publicKeyBytes)
	require.NoError(t, err)
	assert.Len(t, sharedSecret, 32)
	assert.Len(t, ciphertext, MLKEM768CiphertextSize)
}

func TestMLKEM1024Encapsulate(t *testing.T) {
	keyPair, err := NewMLKEM1024KeyPair()
	require.NoError(t, err)

	publicKeyBytes := keyPair.PrivateKey.EncapsulationKey().Bytes()

	sharedSecret, ciphertext, err := MLKEM1024Encapsulate(publicKeyBytes)
	require.NoError(t, err)
	assert.Len(t, sharedSecret, 32)
	assert.Len(t, ciphertext, MLKEM1024CiphertextSize)
}

func TestMLKEM768EncapsulateInvalidKeySize(t *testing.T) {
	_, _, err := MLKEM768Encapsulate([]byte("too-short"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ML-KEM-768 public key size")
}

func TestMLKEM1024EncapsulateInvalidKeySize(t *testing.T) {
	_, _, err := MLKEM1024Encapsulate([]byte("too-short"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ML-KEM-1024 public key size")
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
