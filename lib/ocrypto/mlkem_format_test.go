package ocrypto

import (
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMLKEM768WrapDEKFormats verifies that MLKEM768WrapDEK accepts raw, SPKI DER, and PEM formats
func TestMLKEM768WrapDEKFormats(t *testing.T) {
	keyPair, err := NewMLKEMKeyPair()
	require.NoError(t, err)

	dek := []byte("0123456789abcdef0123456789abcdef")

	// Test 1: Raw key (1184 bytes)
	rawKey := keyPair.PrivateKey.EncapsulationKey().Bytes()
	require.Len(t, rawKey, MLKEM768PublicKeySize)

	wrappedFromRaw, err := MLKEM768WrapDEK(rawKey, dek)
	require.NoError(t, err, "Should accept raw key")

	// Test 2: SPKI DER (1206 bytes)
	spkiDER, err := marshalMLKEMPublicSPKI(OidMLKEM768, rawKey)
	require.NoError(t, err)
	require.Greater(t, len(spkiDER), len(rawKey), "SPKI DER should be larger than raw key")

	wrappedFromSPKI, err := MLKEM768WrapDEK(spkiDER, dek)
	require.NoError(t, err, "Should accept SPKI DER")

	// Test 3: PEM-wrapped SPKI (~1686 bytes)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemBlockPublicKey, Bytes: spkiDER})
	require.Greater(t, len(pemBytes), len(spkiDER), "PEM should be larger than DER")

	wrappedFromPEM, err := MLKEM768WrapDEK(pemBytes, dek)
	require.NoError(t, err, "Should accept PEM-wrapped SPKI")

	// Verify we can unwrap all three (ML-KEM uses randomness, so wrapped results differ each time)
	privateKeyBytes := keyPair.PrivateKey.Bytes()

	plaintext1, err := MLKEM768UnwrapDEK(privateKeyBytes, wrappedFromRaw)
	require.NoError(t, err, "Should unwrap from raw key wrapping")
	assert.Equal(t, dek, plaintext1)

	plaintext2, err := MLKEM768UnwrapDEK(privateKeyBytes, wrappedFromSPKI)
	require.NoError(t, err, "Should unwrap from SPKI DER wrapping")
	assert.Equal(t, dek, plaintext2)

	plaintext3, err := MLKEM768UnwrapDEK(privateKeyBytes, wrappedFromPEM)
	require.NoError(t, err, "Should unwrap from PEM wrapping")
	assert.Equal(t, dek, plaintext3)
}

// TestMLKEM1024WrapDEKFormats verifies that MLKEM1024WrapDEK accepts raw, SPKI DER, and PEM formats
func TestMLKEM1024WrapDEKFormats(t *testing.T) {
	keyPair, err := NewMLKEM1024KeyPair()
	require.NoError(t, err)

	dek := []byte("0123456789abcdef0123456789abcdef")

	// Test 1: Raw key (1568 bytes)
	rawKey := keyPair.PrivateKey.EncapsulationKey().Bytes()
	require.Len(t, rawKey, MLKEM1024PublicKeySize)

	wrappedFromRaw, err := MLKEM1024WrapDEK(rawKey, dek)
	require.NoError(t, err, "Should accept raw key")

	// Test 2: SPKI DER (1590 bytes)
	spkiDER, err := marshalMLKEMPublicSPKI(OidMLKEM1024, rawKey)
	require.NoError(t, err)
	require.Greater(t, len(spkiDER), len(rawKey), "SPKI DER should be larger than raw key")

	wrappedFromSPKI, err := MLKEM1024WrapDEK(spkiDER, dek)
	require.NoError(t, err, "Should accept SPKI DER")

	// Test 3: PEM-wrapped SPKI (~2206 bytes)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemBlockPublicKey, Bytes: spkiDER})
	require.Greater(t, len(pemBytes), len(spkiDER), "PEM should be larger than DER")

	wrappedFromPEM, err := MLKEM1024WrapDEK(pemBytes, dek)
	require.NoError(t, err, "Should accept PEM-wrapped SPKI")

	// Verify we can unwrap all three (ML-KEM uses randomness, so wrapped results differ each time)
	privateKeyBytes := keyPair.PrivateKey.Bytes()

	plaintext1, err := MLKEM1024UnwrapDEK(privateKeyBytes, wrappedFromRaw)
	require.NoError(t, err, "Should unwrap from raw key wrapping")
	assert.Equal(t, dek, plaintext1)

	plaintext2, err := MLKEM1024UnwrapDEK(privateKeyBytes, wrappedFromSPKI)
	require.NoError(t, err, "Should unwrap from SPKI DER wrapping")
	assert.Equal(t, dek, plaintext2)

	plaintext3, err := MLKEM1024UnwrapDEK(privateKeyBytes, wrappedFromPEM)
	require.NoError(t, err, "Should unwrap from PEM wrapping")
	assert.Equal(t, dek, plaintext3)
}

// TestMLKEM768WrapDEKInvalidFormats verifies error handling for invalid inputs
func TestMLKEM768WrapDEKInvalidFormats(t *testing.T) {
	dek := []byte("0123456789abcdef0123456789abcdef")

	// Wrong size raw key
	wrongSizeRaw := make([]byte, 100)
	_, err := MLKEM768WrapDEK(wrongSizeRaw, dek)
	require.Error(t, err, "Should reject wrong-size raw key")

	// Wrong OID in SPKI
	keyPair1024, err := NewMLKEM1024KeyPair()
	require.NoError(t, err)
	spki1024, err := marshalMLKEMPublicSPKI(OidMLKEM1024, keyPair1024.PrivateKey.EncapsulationKey().Bytes())
	require.NoError(t, err)

	_, err = MLKEM768WrapDEK(spki1024, dek)
	require.Error(t, err, "Should reject ML-KEM-1024 SPKI when expecting ML-KEM-768")
	assert.Contains(t, err.Error(), "OID mismatch")

	// Invalid PEM
	invalidPEM := []byte("-----BEGIN PUBLIC KEY-----\ninvalid base64\n-----END PUBLIC KEY-----")
	_, err = MLKEM768WrapDEK(invalidPEM, dek)
	require.Error(t, err, "Should reject invalid PEM")
}
