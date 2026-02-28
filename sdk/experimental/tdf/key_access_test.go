// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/experimental/tdf/keysplit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test constants for key access operations
const (
	testKAS1URL = "https://kas1.example.com/"
	testKAS2URL = "https://kas2.example.com/"

	// Real RSA-2048 public keys for testing key wrapping
	testRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQ2ZuyT/p32SFmWTj+wQ
huQwR4IJSzlJ7CqZ4fOXw90rA2joK27dIGiHrtkQHGhS4SK1mvkYyJaREoppMFRc
AyZWCgixbSdwYJS/KN0hjLIdhtkdBlZDaZN2ayTf2sZjWzOLL2cYzzVsAy9tGL8a
bMqf91DEHv+l58fPxmbJ/i6YFFQoOEsyWnPhXdiExe6poQDCHJFYYOp6iu5kOPWr
jKFj9eGXuFR/CJQ/uxTSM+8/7Ejmi8Oa52TQAUhMPH0U1CRFm/NuiFoFissa0jJC
J3k6syxvf45mPrbtlhcELskXrquDtJOpIMQmEwfuV4j8iLNwVlsR2tAbClJi6UOy
SQIDAQAB
-----END PUBLIC KEY-----`

	testMetadata   = "test metadata content"
	testPolicyJSON = `{"uuid":"test","body":{"dataAttributes":[{"attribute":"test"}],"dissem":[]}}`
)

// createTestSplitResult creates a mock SplitResult for testing key access operations
func createTestSplitResult(kasURL, pubKey string, algorithm string) *keysplit.SplitResult {
	// Generate random split data
	splitData := make([]byte, 32)
	_, err := rand.Read(splitData)
	if err != nil {
		panic("failed to generate test split data: " + err.Error())
	}

	split := keysplit.Split{
		ID:      "test-split-1",
		Data:    splitData,
		KASURLs: []string{kasURL},
	}

	pubKeyInfo := keysplit.KASPublicKey{
		URL:       kasURL,
		Algorithm: algorithm,
		KID:       "test-kid-1",
		PEM:       pubKey,
	}

	return &keysplit.SplitResult{
		Splits:        []keysplit.Split{split},
		KASPublicKeys: map[string]keysplit.KASPublicKey{kasURL: pubKeyInfo},
	}
}

func TestBuildKeyAccessObjects(t *testing.T) {
	t.Run("successfully creates key access objects with RSA public key", func(t *testing.T) {
		// Test that buildKeyAccessObjects correctly processes RSA keys and creates valid KeyAccess objects
		splitResult := createTestSplitResult(testKAS1URL, testRSAPublicKey, "rsa:2048")
		policyBytes := []byte(testPolicyJSON)
		metadata := testMetadata

		keyAccessList, err := buildKeyAccessObjects(splitResult, policyBytes, metadata)

		require.NoError(t, err, "Should successfully create key access objects with valid RSA key")
		require.Len(t, keyAccessList, 1, "Should create exactly one key access object")

		keyAccess := keyAccessList[0]
		assert.Equal(t, "wrapped", keyAccess.KeyType, "RSA keys should use 'wrapped' key type")
		assert.Equal(t, testKAS1URL, keyAccess.KasURL, "Should preserve KAS URL")
		assert.Equal(t, "test-kid-1", keyAccess.KID, "Should preserve key ID")
		assert.Equal(t, "kas", keyAccess.Protocol, "Should use 'kas' protocol")
		assert.Equal(t, "test-split-1", keyAccess.SplitID, "Should preserve split ID")
		assert.NotEmpty(t, keyAccess.WrappedKey, "Should contain wrapped key data")
		assert.NotEmpty(t, keyAccess.PolicyBinding, "Should contain policy binding")
		assert.NotEmpty(t, keyAccess.EncryptedMetadata, "Should contain encrypted metadata")
		assert.Empty(t, keyAccess.EphemeralPublicKey, "RSA keys should not have ephemeral public key")
	})

	t.Run("successfully creates key access objects with EC public key", func(t *testing.T) {
		// Test that buildKeyAccessObjects correctly handles elliptic curve keys with ephemeral key generation

		// Generate a real EC P-256 key pair for testing
		ecKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
		require.NoError(t, err, "Should generate EC key pair")

		ecPublicKeyPEM, err := ecKeyPair.PublicKeyInPemFormat()
		require.NoError(t, err, "Should get public key in PEM format")

		splitResult := createTestSplitResult(testKAS1URL, ecPublicKeyPEM, "ec:secp256r1")
		policyBytes := []byte(testPolicyJSON)
		metadata := testMetadata

		keyAccessList, err := buildKeyAccessObjects(splitResult, policyBytes, metadata)

		require.NoError(t, err, "Should successfully create key access objects with valid EC key")
		require.Len(t, keyAccessList, 1, "Should create exactly one key access object")

		keyAccess := keyAccessList[0]
		assert.Equal(t, "eccWrapped", keyAccess.KeyType, "EC keys should use 'eccWrapped' key type")
		assert.Equal(t, testKAS1URL, keyAccess.KasURL, "Should preserve KAS URL")
		assert.NotEmpty(t, keyAccess.EphemeralPublicKey, "EC keys should have ephemeral public key")
		assert.NotEmpty(t, keyAccess.WrappedKey, "Should contain wrapped key data")
	})

	t.Run("handles multiple KAS URLs in single split", func(t *testing.T) {
		// Test that multiple KAS URLs in one split create separate KeyAccess objects
		splitData := make([]byte, 32)
		_, err := rand.Read(splitData)
		require.NoError(t, err)

		split := keysplit.Split{
			ID:      "multi-kas-split",
			Data:    splitData,
			KASURLs: []string{testKAS1URL, testKAS2URL},
		}

		splitResult := &keysplit.SplitResult{
			Splits: []keysplit.Split{split},
			KASPublicKeys: map[string]keysplit.KASPublicKey{
				testKAS1URL: {URL: testKAS1URL, Algorithm: "rsa:2048", KID: "kid1", PEM: testRSAPublicKey},
				testKAS2URL: {URL: testKAS2URL, Algorithm: "rsa:2048", KID: "kid2", PEM: testRSAPublicKey},
			},
		}

		keyAccessList, err := buildKeyAccessObjects(splitResult, []byte(testPolicyJSON), "")

		require.NoError(t, err, "Should handle multiple KAS URLs")
		assert.Len(t, keyAccessList, 2, "Should create separate KeyAccess for each KAS URL")

		kasURLs := []string{keyAccessList[0].KasURL, keyAccessList[1].KasURL}
		assert.Contains(t, kasURLs, testKAS1URL, "Should include first KAS URL")
		assert.Contains(t, kasURLs, testKAS2URL, "Should include second KAS URL")
	})

	t.Run("skips KAS URLs without public keys", func(t *testing.T) {
		// Test that missing public keys are handled gracefully by skipping those KAS
		splitData := make([]byte, 32)
		_, err := rand.Read(splitData)
		require.NoError(t, err)

		split := keysplit.Split{
			ID:      "missing-key-split",
			Data:    splitData,
			KASURLs: []string{testKAS1URL, testKAS2URL},
		}

		// Only provide public key for one KAS
		splitResult := &keysplit.SplitResult{
			Splits: []keysplit.Split{split},
			KASPublicKeys: map[string]keysplit.KASPublicKey{
				testKAS1URL: {URL: testKAS1URL, Algorithm: "rsa:2048", KID: "kid1", PEM: testRSAPublicKey},
				// testKAS2URL intentionally missing
			},
		}

		keyAccessList, err := buildKeyAccessObjects(splitResult, []byte(testPolicyJSON), "")

		require.NoError(t, err, "Should handle missing public keys gracefully")
		assert.Len(t, keyAccessList, 1, "Should create KeyAccess only for KAS with public key")
		assert.Equal(t, testKAS1URL, keyAccessList[0].KasURL, "Should use KAS with available public key")
	})

	t.Run("handles empty metadata correctly", func(t *testing.T) {
		// Test that empty metadata is handled without creating encrypted metadata
		splitResult := createTestSplitResult(testKAS1URL, testRSAPublicKey, "rsa:2048")

		keyAccessList, err := buildKeyAccessObjects(splitResult, []byte(testPolicyJSON), "")

		require.NoError(t, err, "Should handle empty metadata")
		require.Len(t, keyAccessList, 1, "Should create key access object")
		assert.Empty(t, keyAccessList[0].EncryptedMetadata, "Should not create encrypted metadata for empty input")
	})

	t.Run("returns error for nil split result", func(t *testing.T) {
		// Test error handling for invalid input
		_, err := buildKeyAccessObjects(nil, []byte(testPolicyJSON), "")

		require.Error(t, err, "Should return error for nil split result")
		assert.Contains(t, err.Error(), "no splits provided", "Error should mention missing splits")
	})

	t.Run("returns error for empty splits", func(t *testing.T) {
		// Test error handling for empty splits list
		splitResult := &keysplit.SplitResult{
			Splits:        []keysplit.Split{},
			KASPublicKeys: map[string]keysplit.KASPublicKey{},
		}

		_, err := buildKeyAccessObjects(splitResult, []byte(testPolicyJSON), "")

		require.Error(t, err, "Should return error for empty splits")
		assert.Contains(t, err.Error(), "no splits provided", "Error should mention missing splits")
	})

	t.Run("returns error when no valid key access objects generated", func(t *testing.T) {
		// Test error when all KAS URLs lack public keys
		splitData := make([]byte, 32)
		_, err := rand.Read(splitData)
		require.NoError(t, err)

		split := keysplit.Split{
			ID:      "no-keys-split",
			Data:    splitData,
			KASURLs: []string{testKAS1URL},
		}

		splitResult := &keysplit.SplitResult{
			Splits:        []keysplit.Split{split},
			KASPublicKeys: map[string]keysplit.KASPublicKey{}, // Empty - no public keys
		}

		_, err = buildKeyAccessObjects(splitResult, []byte(testPolicyJSON), "")

		require.Error(t, err, "Should return error when no key access objects can be generated")
		assert.Contains(t, err.Error(), "no valid key access objects generated", "Error should mention no valid objects")
	})
}

func TestCreatePolicyBinding(t *testing.T) {
	t.Run("creates consistent HMAC policy binding", func(t *testing.T) {
		// Test that policy binding creates consistent HMAC hash
		symKey := make([]byte, 32)
		_, err := rand.Read(symKey)
		require.NoError(t, err)

		base64Policy := string(ocrypto.Base64Encode([]byte(testPolicyJSON)))

		policyBinding := createPolicyBinding(symKey, base64Policy)
		assert.Equal(t, "HS256", policyBinding.Alg, "Should use HS256 algorithm")
		assert.NotEmpty(t, policyBinding.Hash, "Should contain hash value")

		// Verify hash is base64 encoded
		_, err = ocrypto.Base64Decode([]byte(policyBinding.Hash))
		require.NoError(t, err, "Hash should be valid base64")
	})

	t.Run("produces different hashes for different policies", func(t *testing.T) {
		// Test that different policies produce different bindings
		symKey := make([]byte, 32)
		_, err := rand.Read(symKey)
		require.NoError(t, err)

		policy1 := string(ocrypto.Base64Encode([]byte(`{"policy": "test1"}`)))
		policy2 := string(ocrypto.Base64Encode([]byte(`{"policy": "test2"}`)))

		pb1 := createPolicyBinding(symKey, policy1)
		pb2 := createPolicyBinding(symKey, policy2)

		hash1 := pb1.Hash
		hash2 := pb2.Hash
		assert.NotEqual(t, hash1, hash2, "Different policies should produce different hashes")
	})

	t.Run("produces different hashes for different keys", func(t *testing.T) {
		// Test that different symmetric keys produce different bindings
		symKey1 := make([]byte, 32)
		symKey2 := make([]byte, 32)
		_, err := rand.Read(symKey1)
		require.NoError(t, err)
		_, err = rand.Read(symKey2)
		require.NoError(t, err)

		policy := string(ocrypto.Base64Encode([]byte(testPolicyJSON)))

		pb1 := createPolicyBinding(symKey1, policy)
		pb2 := createPolicyBinding(symKey2, policy)

		hash1 := pb1.Hash
		hash2 := pb2.Hash
		assert.NotEqual(t, hash1, hash2, "Different keys should produce different hashes")
	})
}

func TestEncryptMetadata(t *testing.T) {
	t.Run("encrypts metadata using AES-GCM", func(t *testing.T) {
		// Test successful metadata encryption with proper structure
		symKey := make([]byte, 32)
		_, err := rand.Read(symKey)
		require.NoError(t, err)

		encryptedMetadata, err := encryptMetadata(symKey, testMetadata)

		require.NoError(t, err, "Should encrypt metadata successfully")
		assert.NotEmpty(t, encryptedMetadata, "Should return encrypted metadata")

		// Verify it's base64 encoded
		decodedJSON, err := ocrypto.Base64Decode([]byte(encryptedMetadata))
		require.NoError(t, err, "Encrypted metadata should be valid base64")

		// Verify JSON structure
		var encMeta EncryptedMetadata
		err = json.Unmarshal(decodedJSON, &encMeta)
		require.NoError(t, err, "Should unmarshal to EncryptedMetadata structure")

		assert.NotEmpty(t, encMeta.Cipher, "Should contain cipher text")
		assert.NotEmpty(t, encMeta.Iv, "Should contain IV")

		// Verify IV and cipher are base64
		_, err = ocrypto.Base64Decode([]byte(encMeta.Iv))
		require.NoError(t, err, "IV should be valid base64")
		_, err = ocrypto.Base64Decode([]byte(encMeta.Cipher))
		require.NoError(t, err, "Cipher should be valid base64")
	})

	t.Run("produces different ciphertext for same metadata with different keys", func(t *testing.T) {
		// Test that different keys produce different encrypted output
		symKey1 := make([]byte, 32)
		symKey2 := make([]byte, 32)
		_, err := rand.Read(symKey1)
		require.NoError(t, err)
		_, err = rand.Read(symKey2)
		require.NoError(t, err)

		encrypted1, err1 := encryptMetadata(symKey1, testMetadata)
		encrypted2, err2 := encryptMetadata(symKey2, testMetadata)

		require.NoError(t, err1, "Should encrypt with first key")
		require.NoError(t, err2, "Should encrypt with second key")
		assert.NotEqual(t, encrypted1, encrypted2, "Different keys should produce different ciphertext")
	})

	t.Run("handles empty metadata", func(t *testing.T) {
		// Test encryption of empty string
		symKey := make([]byte, 32)
		_, err := rand.Read(symKey)
		require.NoError(t, err)

		encryptedMetadata, err := encryptMetadata(symKey, "")

		require.NoError(t, err, "Should handle empty metadata")
		assert.NotEmpty(t, encryptedMetadata, "Should still return encrypted structure")
	})

	t.Run("returns error for invalid key size", func(t *testing.T) {
		// Test error handling for incorrect key size (empty key)
		emptyKey := make([]byte, 0)

		_, err := encryptMetadata(emptyKey, testMetadata)

		require.Error(t, err, "Should return error for empty key")
		assert.Contains(t, err.Error(), "AES-GCM", "Error should mention AES-GCM creation failure")
	})
}

func TestWrapKeyWithPublicKey(t *testing.T) {
	t.Run("wraps key with RSA public key", func(t *testing.T) {
		// Test RSA key wrapping functionality
		symKey := make([]byte, 32)
		_, err := rand.Read(symKey)
		require.NoError(t, err)

		pubKeyInfo := keysplit.KASPublicKey{
			URL:       testKAS1URL,
			Algorithm: "rsa:2048",
			KID:       "test-kid",
			PEM:       testRSAPublicKey,
		}

		wrappedKey, keyType, ephemeralPubKey, err := wrapKeyWithPublicKey(symKey, pubKeyInfo)

		require.NoError(t, err, "Should wrap key with RSA public key")
		assert.NotEmpty(t, wrappedKey, "Should return wrapped key")
		assert.Equal(t, "wrapped", keyType, "RSA keys should use 'wrapped' type")
		assert.Empty(t, ephemeralPubKey, "RSA should not generate ephemeral public key")

		// Verify wrapped key is base64 encoded
		_, err = ocrypto.Base64Decode([]byte(wrappedKey))
		require.NoError(t, err, "Wrapped key should be valid base64")
	})

	t.Run("wraps key with EC public key", func(t *testing.T) {
		// Test elliptic curve key wrapping with ephemeral key generation
		symKey := make([]byte, 32)
		_, err := rand.Read(symKey)
		require.NoError(t, err)

		// Generate a real EC P-256 key pair for testing
		ecKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
		require.NoError(t, err, "Should generate EC key pair")

		ecPublicKeyPEM, err := ecKeyPair.PublicKeyInPemFormat()
		require.NoError(t, err, "Should get public key in PEM format")

		pubKeyInfo := keysplit.KASPublicKey{
			URL:       testKAS1URL,
			Algorithm: "ec:secp256r1",
			KID:       "test-kid",
			PEM:       ecPublicKeyPEM,
		}

		wrappedKey, keyType, ephemeralPubKey, err := wrapKeyWithPublicKey(symKey, pubKeyInfo)

		require.NoError(t, err, "Should wrap key with EC public key")
		assert.NotEmpty(t, wrappedKey, "Should return wrapped key")
		assert.Equal(t, "eccWrapped", keyType, "EC keys should use 'eccWrapped' type")
		assert.NotEmpty(t, ephemeralPubKey, "EC should generate ephemeral public key")

		// Verify ephemeral key is valid PEM
		assert.True(t, strings.HasPrefix(ephemeralPubKey, "-----BEGIN PUBLIC KEY-----"),
			"Ephemeral key should be in PEM format")
		assert.True(t, strings.HasSuffix(ephemeralPubKey, "-----END PUBLIC KEY-----\n"),
			"Ephemeral key should end with PEM footer")
	})

	t.Run("returns error for empty PEM", func(t *testing.T) {
		// Test error handling for missing public key PEM
		symKey := make([]byte, 32)
		_, err := rand.Read(symKey)
		require.NoError(t, err)

		pubKeyInfo := keysplit.KASPublicKey{
			URL:       testKAS1URL,
			Algorithm: "rsa:2048",
			KID:       "test-kid",
			PEM:       "", // Empty PEM
		}

		_, _, _, err = wrapKeyWithPublicKey(symKey, pubKeyInfo)

		require.Error(t, err, "Should return error for empty PEM")
		assert.Contains(t, err.Error(), "public key PEM is empty", "Error should mention empty PEM")
	})

	t.Run("returns error for malformed PEM", func(t *testing.T) {
		// Test error handling for invalid PEM format
		symKey := make([]byte, 32)
		_, err := rand.Read(symKey)
		require.NoError(t, err)

		pubKeyInfo := keysplit.KASPublicKey{
			URL:       testKAS1URL,
			Algorithm: "rsa:2048",
			KID:       "test-kid",
			PEM:       "invalid-pem-data",
		}

		_, _, _, err = wrapKeyWithPublicKey(symKey, pubKeyInfo)

		require.Error(t, err, "Should return error for malformed PEM")
	})
}

func TestTdfSalt(t *testing.T) {
	t.Run("generates consistent TDF salt", func(t *testing.T) {
		// Test that tdfSalt() produces consistent output
		salt1 := tdfSalt()
		salt2 := tdfSalt()

		assert.Equal(t, salt1, salt2, "tdfSalt should produce consistent output")
		assert.Len(t, salt1, 32, "Salt should be 32 bytes (SHA256 output)")
		assert.NotEmpty(t, salt1, "Salt should not be empty")
	})
}
