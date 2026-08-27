package sdk

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These cover createKeyAccess and its helpers directly, without going
// through a writer. They were ported from sdk/experimental/tdf when
// that package's duplicate key-wrapping implementation was deleted;
// the KEM and hybrid paths in particular are exercised nowhere else at
// this level.

const (
	testKAS1URL = "https://kas1.example.com/"
	testKAS2URL = "https://kas2.example.com/"

	// A real RSA-2048 public key. Generating one per test run is slow
	// enough to notice across this many subtests.
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

// newTestSplitResult builds a single-split, single-KAS SplitResult
// addressed to a KAS holding pubKey.
func newTestSplitResult(t *testing.T, pubKey, algorithm string) *SplitResult {
	t.Helper()
	splitData := make([]byte, 32)
	_, err := rand.Read(splitData)
	require.NoError(t, err)

	return &SplitResult{
		Splits: []Split{{
			ID:      "test-split-1",
			Data:    splitData,
			KASURLs: []string{testKAS1URL},
		}},
		KASPublicKeys: map[string]KASPublicKey{
			testKAS1URL: {
				URL:       testKAS1URL,
				Algorithm: algorithm,
				KID:       "test-kid-1",
				PEM:       pubKey,
			},
		},
	}
}

func TestBuildChunkedKeyAccessObjects(t *testing.T) {
	t.Run("RSA public key", func(t *testing.T) {
		splits := newTestSplitResult(t, testRSAPublicKey, "rsa:2048")

		kaos, err := buildChunkedKeyAccessObjects(splits, []byte(testPolicyJSON), testMetadata)
		require.NoError(t, err)
		require.Len(t, kaos, 1)

		kao := kaos[0]
		assert.Equal(t, kWrapped, kao.KeyType)
		assert.Equal(t, testKAS1URL, kao.KasURL)
		assert.Equal(t, "test-kid-1", kao.KID)
		assert.Equal(t, kKasProtocol, kao.Protocol)
		assert.Equal(t, "test-split-1", kao.SplitID)
		assert.NotEmpty(t, kao.WrappedKey)
		assert.NotEmpty(t, kao.PolicyBinding)
		assert.NotEmpty(t, kao.EncryptedMetadata)
		assert.Empty(t, kao.EphemeralPublicKey, "RSA wrapping emits no ephemeral key")
	})

	t.Run("EC public key", func(t *testing.T) {
		ecKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
		require.NoError(t, err)
		ecPublicKeyPEM, err := ecKeyPair.PublicKeyInPemFormat()
		require.NoError(t, err)

		splits := newTestSplitResult(t, ecPublicKeyPEM, "ec:secp256r1")

		kaos, err := buildChunkedKeyAccessObjects(splits, []byte(testPolicyJSON), testMetadata)
		require.NoError(t, err)
		require.Len(t, kaos, 1)

		kao := kaos[0]
		assert.Equal(t, kECWrapped, kao.KeyType, "EC keys use the type the KAS dispatches on")
		assert.Equal(t, testKAS1URL, kao.KasURL)
		assert.NotEmpty(t, kao.EphemeralPublicKey)
		assert.NotEmpty(t, kao.WrappedKey)
	})

	// Each hybrid KEM scheme must land as "hybrid-wrapped" with no
	// ephemeral key -- KEMs carry the encapsulation inside the envelope.
	for _, tc := range []struct {
		name    string
		keyPair func() (ocrypto.KeyPair, error)
		alg     ocrypto.KeyType
	}{
		{
			name:    "X-Wing public key",
			keyPair: func() (ocrypto.KeyPair, error) { return ocrypto.NewXWingKeyPair() },
			alg:     ocrypto.HybridXWingKey,
		},
		{
			name:    "P256+ML-KEM-768 public key",
			keyPair: func() (ocrypto.KeyPair, error) { return ocrypto.NewP256MLKEM768KeyPair() },
			alg:     ocrypto.HybridSecp256r1MLKEM768Key,
		},
		{
			name:    "P384+ML-KEM-1024 public key",
			keyPair: func() (ocrypto.KeyPair, error) { return ocrypto.NewP384MLKEM1024KeyPair() },
			alg:     ocrypto.HybridSecp384r1MLKEM1024Key,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyPair, err := tc.keyPair()
			require.NoError(t, err)
			publicKeyPEM, err := keyPair.PublicKeyInPemFormat()
			require.NoError(t, err)

			splits := newTestSplitResult(t, publicKeyPEM, string(tc.alg))

			kaos, err := buildChunkedKeyAccessObjects(splits, []byte(testPolicyJSON), testMetadata)
			require.NoError(t, err)
			require.Len(t, kaos, 1)

			kao := kaos[0]
			assert.Equal(t, kHybridWrapped, kao.KeyType)
			assert.NotEmpty(t, kao.WrappedKey)
			assert.Empty(t, kao.EphemeralPublicKey)
		})
	}

	t.Run("multiple KAS URLs in one split", func(t *testing.T) {
		splitData := make([]byte, 32)
		_, err := rand.Read(splitData)
		require.NoError(t, err)

		splits := &SplitResult{
			Splits: []Split{{
				ID:      "multi-kas-split",
				Data:    splitData,
				KASURLs: []string{testKAS1URL, testKAS2URL},
			}},
			KASPublicKeys: map[string]KASPublicKey{
				testKAS1URL: {URL: testKAS1URL, Algorithm: "rsa:2048", KID: "kid1", PEM: testRSAPublicKey},
				testKAS2URL: {URL: testKAS2URL, Algorithm: "rsa:2048", KID: "kid2", PEM: testRSAPublicKey},
			},
		}

		kaos, err := buildChunkedKeyAccessObjects(splits, []byte(testPolicyJSON), "")
		require.NoError(t, err)
		require.Len(t, kaos, 2, "one KAO per KAS in the OR-group")
		assert.ElementsMatch(t, []string{testKAS1URL, testKAS2URL}, []string{kaos[0].KasURL, kaos[1].KasURL})
	})

	t.Run("skips KAS URLs with no resolved public key", func(t *testing.T) {
		splitData := make([]byte, 32)
		_, err := rand.Read(splitData)
		require.NoError(t, err)

		splits := &SplitResult{
			Splits: []Split{{
				ID:      "missing-key-split",
				Data:    splitData,
				KASURLs: []string{testKAS1URL, testKAS2URL},
			}},
			KASPublicKeys: map[string]KASPublicKey{
				testKAS1URL: {URL: testKAS1URL, Algorithm: "rsa:2048", KID: "kid1", PEM: testRSAPublicKey},
				// testKAS2URL intentionally absent
			},
		}

		kaos, err := buildChunkedKeyAccessObjects(splits, []byte(testPolicyJSON), "")
		require.NoError(t, err)
		require.Len(t, kaos, 1)
		assert.Equal(t, testKAS1URL, kaos[0].KasURL)
	})

	t.Run("errors when a resolved key has an empty PEM", func(t *testing.T) {
		splits := newTestSplitResult(t, "", "rsa:2048")

		_, err := buildChunkedKeyAccessObjects(splits, []byte(testPolicyJSON), "")
		require.ErrorIs(t, err, errKasPubKeyMissing)
	})

	t.Run("errors on malformed PEM", func(t *testing.T) {
		splits := newTestSplitResult(t, "invalid-pem-data", "rsa:2048")

		_, err := buildChunkedKeyAccessObjects(splits, []byte(testPolicyJSON), "")
		require.Error(t, err)
	})

	t.Run("empty metadata produces no encrypted metadata", func(t *testing.T) {
		splits := newTestSplitResult(t, testRSAPublicKey, "rsa:2048")

		kaos, err := buildChunkedKeyAccessObjects(splits, []byte(testPolicyJSON), "")
		require.NoError(t, err)
		require.Len(t, kaos, 1)
		assert.Empty(t, kaos[0].EncryptedMetadata)
	})

	t.Run("errors on nil split result", func(t *testing.T) {
		_, err := buildChunkedKeyAccessObjects(nil, []byte(testPolicyJSON), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no splits produced")
	})

	t.Run("errors on empty splits", func(t *testing.T) {
		_, err := buildChunkedKeyAccessObjects(&SplitResult{}, []byte(testPolicyJSON), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no splits produced")
	})

	t.Run("errors when every KAS lacks a public key", func(t *testing.T) {
		splitData := make([]byte, 32)
		_, err := rand.Read(splitData)
		require.NoError(t, err)

		splits := &SplitResult{
			Splits:        []Split{{ID: "no-keys-split", Data: splitData, KASURLs: []string{testKAS1URL}}},
			KASPublicKeys: map[string]KASPublicKey{},
		}

		_, err = buildChunkedKeyAccessObjects(splits, []byte(testPolicyJSON), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no valid key access objects generated")
	})
}

func TestCreatePolicyBinding(t *testing.T) {
	symKey := make([]byte, 32)
	_, err := rand.Read(symKey)
	require.NoError(t, err)

	t.Run("binds with HS256 over base64 policy", func(t *testing.T) {
		binding := createPolicyBinding(symKey, ocrypto.Base64Encode([]byte(testPolicyJSON)))

		assert.Equal(t, hmacIntegrityAlgorithm, binding.Alg)
		require.NotEmpty(t, binding.Hash)
		_, err := ocrypto.Base64Decode([]byte(binding.Hash))
		require.NoError(t, err, "hash should be base64")
	})

	t.Run("different policies bind differently", func(t *testing.T) {
		b1 := createPolicyBinding(symKey, ocrypto.Base64Encode([]byte(`{"policy":"test1"}`)))
		b2 := createPolicyBinding(symKey, ocrypto.Base64Encode([]byte(`{"policy":"test2"}`)))
		assert.NotEqual(t, b1.Hash, b2.Hash)
	})

	t.Run("different keys bind differently", func(t *testing.T) {
		otherKey := make([]byte, 32)
		_, err := rand.Read(otherKey)
		require.NoError(t, err)

		policy := ocrypto.Base64Encode([]byte(testPolicyJSON))
		assert.NotEqual(t,
			createPolicyBinding(symKey, policy).Hash,
			createPolicyBinding(otherKey, policy).Hash,
		)
	})
}

func TestEncryptMetadata(t *testing.T) {
	symKey := make([]byte, 32)
	_, err := rand.Read(symKey)
	require.NoError(t, err)

	t.Run("produces a base64 EncryptedMetadata envelope", func(t *testing.T) {
		encrypted, err := encryptMetadata(symKey, testMetadata)
		require.NoError(t, err)
		require.NotEmpty(t, encrypted)

		decodedJSON, err := ocrypto.Base64Decode([]byte(encrypted))
		require.NoError(t, err)

		var encMeta EncryptedMetadata
		require.NoError(t, json.Unmarshal(decodedJSON, &encMeta))
		require.NotEmpty(t, encMeta.Cipher)
		require.NotEmpty(t, encMeta.Iv)

		_, err = ocrypto.Base64Decode([]byte(encMeta.Iv))
		require.NoError(t, err)
		_, err = ocrypto.Base64Decode([]byte(encMeta.Cipher))
		require.NoError(t, err)
	})

	t.Run("different keys produce different ciphertext", func(t *testing.T) {
		otherKey := make([]byte, 32)
		_, err := rand.Read(otherKey)
		require.NoError(t, err)

		a, err := encryptMetadata(symKey, testMetadata)
		require.NoError(t, err)
		b, err := encryptMetadata(otherKey, testMetadata)
		require.NoError(t, err)
		assert.NotEqual(t, a, b)
	})

	t.Run("empty metadata still yields an envelope", func(t *testing.T) {
		encrypted, err := encryptMetadata(symKey, "")
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("errors on an unusable key", func(t *testing.T) {
		_, err := encryptMetadata([]byte{}, testMetadata)
		require.Error(t, err)
	})
}

// TestCreateKeyAccessECUnwrap wraps a DEK to an EC KAS key and then
// unwraps it exactly the way service/kas/access/rewrap.go does for
// "ec-wrapped". Asserting only on KeyType would not catch the envelope
// being, say, a raw XOR of the HKDF output instead of AES-GCM.
func TestCreateKeyAccessECUnwrap(t *testing.T) {
	symKey := make([]byte, 32)
	_, err := rand.Read(symKey)
	require.NoError(t, err)

	ecKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	require.NoError(t, err)
	kasPubPEM, err := ecKeyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	kasPrivPEM, err := ecKeyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	kao, err := createKeyAccess(
		KASInfo{URL: testKAS1URL, PublicKey: kasPubPEM, KID: "test-kid", Algorithm: "ec:secp256r1"},
		symKey, PolicyBinding{}, "", "split-1",
	)
	require.NoError(t, err)
	require.Equal(t, kECWrapped, kao.KeyType)
	require.NotEmpty(t, kao.EphemeralPublicKey)
	assert.True(t, strings.HasPrefix(kao.EphemeralPublicKey, "-----BEGIN PUBLIC KEY-----"))
	assert.True(t, strings.HasSuffix(kao.EphemeralPublicKey, "-----END PUBLIC KEY-----\n"))

	keySize, err := ocrypto.GetECKeySize([]byte(kao.EphemeralPublicKey))
	require.NoError(t, err)
	mode, err := ocrypto.ECSizeToMode(keySize)
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(kao.EphemeralPublicKey))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ecPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	compressed, err := ocrypto.CompressedECPublicKey(mode, *ecPub)
	require.NoError(t, err)

	priv, err := ocrypto.ECPrivateKeyFromPem([]byte(kasPrivPEM))
	require.NoError(t, err)
	dec, err := ocrypto.NewSaltedECDecryptor(priv, tdfSalt(), nil)
	require.NoError(t, err)

	wrapped, err := ocrypto.Base64Decode([]byte(kao.WrappedKey))
	require.NoError(t, err)
	unwrapped, err := dec.DecryptWithEphemeralKey(wrapped, compressed)
	require.NoError(t, err, "KAS must be able to unwrap the EC-wrapped DEK")
	assert.Equal(t, symKey, unwrapped)
}

// TestCreateKeyAccessKEMUnwrap round-trips each hybrid KEM scheme
// through the holder of the corresponding private key.
func TestCreateKeyAccessKEMUnwrap(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keyPair func() (ocrypto.KeyPair, error)
		alg     ocrypto.KeyType
	}{
		{"X-Wing", func() (ocrypto.KeyPair, error) { return ocrypto.NewXWingKeyPair() }, ocrypto.HybridXWingKey},
		{"P256+ML-KEM-768", func() (ocrypto.KeyPair, error) { return ocrypto.NewP256MLKEM768KeyPair() }, ocrypto.HybridSecp256r1MLKEM768Key},
		{"P384+ML-KEM-1024", func() (ocrypto.KeyPair, error) { return ocrypto.NewP384MLKEM1024KeyPair() }, ocrypto.HybridSecp384r1MLKEM1024Key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			symKey := make([]byte, 32)
			_, err := rand.Read(symKey)
			require.NoError(t, err)

			keyPair, err := tc.keyPair()
			require.NoError(t, err)
			pubPEM, err := keyPair.PublicKeyInPemFormat()
			require.NoError(t, err)
			privPEM, err := keyPair.PrivateKeyInPemFormat()
			require.NoError(t, err)

			kao, err := createKeyAccess(
				KASInfo{URL: testKAS1URL, PublicKey: pubPEM, KID: "test-kid", Algorithm: string(tc.alg)},
				symKey, PolicyBinding{}, "", "split-1",
			)
			require.NoError(t, err)
			require.Equal(t, kHybridWrapped, kao.KeyType)
			require.Empty(t, kao.EphemeralPublicKey)

			wrapped, err := ocrypto.Base64Decode([]byte(kao.WrappedKey))
			require.NoError(t, err)
			dec, err := ocrypto.FromPrivatePEM(privPEM)
			require.NoError(t, err)
			plaintext, err := dec.Decrypt(wrapped)
			require.NoError(t, err)
			assert.Equal(t, symKey, plaintext)
		})
	}
}

func TestTdfSalt(t *testing.T) {
	salt1 := tdfSalt()
	salt2 := tdfSalt()

	assert.Equal(t, salt1, salt2, "tdfSalt must be deterministic")
	assert.Len(t, salt1, 32, "SHA-256 output")
}
