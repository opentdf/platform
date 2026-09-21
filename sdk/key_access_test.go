package sdk

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These cover createKeyAccess and its helpers directly, without going through
// CreateTDF. TDFSuite exercises the same code but only asserts that a round
// trip succeeds against its own fake KAS, so it cannot pin the KAO field shape
// or the error paths, and encryptMetadata and tdfSalt have no direct coverage
// at all.

const (
	testKAS1URL = "https://kas1.example.com/"

	// A real RSA-2048 public key. Generating one per test run is slow enough
	// to notice across this many subtests.
	testRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQ2ZuyT/p32SFmWTj+wQ
huQwR4IJSzlJ7CqZ4fOXw90rA2joK27dIGiHrtkQHGhS4SK1mvkYyJaREoppMFRc
AyZWCgixbSdwYJS/KN0hjLIdhtkdBlZDaZN2ayTf2sZjWzOLL2cYzzVsAy9tGL8a
bMqf91DEHv+l58fPxmbJ/i6YFFQoOEsyWnPhXdiExe6poQDCHJFYYOp6iu5kOPWr
jKFj9eGXuFR/CJQ/uxTSM+8/7Ejmi8Oa52TQAUhMPH0U1CRFm/NuiFoFissa0jJC
J3k6syxvf45mPrbtlhcELskXrquDtJOpIMQmEwfuV4j8iLNwVlsR2tAbClJi6UOy
SQIDAQAB
-----END PUBLIC KEY-----`

	testMetadata = "test metadata content"
)

func testSymKey(t *testing.T) []byte {
	t.Helper()
	symKey := make([]byte, kKeySize)
	_, err := rand.Read(symKey)
	require.NoError(t, err)
	return symKey
}

func decodeEncryptedMetadata(t *testing.T, encrypted string) []byte {
	t.Helper()

	decodedJSON, err := ocrypto.Base64Decode([]byte(encrypted))
	require.NoError(t, err)

	var encMeta EncryptedMetadata
	require.NoError(t, json.Unmarshal(decodedJSON, &encMeta))
	require.NotEmpty(t, encMeta.Cipher)
	require.NotEmpty(t, encMeta.Iv)

	iv, err := ocrypto.Base64Decode([]byte(encMeta.Iv))
	require.NoError(t, err)
	require.Len(t, iv, ocrypto.GcmStandardNonceSize)

	ciphertext, err := ocrypto.Base64Decode([]byte(encMeta.Cipher))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(ciphertext), ocrypto.GcmStandardNonceSize)
	assert.Equal(t, iv, ciphertext[:ocrypto.GcmStandardNonceSize])

	return ciphertext
}

// TestCreateKeyAccessRSA pins the shape of the default (RSA) wrapping path:
// which manifest fields are populated and which are deliberately left empty.
func TestCreateKeyAccessRSA(t *testing.T) {
	symKey := testSymKey(t)

	kao, err := createKeyAccess(
		KASInfo{URL: testKAS1URL, PublicKey: testRSAPublicKey, KID: "test-kid", Algorithm: "rsa:2048"},
		symKey, PolicyBinding{Alg: "HS256", Hash: "test-binding"}, "encrypted-metadata", "split-1",
	)
	require.NoError(t, err)

	assert.Equal(t, kWrapped, kao.KeyType)
	assert.Equal(t, testKAS1URL, kao.KasURL)
	assert.Equal(t, "test-kid", kao.KID)
	assert.Equal(t, kKasProtocol, kao.Protocol)
	assert.Equal(t, "split-1", kao.SplitID)
	assert.Equal(t, keyAccessSchemaVersion, kao.SchemaVersion)
	assert.Equal(t, "encrypted-metadata", kao.EncryptedMetadata)
	assert.Equal(t, PolicyBinding{Alg: "HS256", Hash: "test-binding"}, kao.PolicyBinding)
	assert.NotEmpty(t, kao.WrappedKey)
	assert.Empty(t, kao.EphemeralPublicKey, "RSA wrapping emits no ephemeral key")
}

func TestCreateKeyAccessRejectsBadPublicKey(t *testing.T) {
	symKey := testSymKey(t)

	for _, tc := range []struct{ name, pubKey string }{
		{"empty", ""},
		{"malformed", "invalid-pem-data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := createKeyAccess(
				KASInfo{URL: testKAS1URL, PublicKey: tc.pubKey, Algorithm: "rsa:2048"},
				symKey, PolicyBinding{}, "", "split-1",
			)
			require.Error(t, err)
		})
	}
}

// TestCreateKeyAccessECUnwrap wraps a DEK to an EC KAS key and then unwraps it
// exactly the way service/kas/access/rewrap.go does for "ec-wrapped".
// Asserting only on KeyType would not catch the envelope being, say, a raw XOR
// of the HKDF output instead of AES-GCM.
func TestCreateKeyAccessECUnwrap(t *testing.T) {
	symKey := testSymKey(t)

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

// The three hybrid KEM schemes are round-tripped in tdf_hybrid_test.go and are
// deliberately not repeated here.

func TestEncryptMetadata(t *testing.T) {
	symKey := testSymKey(t)

	t.Run("round trips a base64 EncryptedMetadata envelope", func(t *testing.T) {
		encrypted, err := encryptMetadata(symKey, testMetadata)
		require.NoError(t, err)
		require.NotEmpty(t, encrypted)

		ciphertext := decodeEncryptedMetadata(t, encrypted)
		gcm, err := ocrypto.NewAESGcm(symKey)
		require.NoError(t, err)
		plaintext, err := gcm.Decrypt(ciphertext)
		require.NoError(t, err)
		assert.Equal(t, testMetadata, string(plaintext))
	})

	t.Run("a different key cannot decrypt the ciphertext", func(t *testing.T) {
		otherKey := testSymKey(t)

		encrypted, err := encryptMetadata(symKey, testMetadata)
		require.NoError(t, err)
		ciphertext := decodeEncryptedMetadata(t, encrypted)

		gcm, err := ocrypto.NewAESGcm(otherKey)
		require.NoError(t, err)
		_, err = gcm.Decrypt(ciphertext)
		require.Error(t, err)
	})

	t.Run("empty metadata round trips through an envelope", func(t *testing.T) {
		encrypted, err := encryptMetadata(symKey, "")
		require.NoError(t, err)
		ciphertext := decodeEncryptedMetadata(t, encrypted)

		gcm, err := ocrypto.NewAESGcm(symKey)
		require.NoError(t, err)
		plaintext, err := gcm.Decrypt(ciphertext)
		require.NoError(t, err)
		assert.Empty(t, plaintext)
	})

	t.Run("errors on an unusable key", func(t *testing.T) {
		_, err := encryptMetadata([]byte{}, testMetadata)
		require.Error(t, err)
	})
}

func TestTdfSalt(t *testing.T) {
	assert.Equal(t,
		"aa17cf44585fe15fd634c27b9512d842b42af1bac6178d92161edb4e2abf8197",
		hex.EncodeToString(tdfSalt()),
	)
}
