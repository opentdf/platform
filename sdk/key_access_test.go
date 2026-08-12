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

// testBase64Policy is what a caller hands buildKeyAccessObjects: the
// policy document already base64-encoded, since that is the form the
// policy binding is computed over.
var testBase64Policy = string(ocrypto.Base64Encode([]byte(testPolicyJSON)))

// newTestShares builds a single share addressed to one KAS holding
// pubKey.
func newTestShares(t *testing.T, pubKey, algorithm string) []splitShare {
	t.Helper()
	shareData := make([]byte, 32)
	_, err := rand.Read(shareData)
	require.NoError(t, err)

	return []splitShare{{
		id:   "test-split-1",
		data: shareData,
		kases: []KASInfo{{
			URL:       testKAS1URL,
			Algorithm: algorithm,
			KID:       "test-kid-1",
			PublicKey: pubKey,
		}},
	}}
}

func TestBuildKeyAccessObjects(t *testing.T) {
	t.Run("RSA public key", func(t *testing.T) {
		shares := newTestShares(t, testRSAPublicKey, "rsa:2048")

		kaos, err := buildKeyAccessObjects(shares, testBase64Policy, testMetadata)
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

		shares := newTestShares(t, ecPublicKeyPEM, "ec:secp256r1")

		kaos, err := buildKeyAccessObjects(shares, testBase64Policy, testMetadata)
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

			shares := newTestShares(t, publicKeyPEM, string(tc.alg))

			kaos, err := buildKeyAccessObjects(shares, testBase64Policy, testMetadata)
			require.NoError(t, err)
			require.Len(t, kaos, 1)

			kao := kaos[0]
			assert.Equal(t, kHybridWrapped, kao.KeyType)
			assert.NotEmpty(t, kao.WrappedKey)
			assert.Empty(t, kao.EphemeralPublicKey)
		})
	}

	t.Run("multiple KAS in one share", func(t *testing.T) {
		shareData := make([]byte, 32)
		_, err := rand.Read(shareData)
		require.NoError(t, err)

		shares := []splitShare{{
			id:   "multi-kas-split",
			data: shareData,
			kases: []KASInfo{
				{URL: testKAS1URL, Algorithm: "rsa:2048", KID: "kid1", PublicKey: testRSAPublicKey},
				{URL: testKAS2URL, Algorithm: "rsa:2048", KID: "kid2", PublicKey: testRSAPublicKey},
			},
		}}

		kaos, err := buildKeyAccessObjects(shares, testBase64Policy, "")
		require.NoError(t, err)
		require.Len(t, kaos, 2, "one KAO per KAS in the OR-group")
		assert.ElementsMatch(t, []string{testKAS1URL, testKAS2URL}, []string{kaos[0].KasURL, kaos[1].KasURL})
	})

	// A KAS whose wrapping key never resolved arrives here with an empty
	// PEM. Dropping it would silently narrow who can unwrap the share --
	// and, if it was the only KAS, produce a TDF nobody can read -- so it
	// is an error rather than a skip.
	t.Run("errors when one KAS in an OR-group has no public key", func(t *testing.T) {
		shareData := make([]byte, 32)
		_, err := rand.Read(shareData)
		require.NoError(t, err)

		shares := []splitShare{{
			id:   "missing-key-split",
			data: shareData,
			kases: []KASInfo{
				{URL: testKAS1URL, Algorithm: "rsa:2048", KID: "kid1", PublicKey: testRSAPublicKey},
				{URL: testKAS2URL, Algorithm: "rsa:2048", KID: "kid2"},
			},
		}}

		_, err = buildKeyAccessObjects(shares, testBase64Policy, "")
		require.ErrorIs(t, err, errKasPubKeyMissing)
		assert.Contains(t, err.Error(), testKAS2URL, "the error should name the offending KAS")
	})

	t.Run("errors when a resolved key has an empty PEM", func(t *testing.T) {
		shares := newTestShares(t, "", "rsa:2048")

		_, err := buildKeyAccessObjects(shares, testBase64Policy, "")
		require.ErrorIs(t, err, errKasPubKeyMissing)
	})

	t.Run("errors on malformed PEM", func(t *testing.T) {
		shares := newTestShares(t, "invalid-pem-data", "rsa:2048")

		_, err := buildKeyAccessObjects(shares, testBase64Policy, "")
		require.Error(t, err)
	})

	t.Run("empty metadata produces no encrypted metadata", func(t *testing.T) {
		shares := newTestShares(t, testRSAPublicKey, "rsa:2048")

		kaos, err := buildKeyAccessObjects(shares, testBase64Policy, "")
		require.NoError(t, err)
		require.Len(t, kaos, 1)
		assert.Empty(t, kaos[0].EncryptedMetadata)
	})

	t.Run("errors on no shares", func(t *testing.T) {
		_, err := buildKeyAccessObjects(nil, testBase64Policy, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no key access objects generated")
	})

	t.Run("errors on a share with no KAS", func(t *testing.T) {
		shareData := make([]byte, 32)
		_, err := rand.Read(shareData)
		require.NoError(t, err)

		_, err = buildKeyAccessObjects([]splitShare{{id: "no-kas-split", data: shareData}}, testBase64Policy, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no key access objects generated")
	})
}

func TestCreatePolicyBinding(t *testing.T) {
	symKey := make([]byte, 32)
	_, err := rand.Read(symKey)
	require.NoError(t, err)

	t.Run("binds with HS256 over base64 policy", func(t *testing.T) {
		binding := createPolicyBinding(symKey, testBase64Policy)

		assert.Equal(t, hmacIntegrityAlgorithm, binding.Alg)
		require.NotEmpty(t, binding.Hash)
		_, err := ocrypto.Base64Decode([]byte(binding.Hash))
		require.NoError(t, err, "hash should be base64")
	})

	t.Run("different policies bind differently", func(t *testing.T) {
		b1 := createPolicyBinding(symKey, string(ocrypto.Base64Encode([]byte(`{"policy":"test1"}`))))
		b2 := createPolicyBinding(symKey, string(ocrypto.Base64Encode([]byte(`{"policy":"test2"}`))))
		assert.NotEqual(t, b1.Hash, b2.Hash)
	})

	t.Run("different keys bind differently", func(t *testing.T) {
		otherKey := make([]byte, 32)
		_, err := rand.Read(otherKey)
		require.NoError(t, err)

		assert.NotEqual(t,
			createPolicyBinding(symKey, testBase64Policy).Hash,
			createPolicyBinding(otherKey, testBase64Policy).Hash,
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
