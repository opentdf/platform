package sdk

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two types spell themselves for the manifest. The root has one legal
// value, the segment has two, and neither may invent a spelling for anything
// else -- both are int-backed, so out-of-range values are representable.
func TestIntegrityAlgStrings(t *testing.T) {
	assert.Equal(t, hmacIntegrityAlgorithm, RootHS256.String())
	assert.Equal(t, hmacIntegrityAlgorithm, SegmentHS256.String())
	assert.Equal(t, gmacIntegrityAlgorithm, SegmentGMAC.String())

	for _, s := range []string{
		RootIntegrityAlg(1).String(),
		RootIntegrityAlg(-1).String(),
		SegmentIntegrityAlg(99).String(),
		SegmentIntegrityAlg(-1).String(),
	} {
		assert.NotEqual(t, hmacIntegrityAlgorithm, s)
		assert.NotEqual(t, gmacIntegrityAlgorithm, s)
	}
}

// The manifest string has to name the algorithm segmentIntegrity actually
// used, or readers recompute the wrong signature and reject the payload as an
// integrity failure. Anything the String method cannot spell, segmentIntegrity
// must refuse to sign -- that pairing is what keeps the two in step for values
// neither one has a case for. The java and web SDKs use an enum and a string
// union respectively, so neither can express the out-of-range case at all.
func TestSegmentIntegrityMatchesItsManifestString(t *testing.T) {
	key := make([]byte, kKeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	data := make([]byte, kGMACPayloadLength*4)
	_, err = rand.Read(data)
	require.NoError(t, err)

	for _, alg := range []SegmentIntegrityAlg{SegmentHS256, SegmentGMAC} {
		sig, err := segmentIntegrity(data, key, alg, false)
		require.NoError(t, err)

		// The GMAC branch returns the payload's trailing auth tag verbatim;
		// the HS256 branch returns an HMAC over the whole payload.
		usedGMAC := sig == string(data[len(data)-kGMACPayloadLength:])

		assert.Equal(t, usedGMAC, alg.String() == gmacIntegrityAlgorithm,
			"manifest string %q disagrees with the signature computed for alg %d",
			alg, alg)
	}

	for _, alg := range []SegmentIntegrityAlg{SegmentIntegrityAlg(99), SegmentIntegrityAlg(-1)} {
		_, err := segmentIntegrity(data, key, alg, false)
		require.ErrorIs(t, err, ErrUnsupportedSegmentIntegrityAlgorithm, "alg %d", alg)
	}
}

// GMAC signs by returning the ciphertext's trailing kGMACPayloadLength bytes
// verbatim; a ciphertext shorter than that has no tag to return and must be
// rejected rather than silently truncated or padded.
func TestSegmentIntegrityGMACShortCiphertext(t *testing.T) {
	key := make([]byte, kKeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	data := make([]byte, kGMACPayloadLength-1)
	_, err = rand.Read(data)
	require.NoError(t, err)

	_, err = segmentIntegrity(data, key, SegmentGMAC, false)
	require.ErrorIs(t, err, ErrGMACSignatureFailed)
	require.ErrorIs(t, err, ErrTampered)
}

// rootIntegrity is the half of the old calculateSignature whose input never
// went through the AEAD, so it must refuse every algorithm but HS256.
// RootIntegrityAlg names no other value, but it is int-backed: a conversion
// from the deprecated GMAC constant, or from any other int, still compiles.
func TestRootIntegrityRejectsNonHS256(t *testing.T) {
	key := make([]byte, kKeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	aggregate := make([]byte, kGMACPayloadLength*4)
	_, err = rand.Read(aggregate)
	require.NoError(t, err)

	for _, alg := range []RootIntegrityAlg{RootIntegrityAlg(GMAC), RootIntegrityAlg(99), RootIntegrityAlg(-1)} {
		_, err := rootIntegrity(aggregate, key, alg, false)
		require.ErrorIs(t, err, ErrUnsupportedRootIntegrityAlgorithm, "alg %d", alg)
	}

	// HS256 keeps both encodings: raw HMAC for 4.3.0+, hex-encoded for 4.2.2.
	sig, err := rootIntegrity(aggregate, key, RootHS256, false)
	require.NoError(t, err)
	assert.Equal(t, string(ocrypto.CalculateSHA256Hmac(key, aggregate)), sig)

	legacySig, err := rootIntegrity(aggregate, key, RootHS256, true)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(ocrypto.CalculateSHA256Hmac(key, aggregate)), legacySig)
}

// Closing the root off to GMAC must not move the defaults: HS256 root, GMAC
// segments, which is what every writer has been emitting all along.
func TestIntegrityAlgDefaults(t *testing.T) {
	def, err := newTDFConfig()
	require.NoError(t, err)
	assert.Equal(t, RootHS256, def.rootIntegrityAlg)
	assert.Equal(t, SegmentGMAC, def.segmentIntegrityAlg)
}

// The deprecated constants stay numerically where they were, so an existing
// caller that converts one into the new types lands on the same algorithm.
func TestDeprecatedIntegrityAlgorithmConstants(t *testing.T) {
	assert.Equal(t, RootHS256, RootIntegrityAlg(HS256))
	assert.Equal(t, SegmentHS256, SegmentIntegrityAlg(HS256))
	assert.Equal(t, SegmentGMAC, SegmentIntegrityAlg(GMAC))
}

func TestCreatePolicyBinding(t *testing.T) {
	symKey := make([]byte, kKeySize)
	_, err := rand.Read(symKey)
	require.NoError(t, err)

	policyJSON := `{"uuid":"test","body":{"dataAttributes":[{"attribute":"test"}],"dissem":[]}}`

	// The wire format is base64(hex(hmac)), and KAS decodes in that order. The
	// hex layer is easy to drop in a rewrite: every property below still holds
	// without it, but every KAS would reject the result. Pin it to a vector.
	t.Run("known answer", func(t *testing.T) {
		fixedKey := make([]byte, kKeySize)
		for i := range fixedKey {
			fixedKey[i] = byte(i)
		}

		binding := createPolicyBinding(fixedKey, ocrypto.Base64Encode([]byte(`{"uuid":"test"}`)))

		assert.Equal(t,
			"YzFjZTM3OWQ0Y2FiMTZkNmRhNzJkYjllYWQ2NGQ3Y2I0Y2E5YmRhY2FiOGMwNjg1ZmY5MmUzZjc0YWEyYzEyZA==",
			binding.Hash)
	})

	t.Run("binds with HS256 over base64 policy", func(t *testing.T) {
		binding := createPolicyBinding(symKey, ocrypto.Base64Encode([]byte(policyJSON)))

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
		otherKey := make([]byte, kKeySize)
		_, err := rand.Read(otherKey)
		require.NoError(t, err)

		policy := ocrypto.Base64Encode([]byte(policyJSON))
		assert.NotEqual(t,
			createPolicyBinding(symKey, policy).Hash,
			createPolicyBinding(otherKey, policy).Hash,
		)
	})
}
