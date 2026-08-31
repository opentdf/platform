package sdk

import (
	"crypto/rand"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegrityAlgorithmString(t *testing.T) {
	assert.Equal(t, hmacIntegrityAlgorithm, integrityAlgorithmString(HS256))
	assert.Equal(t, gmacIntegrityAlgorithm, integrityAlgorithmString(GMAC))
}

// The manifest string has to name the algorithm calculateSignature actually
// used, or readers recompute the wrong signature and reject the payload as an
// integrity failure. IntegrityAlgorithm is a type alias for int rather than a
// defined type, so out-of-range values are representable and the two functions
// must agree on them too. The java and web SDKs use an enum and a string union
// respectively, so neither can express this case at all.
func TestIntegrityAlgorithmStringMatchesCalculateSignature(t *testing.T) {
	key := make([]byte, kKeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	data := make([]byte, kGMACPayloadLength*4)
	_, err = rand.Read(data)
	require.NoError(t, err)

	for _, alg := range []IntegrityAlgorithm{HS256, GMAC, IntegrityAlgorithm(99), IntegrityAlgorithm(-1)} {
		sig, err := calculateSignature(data, key, alg, false)
		require.NoError(t, err)

		// The GMAC branch returns the payload's trailing auth tag verbatim;
		// the HS256 branch returns an HMAC over the whole payload.
		usedGMAC := sig == string(data[len(data)-kGMACPayloadLength:])

		assert.Equal(t, usedGMAC, integrityAlgorithmString(alg) == gmacIntegrityAlgorithm,
			"manifest string %q disagrees with the signature computed for alg %d",
			integrityAlgorithmString(alg), alg)
	}
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
