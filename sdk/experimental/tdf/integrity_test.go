// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"crypto/rand"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each type spells only the values it accepts. Both are int-backed, so
// out-of-range values are representable, and naming one "HS256" in a manifest
// would claim a signature that was never computed.
func TestIntegrityAlgStrings(t *testing.T) {
	assert.Equal(t, algHS256, RootHS256.String())
	assert.Equal(t, algHS256, SegmentHS256.String())
	assert.Equal(t, algGMAC, SegmentGMAC.String())

	for _, s := range []string{
		RootIntegrityAlg(1).String(),
		RootIntegrityAlg(-1).String(),
		SegmentIntegrityAlg(99).String(),
		SegmentIntegrityAlg(-1).String(),
	} {
		assert.NotEqual(t, algHS256, s)
		assert.NotEqual(t, algGMAC, s)
	}
}

// The deprecated constants stay numerically where they were, so an existing
// caller that converts one into the new types lands on the same algorithm.
func TestDeprecatedIntegrityAlgorithmConstants(t *testing.T) {
	assert.Equal(t, RootHS256, RootIntegrityAlg(HS256))
	assert.Equal(t, SegmentHS256, SegmentIntegrityAlg(HS256))
	assert.Equal(t, SegmentGMAC, SegmentIntegrityAlg(GMAC))
}

// Both segment algorithms are real authenticators, because the input is data
// the cipher produced. An out-of-range value is not, and has to be refused
// rather than quietly treated as GMAC.
func TestSegmentIntegrity(t *testing.T) {
	key := make([]byte, kKeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	data := make([]byte, kGMACPayloadLength*4)
	_, err = rand.Read(data)
	require.NoError(t, err)

	hs256, err := segmentIntegrity(data, key, SegmentHS256)
	require.NoError(t, err)
	assert.Equal(t, string(ocrypto.CalculateSHA256Hmac(key, data)), hs256)

	gmac, err := segmentIntegrity(data, key, SegmentGMAC)
	require.NoError(t, err)
	assert.Equal(t, string(data[len(data)-kGMACPayloadLength:]), gmac)

	for _, alg := range []SegmentIntegrityAlg{SegmentIntegrityAlg(99), SegmentIntegrityAlg(-1)} {
		_, err := segmentIntegrity(data, key, alg)
		require.ErrorIs(t, err, ErrUnsupportedSegmentIntegrityAlgorithm, "alg %d", alg)
	}
}

// The aggregate hash never passed through the AEAD, so tag extraction over it
// authenticates nothing -- it returns a copy of the last segment hash, which is
// manifest data an attacker already controls.
func TestRootIntegrityRejectsNonHS256(t *testing.T) {
	key := make([]byte, kKeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	aggregate := make([]byte, kGMACPayloadLength*4)
	_, err = rand.Read(aggregate)
	require.NoError(t, err)

	for _, alg := range []RootIntegrityAlg{RootIntegrityAlg(GMAC), RootIntegrityAlg(99), RootIntegrityAlg(-1)} {
		_, err := rootIntegrity(aggregate, key, alg)
		require.ErrorIs(t, err, ErrUnsupportedRootIntegrityAlgorithm, "alg %d", alg)
	}

	sig, err := rootIntegrity(aggregate, key, RootHS256)
	require.NoError(t, err)
	assert.Equal(t, string(ocrypto.CalculateSHA256Hmac(key, aggregate)), sig)
}

// Option cannot return an error, so Finalize is the only place an illegal root
// algorithm can be caught -- and it must be, or the writer produces a file no
// conforming reader will accept.
func TestFinalizeRejectsGMACRoot(t *testing.T) {
	ctx := t.Context()

	writer, err := NewWriter(ctx, WithIntegrityAlgorithm(RootIntegrityAlg(GMAC)))
	require.NoError(t, err)

	_, err = writer.WriteSegment(ctx, 0, []byte("Confidential business information"))
	require.NoError(t, err)

	attributes := []*policy.Value{
		createTestAttribute("https://example.com/attr/Category/value/Financial", testKAS1, "kid1"),
	}
	_, err = writer.Finalize(ctx, WithAttributeValues(attributes))
	require.ErrorIs(t, err, ErrUnsupportedRootIntegrityAlgorithm)
}

// Both segment algorithms round-trip through Finalize, and neither disturbs the
// root, which stays HS256 whatever the segments declare.
func TestFinalizeSegmentAlgNamesWhatItSigned(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  SegmentIntegrityAlg
		want string
	}{
		{"hs256", SegmentHS256, algHS256},
		{"gmac", SegmentGMAC, algGMAC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			writer, err := NewWriter(ctx, WithSegmentIntegrityAlgorithm(tc.alg))
			require.NoError(t, err)

			_, err = writer.WriteSegment(ctx, 0, []byte("Confidential business information"))
			require.NoError(t, err)

			attributes := []*policy.Value{
				createTestAttribute("https://example.com/attr/Category/value/Financial", testKAS1, "kid1"),
			}
			result, err := writer.Finalize(ctx, WithAttributeValues(attributes))
			require.NoError(t, err)

			intInfo := result.Manifest.IntegrityInformation
			assert.Equal(t, tc.want, intInfo.SegmentHashAlgorithm)
			assert.Equal(t, algHS256, intInfo.Algorithm, "root stays HS256 regardless of the segment algorithm")
		})
	}
}
