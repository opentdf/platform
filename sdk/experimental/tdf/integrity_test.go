// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"crypto/rand"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk"
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

// Option cannot return an error, so NewWriter is where an algorithm the
// delegate cannot produce has to be caught -- silently substituting one would
// write a manifest that disagrees with what the caller asked for.
func TestNewWriterRejectsUnproducibleAlgorithms(t *testing.T) {
	ctx := t.Context()

	_, err := NewWriter(ctx, WithIntegrityAlgorithm(RootIntegrityAlg(GMAC)))
	require.ErrorIs(t, err, sdk.ErrUnsupportedRootIntegrityAlgorithm)

	_, err = NewWriter(ctx, WithSegmentIntegrityAlgorithm(SegmentHS256))
	require.ErrorIs(t, err, sdk.ErrUnsupportedSegmentIntegrityAlgorithm)
}

// The defaults are the only algorithms the writer emits, so a manifest names
// them whether or not the caller asked.
func TestFinalizeNamesWhatItSigned(t *testing.T) {
	ctx := t.Context()

	writer, err := NewWriter(ctx)
	require.NoError(t, err)

	_, err = writer.WriteSegment(ctx, 0, []byte("Confidential business information"))
	require.NoError(t, err)

	attributes := []*policy.Value{
		createTestAttribute("https://example.com/attr/Category/value/Financial", testKAS1, "kid1"),
	}
	result, err := writer.Finalize(ctx, WithAttributeValues(attributes))
	require.NoError(t, err)

	intInfo := result.Manifest.IntegrityInformation
	assert.Equal(t, algGMAC, intInfo.SegmentHashAlgorithm)
	assert.Equal(t, algHS256, intInfo.Algorithm)
}
