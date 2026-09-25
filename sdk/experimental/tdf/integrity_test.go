// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"testing"

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

// Option cannot return an error, so NewWriter is where an algorithm the
// delegate cannot produce has to be caught -- silently substituting one would
// write a manifest that disagrees with what the caller asked for.
//
// ErrUnsupportedRootIntegrityAlgorithm and ErrUnsupportedSegmentIntegrityAlgorithm
// are aliases of the sdk-scoped errors (see manifest.go), so both names must
// match the same error.
func TestNewWriterRejectsUnproducibleAlgorithms(t *testing.T) {
	ctx := t.Context()

	_, err := NewWriter(ctx, WithIntegrityAlgorithm(RootIntegrityAlg(GMAC)))
	require.ErrorIs(t, err, sdk.ErrUnsupportedRootIntegrityAlgorithm)
	require.ErrorIs(t, err, ErrUnsupportedRootIntegrityAlgorithm)

	_, err = NewWriter(ctx, WithSegmentIntegrityAlgorithm(SegmentHS256))
	require.ErrorIs(t, err, sdk.ErrUnsupportedSegmentIntegrityAlgorithm)
	require.ErrorIs(t, err, ErrUnsupportedSegmentIntegrityAlgorithm)
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
