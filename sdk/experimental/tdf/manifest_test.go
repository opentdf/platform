// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"crypto/rand"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This package used to be the only public API in any OpenTDF SDK that could
// write a GMAC root signature. The root signature covers the aggregate hash,
// which AES-GCM never processes, so "GMAC" there is not a tag read back out of
// the AEAD -- it is a copy of the last segment hash, computed without the key
// and forgeable by anyone who can edit the manifest.
func TestRootIntegrityRejectsGMAC(t *testing.T) {
	key := make([]byte, kKeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	aggregate := make([]byte, kGMACPayloadLength*4)
	_, err = rand.Read(aggregate)
	require.NoError(t, err)

	_, err = rootIntegrity(aggregate, key, GMAC)
	require.ErrorIs(t, err, ErrUnsupportedRootIntegrityAlgorithm)

	sig, err := rootIntegrity(aggregate, key, HS256)
	require.NoError(t, err)
	assert.Equal(t, string(ocrypto.CalculateSHA256Hmac(key, aggregate)), sig)
}

// Segments keep both algorithms: their input is ciphertext the AEAD produced,
// so the trailing bytes really are the tag it computed under the DEK.
func TestSegmentIntegrityKeepsGMAC(t *testing.T) {
	key := make([]byte, kKeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	ciphertext := make([]byte, kGMACPayloadLength*4)
	_, err = rand.Read(ciphertext)
	require.NoError(t, err)

	tag, err := segmentIntegrity(ciphertext, key, GMAC)
	require.NoError(t, err)
	assert.Equal(t, string(ciphertext[len(ciphertext)-kGMACPayloadLength:]), tag)

	hmacSig, err := segmentIntegrity(ciphertext, key, HS256)
	require.NoError(t, err)
	assert.Equal(t, string(ocrypto.CalculateSHA256Hmac(key, ciphertext)), hmacSig)

	// A ciphertext shorter than the tag has no tag to return.
	_, err = segmentIntegrity(ciphertext[:kGMACPayloadLength-1], key, GMAC)
	require.Error(t, err)
}

// The writer must refuse the configuration outright rather than emit a file a
// conforming reader would then have to reject.
func TestNewWriterRejectsGMACRoot(t *testing.T) {
	ctx := t.Context()

	_, err := NewWriter(ctx, WithIntegrityAlgorithm(GMAC))
	require.ErrorIs(t, err, ErrUnsupportedRootIntegrityAlgorithm)

	_, err = NewWriter(ctx, WithIntegrityAlgorithm(IntegrityAlgorithm(99)))
	require.ErrorIs(t, err, ErrUnsupportedRootIntegrityAlgorithm)

	// Segments are unaffected.
	for _, alg := range []IntegrityAlgorithm{HS256, GMAC} {
		w, err := NewWriter(ctx, WithSegmentIntegrityAlgorithm(alg))
		require.NoError(t, err)
		assert.Equal(t, alg, w.segmentIntegrityAlgorithm)
		assert.Equal(t, IntegrityAlgorithm(HS256), w.integrityAlgorithm)
	}

	_, err = NewWriter(ctx, WithSegmentIntegrityAlgorithm(IntegrityAlgorithm(99)))
	require.Error(t, err)
}
