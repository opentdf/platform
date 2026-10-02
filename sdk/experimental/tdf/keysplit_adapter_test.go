// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/require"
)

// TestXORSplitterAdapterRoundTrip proves the xorSplitter adapter's Split ->
// KeyAccess pipeline actually round-trips through real crypto, not just that
// it produces well-shaped output. The multi-KAS subtests in writer_test.go
// (testKeySplittingWithMultipleAttributes, testXORReconstruction,
// testDifferentAttributeRules) only assert non-empty/well-formed shares --
// exactly the assertion style that missed the original EC-KAS bug this PR
// fixes (wrong KeyType string, XOR instead of AES-GCM wrapping, missing
// schemaVersion).
//
// sdk.ChunkedWriter already runs SplitResult.VerifyReconstruction against the
// live DEK before wrapping anything, so the adapter's arithmetic (do the
// shares XOR back to the DEK) is already covered. What that check cannot
// catch is a bug in the wrap step itself: the adapter's
// Algorithm: ocrypto.KeyType(key.Algorithm) conversion selects which wrap
// scheme createKeyAccess uses, and picking the wrong one -- exactly the class
// of bug that shipped an undecryptable TDF before this PR -- corrupts bytes
// after VerifyReconstruction has already passed. Decrypting for real is the
// only way to catch that.
//
// This test finalizes a three-KAS ALL_OF TDF through this package's own
// Writer (exercising xorSplitter, not sdk.CreateTDF's single-KAS path), then
// for each resulting key access object: decrypts the wrapped share with the
// matching KAS's real RSA private key and checks it reproduces that KAO's own
// policy binding (chunked_writer.go's createPolicyBinding keys the HMAC on
// the split's own share, not the aggregate DEK, so this is checkable per KAO
// independently). It then XORs every recovered share together and checks the
// result reproduces the manifest's root signature -- an HMAC-SHA256 of the
// aggregate segment hash keyed by the full DEK -- which only the real DEK can
// produce.
func TestXORSplitterAdapterRoundTrip(t *testing.T) {
	ctx := t.Context()

	urls := []string{testKAS1, testKAS2, testKAS3}
	privByURL := make(map[string]string, len(urls))
	attrs := make([]*policy.Value, len(urls))
	for i, url := range urls {
		keyPair, err := ocrypto.NewRSAKeyPair(2048)
		require.NoError(t, err)
		pubPEM, err := keyPair.PublicKeyInPemFormat()
		require.NoError(t, err)
		privPEM, err := keyPair.PrivateKeyInPemFormat()
		require.NoError(t, err)

		privByURL[url] = privPEM
		attrs[i] = createTestAttributeWithAlgorithm(t,
			fmt.Sprintf("https://example.com/attr/MultiKAS/value/Share%d", i),
			url, fmt.Sprintf("kid%d", i), policy.Algorithm_ALGORITHM_RSA_2048, pubPEM)
	}

	writer, err := NewWriter(ctx)
	require.NoError(t, err)

	_, err = writer.WriteSegment(ctx, 0, []byte("multi-KAS adapter round trip"))
	require.NoError(t, err)

	result, err := writer.Finalize(ctx, WithAttributeValues(attrs))
	require.NoError(t, err)

	kaos := result.Manifest.KeyAccessObjs
	require.Len(t, kaos, len(urls), "each of the three ALL_OF attributes on a distinct KAS must get its own split")

	policyBytes := []byte(result.Manifest.Policy) // already base64, matching createPolicyBinding's input
	var dek []byte
	for _, kao := range kaos {
		priv, ok := privByURL[kao.KasURL]
		require.True(t, ok, "no private key registered for KAS %q", kao.KasURL)

		dec, err := ocrypto.FromPrivatePEM(priv)
		require.NoError(t, err)

		wrapped, err := ocrypto.Base64Decode([]byte(kao.WrappedKey))
		require.NoError(t, err)
		share, err := dec.Decrypt(wrapped)
		require.NoError(t, err, "KAS %s must be able to unwrap its share", kao.KasURL)

		binding, ok := kao.PolicyBinding.(PolicyBinding)
		require.True(t, ok, "policy binding should be a PolicyBinding, got %T", kao.PolicyBinding)
		expectedHash := ocrypto.CalculateSHA256Hmac(share, policyBytes)
		expected := string(ocrypto.Base64Encode([]byte(hex.EncodeToString(expectedHash))))
		require.Equal(t, expected, binding.Hash, "recovered share for KAS %s must reproduce its own policy binding", kao.KasURL)

		if dek == nil {
			dek = make([]byte, len(share))
		}
		require.Len(t, share, len(dek), "every share must be the same length as the DEK")
		for i, b := range share {
			dek[i] ^= b
		}
	}

	var aggregate []byte
	for _, seg := range result.Manifest.Segments {
		decoded, err := ocrypto.Base64Decode([]byte(seg.Hash))
		require.NoError(t, err)
		aggregate = append(aggregate, decoded...)
	}

	rootSig, err := ocrypto.Base64Decode([]byte(result.Manifest.Signature))
	require.NoError(t, err)
	expectedRootSig := ocrypto.CalculateSHA256Hmac(dek, aggregate)
	require.Equal(t, expectedRootSig, rootSig,
		"XOR-reconstructed shares must reproduce the manifest's root signature, proving they really are the DEK the writer used")
}
