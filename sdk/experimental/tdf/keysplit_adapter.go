// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/experimental/tdf/keysplit"
)

// xorSplitter adapts this package's multi-KAS XOR splitter to the
// stable [sdk.KeySplitter] seam.
//
// This is why the experimental Writer is more than a rename of
// [sdk.NewChunkedWriter]: sdk.DefaultKeySplitter is single-KAS and
// ignores attributes, whereas [keysplit.XORSplitter] evaluates the full
// ABAC boolean expression and XOR-splits the DEK across every KAS the
// resulting clauses require.
//
// The two result shapes are field-identical; only the package differs.
// The one structural mismatch is where the default KAS enters: sdk
// passes it per Split call, keysplit takes it at construction, so the
// splitter is built inside Split rather than held on the adapter.
type xorSplitter struct{}

// Split evaluates attrs and returns the DEK shares plus the wrapping
// key for each KAS they are addressed to.
//
// keysplit's errors (ErrNoDefaultKAS and friends) are returned
// unwrapped so callers can match on them as before.
func (xorSplitter) Split(ctx context.Context, attrs []*policy.Value, dek []byte, defaultKAS *policy.SimpleKasKey) (*sdk.SplitResult, error) {
	splitter := keysplit.NewXORSplitter(keysplit.WithDefaultKAS(defaultKAS))
	res, err := splitter.GenerateSplits(ctx, attrs, dek)
	if err != nil {
		return nil, err
	}

	out := &sdk.SplitResult{
		KASPublicKeys: make(map[string]sdk.KASPublicKey, len(res.KASPublicKeys)),
		Splits:        make([]sdk.Split, 0, len(res.Splits)),
	}
	for url, key := range res.KASPublicKeys {
		out.KASPublicKeys[url] = sdk.KASPublicKey{
			Algorithm: key.Algorithm,
			KID:       key.KID,
			PEM:       key.PEM,
			URL:       key.URL,
		}
	}
	for _, split := range res.Splits {
		out.Splits = append(out.Splits, sdk.Split{
			Data:    split.Data,
			ID:      split.ID,
			KASURLs: split.KASURLs,
		})
	}
	return out, nil
}
