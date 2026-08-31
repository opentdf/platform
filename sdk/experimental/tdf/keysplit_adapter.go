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

// Split evaluates the request's attributes and returns the DEK shares
// plus the wrapping key for each KAS they are addressed to.
//
// keysplit's errors (ErrNoDefaultKAS and friends) are returned
// unwrapped so callers can match on them as before.
//
// keysplit takes a single default KAS, so only the first entry of
// req.DefaultKAS is honored; it has no notion of splitting the DEK
// across several defaults.
func (xorSplitter) Split(ctx context.Context, req sdk.SplitRequest) (*sdk.SplitResult, error) {
	var defaultKAS *policy.SimpleKasKey
	if len(req.DefaultKAS) > 0 {
		defaultKAS = req.DefaultKAS[0]
	}
	splitter := keysplit.NewXORSplitter(keysplit.WithDefaultKAS(defaultKAS))
	res, err := splitter.GenerateSplits(ctx, req.Attributes, req.DEK)
	if err != nil {
		return nil, err
	}

	out := &sdk.SplitResult{Splits: make([]sdk.Split, 0, len(res.Splits))}
	for _, split := range res.Splits {
		// keysplit reports keys in a result-wide, URL-keyed map, whereas
		// sdk.Split carries its own key list. Resolve each of the split's
		// URLs against that map; a URL keysplit left out yields an empty
		// PEM, which buildKeyAccessObjects rejects -- the same outcome as
		// before this seam took a key list.
		keys := make([]sdk.KASPublicKey, 0, len(split.KASURLs))
		for _, url := range split.KASURLs {
			key := res.KASPublicKeys[url]
			keys = append(keys, sdk.KASPublicKey{
				Algorithm: key.Algorithm,
				KID:       key.KID,
				PEM:       key.PEM,
				URL:       url,
			})
		}
		out.Splits = append(out.Splits, sdk.Split{
			Data: split.Data,
			ID:   split.ID,
			Keys: keys,
		})
	}
	return out, nil
}
