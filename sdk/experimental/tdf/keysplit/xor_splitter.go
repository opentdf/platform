// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package keysplit

import (
	"context"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk"
)

const (
	aes256KeyLength = 32 // AES-256 key length in bytes
)

// Splitter defines the interface for key splitting implementations
//
// Deprecated: use [sdk.KeySplitter], whose Split method takes a request
// struct and so can carry the default KAS, the preferred wrapping
// algorithm, and a split-ID generator.
type Splitter interface {
	// GenerateSplits analyzes attributes and creates key splits from a DEK
	GenerateSplits(ctx context.Context, attrs []*policy.Value, dek []byte) (*SplitResult, error)
}

// SplitterOption configures the splitter behavior
//
// Deprecated: use [sdk.KeySplitterOption].
type SplitterOption func(*splitterConfig)

// splitterConfig holds configuration for the splitter
type splitterConfig struct {
	defaultKAS *policy.SimpleKasKey // Default KAS with full key information
}

// WithDefaultKAS sets the default KAS with complete key information
//
// Deprecated: set [sdk.SplitRequest.DefaultKAS], which takes a list, so
// a policy with no key access of its own can still be split across
// several servers.
func WithDefaultKAS(kas *policy.SimpleKasKey) SplitterOption {
	return func(c *splitterConfig) {
		c.defaultKAS = kas
	}
}

// XORSplitter implements XOR-based secret sharing for key splitting
//
// Deprecated: this is now a thin adapter over [sdk.DefaultKeySplitter],
// which is the same attribute reasoning [sdk.SDK.CreateTDF] performs.
// Call that directly.
type XORSplitter struct {
	config splitterConfig
}

// NewXORSplitter creates a new XOR-based key splitter
//
// Deprecated: use [sdk.DefaultKeySplitter] for offline splitting, or
// [sdk.SDK.KeySplitter] to resolve keys the policy does not carry
// against a running platform.
func NewXORSplitter(opts ...SplitterOption) *XORSplitter {
	cfg := splitterConfig{}

	for _, opt := range opts {
		opt(&cfg)
	}

	return &XORSplitter{config: cfg}
}

// GenerateSplits implements the main key splitting workflow.
//
// It delegates to [sdk.DefaultKeySplitter]. The split structure this
// returns is therefore whatever SDK.CreateTDF would have produced for
// the same attributes, which differs from what this package used to
// decide on its own:
//
//   - A hierarchy rule is an AND, one split per value, not an OR.
//   - A value naming no KAS is an error rather than a silent omission,
//     as is a KAS whose public key cannot be resolved.
//   - Splits come out in attribute order rather than sorted by ID, and
//     a single split carries an empty ID rather than a random one.
//
// This splitter is offline: every wrapping key must be carried by the
// attribute values themselves or by the default KAS.
func (x *XORSplitter) GenerateSplits(ctx context.Context, attrs []*policy.Value, dek []byte) (*SplitResult, error) {
	if len(dek) == 0 {
		return nil, ErrEmptyDEK
	}
	if len(dek) != aes256KeyLength {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d", ErrInvalidDEK, len(dek), aes256KeyLength)
	}

	req := sdk.SplitRequest{
		Attributes: attrs,
		DEK:        dek,
	}
	if x.config.defaultKAS != nil {
		req.DefaultKAS = []*policy.SimpleKasKey{x.config.defaultKAS}
	}

	result, err := sdk.DefaultKeySplitter().Split(ctx, req)
	switch {
	case errors.Is(err, sdk.ErrSplitterRequiresDefaultKAS):
		// Kept as this package's own error so existing errors.Is checks
		// against ErrNoDefaultKAS keep matching.
		return nil, ErrNoDefaultKAS
	case err != nil:
		return nil, err
	case len(result.Splits) == 0:
		return nil, fmt.Errorf("%w: no split assignments generated", ErrNoSplitsGenerated)
	}

	splits := make([]Split, 0, len(result.Splits))
	for _, s := range result.Splits {
		keys := make([]KASPublicKey, 0, len(s.Keys))
		for _, k := range s.Keys {
			keys = append(keys, KASPublicKey{
				URL:       k.URL,
				KID:       k.KID,
				PEM:       k.PEM,
				Algorithm: k.Algorithm,
			})
		}
		splits = append(splits, Split{ID: s.ID, Data: s.Data, Keys: keys})
	}

	return &SplitResult{Splits: splits}, nil
}
