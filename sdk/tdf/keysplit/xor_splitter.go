package keysplit

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/protocol/go/policy"
)

// Splitter defines the interface for key splitting implementations
type Splitter interface {
	// GenerateSplits analyzes attributes and creates key splits from a DEK
	GenerateSplits(ctx context.Context, attrs []*policy.Value, dek []byte) (*SplitResult, error)
}

// SplitterOption configures the splitter behavior
type SplitterOption func(*splitterConfig)

// splitterConfig holds configuration for the splitter
type splitterConfig struct {
	defaultKAS *policy.SimpleKasKey // Default KAS with full key information
	splitIDGen func() string         // Function to generate split IDs
}

// WithDefaultKAS sets the default KAS with complete key information
func WithDefaultKAS(kas *policy.SimpleKasKey) SplitterOption {
	return func(c *splitterConfig) {
		c.defaultKAS = kas
	}
}

// WithSplitIDGenerator sets a custom split ID generator
func WithSplitIDGenerator(gen func() string) SplitterOption {
	return func(c *splitterConfig) {
		c.splitIDGen = gen
	}
}

// XORSplitter implements XOR-based secret sharing for key splitting
type XORSplitter struct {
	config splitterConfig
}

// NewXORSplitter creates a new XOR-based key splitter
func NewXORSplitter(opts ...SplitterOption) *XORSplitter {
	cfg := splitterConfig{
		splitIDGen: generateSplitID, // Use the default from split_planner.go
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	return &XORSplitter{config: cfg}
}

// GenerateSplits implements the main key splitting workflow
func (x *XORSplitter) GenerateSplits(ctx context.Context, attrs []*policy.Value, dek []byte) (*SplitResult, error) {
	// Validate inputs
	if len(dek) == 0 {
		return nil, ErrEmptyDEK
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, expected 32", ErrInvalidDEK, len(dek))
	}
	
	// If no attributes provided, check if we have a default KAS
	if len(attrs) == 0 {
		if x.config.defaultKAS == nil {
			return nil, ErrNoDefaultKAS
		}
		// Use default KAS for single split
		kasURL := x.config.defaultKAS.KasUri
		kasPublicKeys := make(map[string]KASPublicKey)
		
		// Add the default KAS public key if available
		if x.config.defaultKAS.PublicKey != nil {
			kasPublicKeys[kasURL] = KASPublicKey{
				URL:       kasURL,
				KID:       x.config.defaultKAS.PublicKey.GetKid(),
				PEM:       x.config.defaultKAS.PublicKey.GetPem(),
				Algorithm: formatAlgorithm(x.config.defaultKAS.PublicKey.GetAlgorithm()),
			}
		}
		
		return &SplitResult{
			Splits: []Split{{
				ID:      generateSplitID(),
				Data:    dek, // Single split, no XOR needed
				KASURLs: []string{kasURL},
			}},
			KASPublicKeys: kasPublicKeys,
		}, nil
	}

	slog.Debug("starting key split generation",
		slog.Int("num_attributes", len(attrs)),
		slog.Int("dek_size", len(dek)))

	// 1. Build boolean expression from attributes
	expr, err := buildBooleanExpression(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to build boolean expression: %w", err)
	}

	// 2. Create split plan based on attribute rules
	var defaultKASURL string
	if x.config.defaultKAS != nil {
		defaultKASURL = x.config.defaultKAS.KasUri
	}
	assignments, err := createSplitPlan(expr, defaultKASURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create split plan: %w", err)
	}

	if len(assignments) == 0 {
		return nil, fmt.Errorf("%w: no split assignments generated", ErrNoSplitsGenerated)
	}

	// 3. Perform XOR-based key splitting
	splits, err := x.performXORSplit(dek, assignments)
	if err != nil {
		return nil, fmt.Errorf("failed to perform XOR split: %w", err)
	}

	// 4. Collect all public keys from assignments
	allKeys := collectAllPublicKeys(assignments)

	slog.Debug("completed key split generation",
		slog.Int("num_splits", len(splits)),
		slog.Int("num_kas_keys", len(allKeys)))

	return &SplitResult{
		Splits:        splits,
		KASPublicKeys: allKeys,
	}, nil
}

// performXORSplit implements the XOR-based secret sharing algorithm
func (x *XORSplitter) performXORSplit(dek []byte, assignments []SplitAssignment) ([]Split, error) {
	numSplits := len(assignments)

	if numSplits == 1 {
		// Single assignment - no splitting needed, return DEK as-is
		assignment := assignments[0]
		slog.Debug("single split assignment, no XOR splitting needed",
			slog.String("split_id", assignment.SplitID),
			slog.Any("kas_urls", assignment.KASURLs))

		return []Split{{
			ID:      assignment.SplitID,
			Data:    dek,
			KASURLs: assignment.KASURLs,
		}}, nil
	}

	// Multiple assignments - perform XOR splitting
	slog.Debug("performing XOR split across multiple assignments",
		slog.Int("num_splits", numSplits))

	splits := make([]Split, 0, numSplits)
	remainder := make([]byte, len(dek))
	copy(remainder, dek) // Start with original DEK

	// Generate random splits for all but the last assignment
	for i, assignment := range assignments {
		var splitData []byte

		if i < numSplits-1 {
			// Generate random split key
			splitData = make([]byte, len(dek))
			if _, err := rand.Read(splitData); err != nil {
				return nil, fmt.Errorf("%w: failed to generate random split: %v",
					ErrSplitGeneration, err)
			}

			// XOR this split with the remainder to maintain the invariant:
			// dek = split[0] XOR split[1] XOR ... XOR split[n-1]
			for j := range remainder {
				remainder[j] ^= splitData[j]
			}

			slog.Debug("generated random split",
				slog.Int("split_index", i),
				slog.String("split_id", assignment.SplitID))
		} else {
			// Last split is the remainder to satisfy the XOR equation
			splitData = remainder
			slog.Debug("generated remainder split",
				slog.Int("split_index", i),
				slog.String("split_id", assignment.SplitID))
		}

		splits = append(splits, Split{
			ID:      assignment.SplitID,
			Data:    splitData,
			KASURLs: assignment.KASURLs,
		})
	}

	// Verify the splits can reconstruct the original DEK
	if err := x.verifySplitReconstruction(dek, splits); err != nil {
		return nil, fmt.Errorf("split verification failed: %w", err)
	}

	return splits, nil
}

// verifySplitReconstruction ensures splits XOR back to original DEK
func (x *XORSplitter) verifySplitReconstruction(originalDEK []byte, splits []Split) error {
	if len(splits) == 1 {
		// Single split should equal original DEK
		if len(splits[0].Data) != len(originalDEK) {
			return fmt.Errorf("single split length mismatch: got %d, expected %d",
				len(splits[0].Data), len(originalDEK))
		}
		for i, b := range splits[0].Data {
			if b != originalDEK[i] {
				return fmt.Errorf("single split data mismatch at byte %d", i)
			}
		}
		return nil
	}

	// Multiple splits - XOR them together
	reconstructed := make([]byte, len(originalDEK))

	for _, split := range splits {
		if len(split.Data) != len(originalDEK) {
			return fmt.Errorf("split %s length mismatch: got %d, expected %d",
				split.ID, len(split.Data), len(originalDEK))
		}

		for i, b := range split.Data {
			reconstructed[i] ^= b
		}
	}

	// Compare with original
	for i, b := range reconstructed {
		if b != originalDEK[i] {
			return fmt.Errorf("reconstructed DEK mismatch at byte %d: got 0x%02x, expected 0x%02x",
				i, b, originalDEK[i])
		}
	}

	slog.Debug("verified split reconstruction successful",
		slog.Int("num_splits", len(splits)),
		slog.Int("dek_length", len(originalDEK)))

	return nil
}
