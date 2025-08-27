package sdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/sdk/tdf"
)

var (
	ErrStreamingWriterAlreadyFinalized = errors.New("streaming writer is already finalized")
	ErrStreamingWriterInvalidPart      = errors.New("invalid segment index, must be >= 0")
	ErrStreamingWriterInvalidFQN       = errors.New("invalid attribute FQN")
)

// FinalizeConfig holds configuration options for finalizing a streaming TDF.
type FinalizeConfig struct {
	defaultKAS                 *policy.SimpleKasKey
	assertions                 []tdf.AssertionConfig
	excludeVersionFromManifest bool
	addDefaultAssertion        bool
	encryptedMetadata          string
	payloadMimeType            string
}

// FinalizeOption is a functional option for configuring TDF finalization.
type FinalizeOption func(*FinalizeConfig) error

// WithDefaultKAS sets the default KAS for the TDF using a SimpleKasKey.
func WithDefaultKAS(kas *policy.SimpleKasKey) FinalizeOption {
	return func(c *FinalizeConfig) error {
		c.defaultKAS = kas
		return nil
	}
}

// WithPayloadMimeType sets the MIME type of the payload.
func WithPayloadMimeType(mimeType string) FinalizeOption {
	return func(c *FinalizeConfig) error {
		c.payloadMimeType = mimeType
		return nil
	}
}

// WithEncryptedMetadata sets encrypted metadata for the TDF.
func WithEncryptedMetadata(metadata string) FinalizeOption {
	return func(c *FinalizeConfig) error {
		c.encryptedMetadata = metadata
		return nil
	}
}

// WithExcludeVersionFromManifest excludes the version from the manifest.
func WithExcludeVersionFromManifest(exclude bool) FinalizeOption {
	return func(c *FinalizeConfig) error {
		c.excludeVersionFromManifest = exclude
		return nil
	}
}

// WithDefaultAssertion adds a default assertion to the TDF.
func WithDefaultAssertion(add bool) FinalizeOption {
	return func(c *FinalizeConfig) error {
		c.addDefaultAssertion = add
		return nil
	}
}

// StreamingWriter provides a simple wrapper around tdf.Writer for S3 multipart upload use cases.
// It handles the conversion between S3 part numbers (1-based) and TDF segment indices (0-based).
//
// Example usage:
//
//	// Create SDK instance
//	sdk, err := New("https://platform.example.com")
//	if err != nil {
//		return err
//	}
//	defer sdk.Close()
//
//	// Create streaming writer
//	writer, err := sdk.NewStreamingWriter(ctx)
//	if err != nil {
//		return err
//	}
//
//	// Write segments (e.g., from S3 multipart uploads)
//	part1Data := []byte("Hello, ")
//	encryptedPart1, err := writer.WriteSegment(1, part1Data) // S3 part 1 -> TDF segment 0
//	if err != nil {
//		return err
//	}
//	// Upload encryptedPart1 to S3...
//
//	part2Data := []byte("World!")
//	encryptedPart2, err := writer.WriteSegment(2, part2Data) // S3 part 2 -> TDF segment 1
//	if err != nil {
//		return err
//	}
//	// Upload encryptedPart2 to S3...
//
//	// Finalize with attributes and options
//	attributeFQNs := []string{
//		"https://example.com/attr/clearance/value/secret",
//		"https://example.com/attr/department/value/engineering",
//	}
//
//	finalBytes, manifest, err := writer.Finalize(ctx, attributeFQNs,
//		WithPayloadMimeType("text/plain"),
//		WithDefaultKAS("https://kas.example.com"),
//		WithEncryptedMetadata("project: streaming-tdf"),
//	)
//	if err != nil {
//		return err
//	}
//	// Upload finalBytes as the final part of the TDF...
type StreamingWriter struct {
	writer *tdf.Writer
	sdk    *SDK
}

// NewStreamingWriter creates a new StreamingWriter using the SDK's configuration.
// The writer uses the SDK's default KAS, attributes, and other TDF settings.
func (s *SDK) NewStreamingWriter(ctx context.Context) (*StreamingWriter, error) {
	// Create a new tdf.Writer with default options
	writer, err := tdf.NewWriter(ctx)
	if err != nil {
		return nil, err
	}

	return &StreamingWriter{
		writer: writer,
		sdk:    s,
	}, nil
}

// WriteSegment encrypts and writes a segment for the given index.
// Indices are 0-based for the low-level API.
// Returns the encrypted bytes that can be immediately uploaded.
func (w *StreamingWriter) WriteSegment(ctx context.Context, segmentIndex int, data []byte) ([]byte, error) {
	if segmentIndex < 0 {
		return nil, ErrStreamingWriterInvalidPart
	}

	return w.writer.WriteSegment(ctx, segmentIndex, data)
}

// Finalize completes the TDF creation with the specified attribute FQNs and configuration options.
// It fetches the attribute values from the platform using their FQNs, then finalizes the TDF
// with proper configuration. Returns the final TDF bytes (manifest and metadata) and the manifest object.
func (w *StreamingWriter) Finalize(ctx context.Context, attributeFQNs []string, opts ...FinalizeOption) ([]byte, *tdf.Manifest, error) {
	// Apply the configuration options
	config := &FinalizeConfig{
		payloadMimeType: "application/octet-stream", // Default MIME type
	}

	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, nil, fmt.Errorf("failed to apply finalize option: %w", err)
		}
	}

	// Fetch attributes from the platform using FQNs
	attributeValues, err := w.fetchAttributesByFQNs(ctx, attributeFQNs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch attributes: %w", err)
	}

	// Build finalize options for the underlying TDF writer
	var tdfFinalizeOpts []tdf.Option[*tdf.WriterFinalizeConfig]

	// Set the default KAS
	//nolint:nestif // KAS fallback logic requires nested conditionals for clear hierarchy
	if config.defaultKAS != nil {
		tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithDefaultKAS(config.defaultKAS))
	} else {
		// Try to get base key from well-known configuration
		if baseKey, err := getBaseKey(ctx, *w.sdk); err == nil {
			tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithDefaultKAS(baseKey))
		} else if w.sdk.PlatformConfiguration != nil {
			// Fallback to platform endpoint as a minimal SimpleKasKey
			if platformEndpoint, err := w.sdk.PlatformConfiguration.platformEndpoint(); err == nil {
				defaultKAS := &policy.SimpleKasKey{KasUri: platformEndpoint}
				tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithDefaultKAS(defaultKAS))
			}
		}
	}

	// Set attribute values
	tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithAttributeValues(attributeValues))

	// Set payload MIME type
	tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithPayloadMimeType(config.payloadMimeType))

	// Set encrypted metadata if provided
	if config.encryptedMetadata != "" {
		tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithEncryptedMetadata(config.encryptedMetadata))
	}

	// Set version exclusion option
	if config.excludeVersionFromManifest {
		tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithExcludeVersionFromManifest(config.excludeVersionFromManifest))
	}

	// Set custom assertions if provided
	if len(config.assertions) > 0 {
		tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithAssertions(config.assertions...))
	}

	// Set default assertion option
	if config.addDefaultAssertion {
		tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithDefaultAssertion(config.addDefaultAssertion))
	}

	return w.writer.Finalize(ctx, tdfFinalizeOpts...)
}

// fetchAttributesByFQNs retrieves attribute values from the platform by their FQNs.
func (w *StreamingWriter) fetchAttributesByFQNs(ctx context.Context, fqns []string) ([]*policy.Value, error) {
	if len(fqns) == 0 {
		return []*policy.Value{}, nil
	}

	// Validate FQNs
	for _, fqn := range fqns {
		if fqn == "" {
			return nil, fmt.Errorf("%w: empty FQN provided", ErrStreamingWriterInvalidFQN)
		}
	}

	// Call the platform to get attribute values
	resp, err := w.sdk.Attributes.GetAttributeValuesByFqns(ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
		WithValue: &policy.AttributeValueSelector{
			WithKeyAccessGrants: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attributes by FQNs: %w", err)
	}

	// Extract the values from the response
	values := make([]*policy.Value, 0, len(fqns))
	for _, fqn := range fqns {
		if attrAndValue, exists := resp.GetFqnAttributeValues()[fqn]; exists && attrAndValue.GetValue() != nil {
			values = append(values, attrAndValue.GetValue())
		} else {
			return nil, fmt.Errorf("%w: attribute not found for FQN '%s'", ErrStreamingWriterInvalidFQN, fqn)
		}
	}

	return values, nil
}
