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
    keepSegments               []int
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

// WithSegments restricts finalization to a contiguous prefix of segments.
// Indices must form [0..K] with no gaps or duplicates, and no later segments
// may have been written.
func WithSegments(indices []int) FinalizeOption {
    return func(c *FinalizeConfig) error {
        c.keepSegments = indices
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

// Experimental and api could change
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

// StreamingWriterOption configures NewStreamingWriterWithOptions.
type StreamingWriterOption func(*[]tdf.Option[*tdf.WriterConfig]) error

// WithInitialAttributeFQNs resolves attribute FQNs and sets them as initial
// attributes on the underlying tdf.Writer at creation time.
func (s *SDK) WithInitialAttributeFQNs(ctx context.Context, fqns []string) StreamingWriterOption {
    return func(opts *[]tdf.Option[*tdf.WriterConfig]) error {
        values, err := (&StreamingWriter{sdk: s}).fetchAttributesByFQNs(ctx, fqns)
        if err != nil {
            return err
        }
        *opts = append(*opts, tdf.WithInitialAttributes(values))
        return nil
    }
}

// WithDefaultKASForWriter sets the default KAS on the underlying tdf.Writer
// at creation time.
func WithDefaultKASForWriter(kas *policy.SimpleKasKey) StreamingWriterOption {
    return func(opts *[]tdf.Option[*tdf.WriterConfig]) error {
        *opts = append(*opts, tdf.WithDefaultKASForWriter(kas))
        return nil
    }
}

// NewStreamingWriterWithOptions creates a new StreamingWriter with writer-level
// options applied at creation time (e.g., initial attributes, default KAS).
//
// Example:
//
//  sw, err := sdk.NewStreamingWriterWithOptions(ctx,
//      sdk.WithInitialAttributeFQNs(ctx, []string{
//          "https://example.com/attr/Basic/value/Test",
//      }),
//      sdk.WithDefaultKASForWriter(&policy.SimpleKasKey{KasUri: "https://kas.example.com"}),
//  )
//  if err != nil { /* handle */ }
//  // Write segments, then finalize (wrapper also supports sdk.WithSegments for prefix selection).
//
func (s *SDK) NewStreamingWriterWithOptions(ctx context.Context, swOpts ...StreamingWriterOption) (*StreamingWriter, error) {
    var writerOpts []tdf.Option[*tdf.WriterConfig]
    for _, o := range swOpts {
        if err := o(&writerOpts); err != nil {
            return nil, fmt.Errorf("failed to apply streaming writer option: %w", err)
        }
    }
    writer, err := tdf.NewWriter(ctx, writerOpts...)
    if err != nil {
        return nil, err
    }
    return &StreamingWriter{writer: writer, sdk: s}, nil
}

// WriteSegment encrypts and writes a segment for the given index.
// Indices are 0-based for the low-level API.
// Returns the encrypted bytes that can be immediately uploaded.
func (w *StreamingWriter) WriteSegment(ctx context.Context, segmentIndex int, data []byte) (*tdf.SegmentResult, error) {
	if segmentIndex < 0 {
		return nil, ErrStreamingWriterInvalidPart
	}

	return w.writer.WriteSegment(ctx, segmentIndex, data)
}

// Finalize completes the TDF creation with the specified attribute FQNs and configuration options.
// It fetches the attribute values from the platform using their FQNs, then finalizes the TDF
// with proper configuration. Returns the final TDF bytes (manifest and metadata) and the manifest object.
func (w *StreamingWriter) Finalize(ctx context.Context, attributeFQNs []string, opts ...FinalizeOption) (*tdf.FinalizeResult, error) {
	// Apply the configuration options
	cfg := &FinalizeConfig{
		payloadMimeType: "application/octet-stream", // Default MIME type
	}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("failed to apply finalize option: %w", err)
		}
	}

	// Fetch attributes from the platform using FQNs
	attributeValues, err := w.fetchAttributesByFQNs(ctx, attributeFQNs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attributes: %w", err)
	}

	// Build finalize options for the underlying TDF writer
	var tdfFinalizeOpts []tdf.Option[*tdf.WriterFinalizeConfig]

	// Set the default KAS
	//nolint:nestif // KAS fallback logic requires nested conditionals for clear hierarchy
	if cfg.defaultKAS != nil {
		tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithDefaultKAS(cfg.defaultKAS))
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
	tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithPayloadMimeType(cfg.payloadMimeType))

    // Set encrypted metadata if provided
    if cfg.encryptedMetadata != "" {
        tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithEncryptedMetadata(cfg.encryptedMetadata))
    }

	// Set version exclusion option
	if cfg.excludeVersionFromManifest {
		tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithExcludeVersionFromManifest(cfg.excludeVersionFromManifest))
	}

	// Assertions
	if cfg.addDefaultAssertion {
		systemMeta, err := GetSystemMetadataAssertionConfig()
		if err != nil {
			return nil, err
		}
		cfg.assertions = append(cfg.assertions, systemMeta)
	}

	// Set custom assertions if provided
    if len(cfg.assertions) > 0 {
        tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithAssertions(cfg.assertions...))
    }

    // Apply segment restriction if provided
    if len(cfg.keepSegments) > 0 {
        tdfFinalizeOpts = append(tdfFinalizeOpts, tdf.WithSegments(cfg.keepSegments))
    }

    return w.writer.Finalize(ctx, tdfFinalizeOpts...)
}

// GetManifest returns the current manifest snapshot from the underlying writer.
// Before finalize, this is a provisional manifest (informational only). After
// finalize, it is the final manifest.
func (w *StreamingWriter) GetManifest() *tdf.Manifest {
    return w.writer.GetManifest()
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
