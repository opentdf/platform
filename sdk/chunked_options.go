package sdk

import (
	"io"

	"github.com/opentdf/platform/protocol/go/policy"
)

// WithChunkedArchiveWriterFactory overrides the ZIP archive writer
// factory used by the chunked Writer.
func WithChunkedArchiveWriterFactory(f ArchiveWriterFactory) ChunkedWriterOption {
	return func(c *ChunkedWriterConfig) error {
		c.archiveFactory = f
		return nil
	}
}

// WithChunkedCipherFactory overrides the segment cipher factory used
// by the chunked Writer.
func WithChunkedCipherFactory(f SegmentCipherFactory) ChunkedWriterOption {
	return func(c *ChunkedWriterConfig) error {
		c.cipherFactory = f
		return nil
	}
}

// WithChunkedClock overrides the time source used by the chunked
// Writer.
func WithChunkedClock(clock Clock) ChunkedWriterOption {
	return func(c *ChunkedWriterConfig) error {
		c.clock = clock
		return nil
	}
}

// WithChunkedInitialAttributes sets attribute values used by Finalize
// when the Finalize call does not supply its own.
func WithChunkedInitialAttributes(values []*policy.Value) ChunkedWriterOption {
	return func(c *ChunkedWriterConfig) error {
		c.initialAttributes = values
		return nil
	}
}

// WithChunkedDefaultKAS sets the default KAS used by Finalize when
// the Finalize call does not supply its own.
func WithChunkedDefaultKAS(kas *policy.SimpleKasKey) ChunkedWriterOption {
	return func(c *ChunkedWriterConfig) error {
		c.initialDefaultKAS = kas
		return nil
	}
}

// WithChunkedIntegrityAlgorithm sets the algorithm used for the
// manifest root signature.
func WithChunkedIntegrityAlgorithm(algo IntegrityAlgorithm) ChunkedWriterOption {
	return func(c *ChunkedWriterConfig) error {
		c.integrityAlgorithm = algo
		return nil
	}
}

// WithChunkedKeySplitter overrides the key splitter used by the
// chunked Writer. Callers with multi-KAS attribute grants should
// inject a splitter that understands their grant model.
func WithChunkedKeySplitter(splitter KeySplitter) ChunkedWriterOption {
	return func(c *ChunkedWriterConfig) error {
		c.splitter = splitter
		return nil
	}
}

// WithChunkedRand overrides the entropy source used to generate the
// DEK.
func WithChunkedRand(r io.Reader) ChunkedWriterOption {
	return func(c *ChunkedWriterConfig) error {
		c.rand = r
		return nil
	}
}

// WithChunkedSegmentIntegrityAlgorithm sets the algorithm used for
// per-segment integrity hashes.
func WithChunkedSegmentIntegrityAlgorithm(algo IntegrityAlgorithm) ChunkedWriterOption {
	return func(c *ChunkedWriterConfig) error {
		c.segmentIntegrityAlgorithm = algo
		return nil
	}
}

// WithChunkedAssertions attaches signed assertions to the produced
// TDF. Not yet supported by ChunkedWriter; Finalize returns
// ErrChunkedAssertionsUnsupported when the list is non-empty. The
// option is present so upstream call sites can be written in advance
// of assertion support.
func WithChunkedAssertions(assertions []AssertionConfig) ChunkedFinalizeOption {
	return func(c *ChunkedFinalizeConfig) error {
		c.assertions = assertions
		return nil
	}
}

// WithChunkedAttributes overrides the writer's initial attributes for
// this Finalize call.
func WithChunkedAttributes(values []*policy.Value) ChunkedFinalizeOption {
	return func(c *ChunkedFinalizeConfig) error {
		c.attributes = values
		return nil
	}
}

// WithChunkedDefaultKASForFinalize overrides the writer's initial
// default KAS for this Finalize call.
func WithChunkedDefaultKASForFinalize(kas *policy.SimpleKasKey) ChunkedFinalizeOption {
	return func(c *ChunkedFinalizeConfig) error {
		c.defaultKAS = kas
		return nil
	}
}

// WithChunkedEncryptedMetadata attaches AES-GCM-encrypted metadata to
// every KAO in the TDF. The metadata is keyed on the split share and
// only decryptable by a reader that has been granted access.
func WithChunkedEncryptedMetadata(metadata string) ChunkedFinalizeOption {
	return func(c *ChunkedFinalizeConfig) error {
		c.encryptedMetadata = metadata
		return nil
	}
}

// WithChunkedExcludeVersion omits the schemaVersion field from the
// produced manifest for compatibility with older readers.
func WithChunkedExcludeVersion() ChunkedFinalizeOption {
	return func(c *ChunkedFinalizeConfig) error {
		c.excludeVersion = true
		return nil
	}
}

// WithChunkedMimeType records the payload MIME type in the manifest.
func WithChunkedMimeType(mimeType string) ChunkedFinalizeOption {
	return func(c *ChunkedFinalizeConfig) error {
		c.mimeType = mimeType
		return nil
	}
}

// WithChunkedSegments restricts the finalized manifest to the given
// contiguous prefix of segment indices [0..K].
func WithChunkedSegments(indices []int) ChunkedFinalizeOption {
	return func(c *ChunkedFinalizeConfig) error {
		c.keepSegments = indices
		return nil
	}
}
