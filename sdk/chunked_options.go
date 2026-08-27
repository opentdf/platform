package sdk

import (
	"fmt"
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
// Writer and, through it, by the zipstream layer that stamps ZIP
// header timestamps. Tests inject FixedClock for deterministic
// output.
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
//
// A reader treats a missing schemaVersion as "predates 4.3.0" and so
// expects hex-then-base64 signatures. Those are written during
// WriteSegment, before this option is seen, so on its own this option
// makes Finalize fail with [ErrChunkedVersionHexMismatch]. Pass
// [WithChunkedTargetMode] at construction instead; it sets both.
func WithChunkedExcludeVersion() ChunkedFinalizeOption {
	return func(c *ChunkedFinalizeConfig) error {
		c.excludeVersion = true
		return nil
	}
}

// WithChunkedTargetMode targets a specific TDF spec version, given as
// a semver string such as "4.2.2".
//
// Below 4.3.0 the writer emits the legacy wire format: segment, root,
// and assertion signatures are hex-encoded before base64 (yielding the
// doubly-encoded values pre-4.3.0 readers expect), and schemaVersion is
// omitted from the manifest, which is how those readers detect it. The
// two travel together -- a manifest carrying one without the other
// cannot be verified by any reader.
//
// An empty mode selects the current format.
func WithChunkedTargetMode(mode string) ChunkedWriterOption {
	return func(c *ChunkedWriterConfig) error {
		if mode == "" {
			c.useHex = false
			c.excludeVersion = false
			return nil
		}
		legacy, err := isLessThanSemver(mode, hexSemverThreshold)
		if err != nil {
			return fmt.Errorf("target mode %q: %w", mode, err)
		}
		c.useHex = legacy
		c.excludeVersion = legacy
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
