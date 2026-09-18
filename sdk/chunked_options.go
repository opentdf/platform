package sdk

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/opentdf/platform/protocol/go/policy"
)

// Every option below that takes a pointer or an interface rejects nil
// rather than storing it. A stored nil is not detectable later: the
// config field is indistinguishable from "not set". For an injection
// seam that means NewChunkedWriter installs no default and the nil is
// dereferenced during writing -- for the splitter, not until Finalize,
// long after the caller has encrypted every segment. For the default
// KAS it is worse than a panic, because nothing fails: key access
// silently falls back to the platform base key, and the caller learns
// their data went to a KAS they never named only when a reader cannot
// unwrap it.

// The slice-valued options below clone what they are given. Each is retained
// for the lifetime of the writer or of one Finalize call, and each determines
// something the caller cannot inspect afterwards -- the written policy, the
// signed assertions, the segments the manifest names. Keeping the caller's
// backing array would let a mutation after the call silently change any of
// them, including loosening the policy on data already encrypted.
//
// The clone stops at the slice, though, so it only closes the half of that
// hole reachable by reslicing or reassigning an element. What the elements
// point at stays shared: buildChunkedPolicy reads each *policy.Value at
// Finalize, and signAssertions signs with whatever AssertionKey.Key holds.
// Mutating a retained policy value still rewrites the bound policy, which is
// the loosening described above -- cloning the slice does not prevent it.
// Callers must treat everything they hand these options as frozen until
// Finalize returns.

// withChunkedArchiveWriterFactory overrides the ZIP archive writer
// factory used by the [ChunkedWriter]. The factory must not be nil.
func withChunkedArchiveWriterFactory(f archiveWriterFactory) ChunkedWriterOption {
	return func(c *chunkedWriterConfig) error {
		if f == nil {
			return errors.New("chunked: archive writer factory must not be nil")
		}
		c.archiveFactory = f
		return nil
	}
}

// withChunkedCipherFactory overrides the segment cipher factory used
// by the [ChunkedWriter]. The factory must not be nil.
func withChunkedCipherFactory(f segmentCipherFactory) ChunkedWriterOption {
	return func(c *chunkedWriterConfig) error {
		if f == nil {
			return errors.New("chunked: cipher factory must not be nil")
		}
		c.cipherFactory = f
		return nil
	}
}

// withChunkedClock overrides the time source used by the
// [ChunkedWriter] and, through it, by the zipstream layer that stamps
// ZIP header timestamps. Tests inject fixedClock for deterministic
// output. The clock must not be nil.
func withChunkedClock(clock clock) ChunkedWriterOption {
	return func(c *chunkedWriterConfig) error {
		if clock == nil {
			return errors.New("chunked: clock must not be nil")
		}
		c.clock = clock
		return nil
	}
}

// WithChunkedInitialAttributes sets attribute values used by Finalize
// when the Finalize call does not supply its own.
func WithChunkedInitialAttributes(values []*policy.Value) ChunkedWriterOption {
	return func(c *chunkedWriterConfig) error {
		c.initialAttributes = slices.Clone(values)
		return nil
	}
}

// WithChunkedDefaultKAS sets the default KAS used by Finalize when
// the Finalize call does not supply its own. The KAS must not be nil:
// omit the option to leave key access to be resolved some other way.
func WithChunkedDefaultKAS(kas *policy.SimpleKasKey) ChunkedWriterOption {
	return func(c *chunkedWriterConfig) error {
		if kas == nil {
			return errors.New("chunked: default KAS must not be nil")
		}
		c.initialDefaultKAS = kas
		return nil
	}
}

// WithChunkedKeySplitter overrides the key splitter used by the
// [ChunkedWriter]. Callers with multi-KAS attribute grants should
// inject a splitter that understands their grant model. The splitter
// must not be nil.
func WithChunkedKeySplitter(splitter KeySplitter) ChunkedWriterOption {
	return func(c *chunkedWriterConfig) error {
		if splitter == nil {
			return errors.New("chunked: key splitter must not be nil")
		}
		c.splitter = splitter
		c.splitterSet = true
		return nil
	}
}

// withChunkedRand overrides the entropy source used to generate the
// DEK. The reader must not be nil.
func withChunkedRand(r io.Reader) ChunkedWriterOption {
	return func(c *chunkedWriterConfig) error {
		if r == nil {
			return errors.New("chunked: rand must not be nil")
		}
		c.rand = r
		return nil
	}
}

// WithChunkedTDFOptions supplies the key access options — attributes, KAS
// information, preferred wrapping algorithm — that SDK.NewChunkedWriter
// resolves against the platform at Finalize. It has no effect on the
// package-level NewChunkedWriter, which has no platform to resolve against;
// use WithChunkedKeySplitter there.
func WithChunkedTDFOptions(opts ...TDFOption) ChunkedWriterOption {
	return func(c *chunkedWriterConfig) error {
		c.tdfOptions = append(c.tdfOptions, opts...)
		return nil
	}
}

// WithChunkedAssertions attaches signed assertions to the produced
// TDF. Each assertion is bound to the payload's aggregate hash, so
// they are signed at Finalize once every segment is in. Assertions
// without their own SigningKey are signed with HS256 over the DEK.
func WithChunkedAssertions(assertions []AssertionConfig) ChunkedFinalizeOption {
	return func(c *chunkedFinalizeConfig) error {
		c.assertions = slices.Clone(assertions)
		return nil
	}
}

// WithChunkedAttributes overrides the writer's initial attributes for
// this Finalize call.
//
// An empty or nil slice does not clear the writer's initial
// attributes -- it reads as "not specified" and the initial ones still
// apply. There is deliberately no way to finalize with no attributes
// once the writer was constructed with some: dropping attributes
// silently would loosen the policy on the data, which is the one
// mistake here that cannot be detected after the fact. Construct a
// writer without WithChunkedInitialAttributes instead.
func WithChunkedAttributes(values []*policy.Value) ChunkedFinalizeOption {
	return func(c *chunkedFinalizeConfig) error {
		c.attributes = slices.Clone(values)
		return nil
	}
}

// WithChunkedDefaultKASForFinalize overrides the writer's initial
// default KAS for this Finalize call. The KAS must not be nil: omit
// the option to keep whatever WithChunkedDefaultKAS set.
func WithChunkedDefaultKASForFinalize(kas *policy.SimpleKasKey) ChunkedFinalizeOption {
	return func(c *chunkedFinalizeConfig) error {
		if kas == nil {
			return errors.New("chunked: default KAS must not be nil")
		}
		c.defaultKAS = kas
		return nil
	}
}

// WithChunkedEncryptedMetadata attaches AES-GCM-encrypted metadata to
// every KAO in the TDF. The metadata is keyed on the split share and
// only decryptable by a reader that has been granted access.
func WithChunkedEncryptedMetadata(metadata string) ChunkedFinalizeOption {
	return func(c *chunkedFinalizeConfig) error {
		c.encryptedMetadata = metadata
		return nil
	}
}

// WithChunkedTargetMode targets a specific TDF spec version, given as
// a semver string such as "4.2.2". An empty mode selects the most
// recently available target version (4.3.0).
func WithChunkedTargetMode(mode string) ChunkedWriterOption {
	return func(c *chunkedWriterConfig) error {
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
	return func(c *chunkedFinalizeConfig) error {
		c.mimeType = mimeType
		return nil
	}
}

// WithChunkedSegments sets the segments the finalized manifest
// describes. Passing no indices emits every written segment in
// ascending index order, which is what most callers want.
//
// The indices need not be contiguous. A caller that reserves a fixed
// block of indices per upload part -- part N owning
// [N*stride, (N+1)*stride) -- and fills only part of each block writes
// a sparse index set by construction; listing it here is fine.
//
// What the indices must be is a prefix of the written segments in
// ascending index order: they may drop from the end, but may not
// reorder or skip. The archive stores segments sorted by index, so a
// manifest that reorders them would not describe the bytes on disk,
// and one that skips a segment with bytes after it would misread every
// segment that follows. For the same reason the caller must
// concatenate each segment's TDFData in ascending index order.
//
// Dropping a segment from the manifest does not shrink the archive:
// the underlying writer never rolls back a completed segment's
// contribution to the payload's recorded size and CRC, so every
// segment that was actually written -- including ones this option
// excludes from the manifest -- must still be appended by the caller
// when assembling the final file. Skipping a dropped segment's bytes
// produces an archive whose central directory offsets overshoot.
func WithChunkedSegments(indices []int) ChunkedFinalizeOption {
	return func(c *chunkedFinalizeConfig) error {
		// Cloned because segmentOrderLocked validates the live slice before
		// copying it, so a concurrent mutation could slip between the check
		// and the use.
		c.keepSegments = slices.Clone(indices)
		return nil
	}
}
