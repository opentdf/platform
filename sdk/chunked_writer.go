package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/internal/zipstream"
)

// The injection seams below — the clock, the segment cipher, the archive
// writer and the entropy source — are unexported on purpose. Each exists so
// in-package tests can pin non-deterministic behavior; none is reachable from
// outside. For archiveWriterFactory it is the signature that closes the seam,
// not the return type's implementability: a struct declared anywhere with the
// right method set satisfies zipstream.SegmentWriter, but no code outside this
// package can spell `func(clock) zipstream.SegmentWriter` — clock is
// unexported and zipstream lives under internal/ — so a factory value cannot
// be constructed to pass in.

// clock supplies the current time to the chunked writer and, through it, to
// the zipstream layer that stamps ZIP header timestamps. Injected so tests can
// pin timestamps and produce byte-for-byte deterministic TDF output.
type clock interface {
	// Now returns the current wall-clock time.
	Now() time.Time
}

// systemClock returns time.Now(). Production default.
type systemClock struct{}

// Now returns the current wall-clock time.
func (systemClock) Now() time.Time { return time.Now() }

// fixedClock returns the same time on every call, for deterministic ZIP
// output in tests.
type fixedClock struct {
	// T is the wall-clock time to return from Now.
	T time.Time
}

// Now returns the pinned time.
func (c fixedClock) Now() time.Time { return c.T }

// segmentSealer encrypts one numbered part of a single message under a single
// key. Implementations must be safe for concurrent use by segment writers.
//
// The output must be AEAD in the shape the TDF reader expects: a 12-byte
// header, which is the part's IV, and a ciphertext ending in a 16-byte
// authentication tag. WriteSegment prepends the header to the ciphertext on
// the wire but hands segmentIntegrity the ciphertext alone, which under
// SegmentGMAC reads the tag straight off the tail; an implementation that
// omits the tag produces a manifest that verifies against nothing.
//
// Uniqueness is the caller's to supply and the implementation's to honor.
// Distinct parts must produce distinct headers, and an implementation that
// invents its own header instead of deriving one from the part breaks that
// *silently*: the segment still decrypts, because the reader takes whatever
// header the writer prepended. What is lost is the guarantee that no two
// segments under one key ever share an IV.
type segmentSealer interface {
	// Seal returns (header, ciphertext, error) for part. It must allocate its
	// output and must neither retain nor modify data, which WriteSegment
	// passes through from its caller.
	Seal(part uint32, data []byte) ([]byte, []byte, error)
}

// segmentSealerFactory builds a segmentSealer from a key and the message ID
// shared by every part of the message. Tests inject failing and blocking
// sealers; production uses defaultSegmentSealerFactory.
//
// Taking both at once is the point: it leaves no way to hold a key and a
// message ID as two values that a later refactor can desynchronize, which
// would pair one message's ID with another message's key -- cross-file IV
// reuse, the failure this construction exists to remove.
type segmentSealerFactory func(dek []byte, id ocrypto.MessageID) (segmentSealer, error)

// defaultSegmentSealerFactory wraps ocrypto.NewAESGcmSealer (AES-256-GCM with
// a deterministic per-part IV).
func defaultSegmentSealerFactory(dek []byte, id ocrypto.MessageID) (segmentSealer, error) {
	sealer, err := ocrypto.NewAESGcmSealer(dek, id)
	if err != nil {
		return nil, err
	}
	return sealer, nil
}

// messageSealerEntry is the per-key half of a messageSealers registry: the
// sealer itself plus whatever key access metadata has been sealed under that
// key, which must be sealed exactly once because it spends [metadataPart].
type messageSealerEntry struct {
	// sealer encrypts every part -- payload and metadata -- under this key.
	sealer segmentSealer

	// metadata is the encoded EncryptedMetadata sealed at metadataPart.
	// metadataSealed distinguishes a cached empty result from an absent one.
	metadata       string
	metadataSealed bool
}

// messageSealers is the set of sealers one message uses, one per distinct key,
// all sharing the message's single ID.
//
// The registry exists because a TDF seals under more than one key: the DEK for
// the payload, and each XOR share for that share's key access metadata. Those
// keys may coincide -- with a single split the sole share is the DEK verbatim
// -- and when they do, both uses must reach the *same* sealer, or the metadata
// and segment 0 would be numbered independently under one key.
//
// Entries are keyed by a copy of the key bytes, never by split ID or KAS URL,
// which can change while the underlying key does not. They live as long as the
// writer: dropping one and rebuilding it would reset that key's encryption
// budget on the RBG fallback. Repeated splits mint fresh share keys and so add
// entries, which is a bounded but real memory cost on a writer that finalizes
// many times.
//
// The keys are secret material. Do not log them, expose them, or put them in
// an error message.
type messageSealers struct {
	// id is the message ID every entry's sealer derives its IVs from. Fixed at
	// construction; one message, one ID.
	id ocrypto.MessageID

	// factory builds an entry's sealer on first use of its key.
	factory segmentSealerFactory

	// mu guards entries and the fields of every entry in it. Held only across
	// local work -- sealer construction, one encryption, encoding -- never
	// across KAS resolution or any other network call.
	mu sync.Mutex

	// entries maps a copied key to its sealer and cached metadata.
	entries map[[kKeySize]byte]*messageSealerEntry
}

// newMessageSealers returns an empty registry over id. A nil factory means
// defaultSegmentSealerFactory.
func newMessageSealers(id ocrypto.MessageID, factory segmentSealerFactory) *messageSealers {
	if factory == nil {
		factory = defaultSegmentSealerFactory
	}
	return &messageSealers{
		id:      id,
		factory: factory,
		entries: make(map[[kKeySize]byte]*messageSealerEntry),
	}
}

// sealerFor returns the sealer for key, building it on first use.
func (s *messageSealers) sealerFor(key []byte) (segmentSealer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.entryLocked(key)
	if err != nil {
		return nil, err
	}
	return entry.sealer, nil
}

// entryLocked finds or creates the entry for key. Caller holds s.mu.
func (s *messageSealers) entryLocked(key []byte) (*messageSealerEntry, error) {
	if len(key) != kKeySize {
		// The length, never the key.
		return nil, fmt.Errorf("%w: got %d bytes, want %d", errSealerKeySize, len(key), kKeySize)
	}
	var k [kKeySize]byte
	copy(k[:], key)
	if entry, ok := s.entries[k]; ok {
		return entry, nil
	}
	sealer, err := s.factory(key, s.id)
	if err != nil {
		return nil, fmt.Errorf("build segment sealer: %w", err)
	}
	entry := &messageSealerEntry{sealer: sealer}
	s.entries[k] = entry
	return entry, nil
}

// archiveWriterFactory builds a zipstream.SegmentWriter for a new TDF. It
// receives the writer's clock so ZIP header timestamps stay injectable
// end-to-end.
type archiveWriterFactory func(c clock) zipstream.SegmentWriter

// defaultArchiveWriterFactory returns a ZIP64-enabled segment writer with its
// clock plumbed to the caller-supplied clock.
//
// The 1 is expectedSegments, which reads like a capacity hint but is not:
// nothing raises it, so a writer that goes on to accept five hundred segments
// still reports ExpectedCount 1. It is harmless only because that count is
// consulted solely when no explicit segment order has been set, and
// zipstream's Finalize always derives an order from the segments actually
// present before it checks completeness.
func defaultArchiveWriterFactory(c clock) zipstream.SegmentWriter {
	return zipstream.NewSegmentTDFWriter(1,
		zipstream.WithZip64(),
		zipstream.WithClock(c.Now),
	)
}

// Sentinel errors returned by [ChunkedWriter].
//
// Experimental: not part of the stable SDK API; may change or be removed.
var (
	// ErrChunkedAlreadyFinalized is returned when a ChunkedWriter
	// method is called after Finalize has already succeeded.
	ErrChunkedAlreadyFinalized = errors.New("chunked: writer already finalized")

	// ErrChunkedCleanupFailed is returned when a failed WriteSegment
	// could not roll its partial write back out of the archive, and by
	// every later call on that writer.
	//
	// CleanupSegment is what makes a failed WriteSegment retryable: it
	// returns the archive to a state indistinguishable from never
	// having attempted the index. If it fails, the archive may still
	// carry that attempt's record and its contribution to the payload's
	// size and CRC, and nothing here can tell how much. Continuing
	// would write later segments at offsets computed from a payload
	// length that counts bytes the manifest never describes, producing
	// an archive that assembles cleanly and fails at decrypt. Fencing
	// the writer surfaces it at the next call instead.
	//
	// Unreachable with the default archive writer, whose CleanupSegment
	// cannot fail; it is the injected-factory case this guards.
	ErrChunkedCleanupFailed = errors.New("chunked: segment cleanup failed after a failed write; writer is unusable")

	// ErrChunkedCloseFailed is returned when the archive's Close fails
	// after its Finalize already succeeded. The archive is terminally
	// finalized internally at that point regardless, so the writer is
	// unusable: every subsequent call returns this same error rather
	// than retrying against an archive that can only fail again.
	//
	// Note what is being discarded. Finalize had already returned a
	// complete, valid trailer; it is dropped because the archive
	// reported a fault afterwards, not because the bytes were bad. The
	// payload segments already uploaded are still sound -- the TDF is
	// unfinishable through this writer, but nothing about the data
	// itself is in question.
	//
	// Unreachable with the default archive writer, whose Close cannot
	// fail; it is the injected-factory case this guards.
	ErrChunkedCloseFailed = errors.New("chunked: archive close failed after finalize; writer is unusable")

	// ErrChunkedFinalizeFailed is returned when the archive reports
	// that it had already mutated itself before failing -- or reports
	// nothing either way -- and by every later call on that writer.
	// Such a failure is not retryable: zipstream appends the payload
	// entry to the central directory partway through finalizing, then
	// can still fail on the manifest entry, on a ZIP64 requirement, or
	// on generating the directory bytes, and it does not roll that back
	// or mark itself finalized. A second attempt would append the
	// payload entry again, yielding a central directory with two
	// entries for one payload: an archive some readers accept and
	// silently misread. Failing fast is the only safe answer.
	//
	// An archive failure raised before any mutation does not produce
	// this error and does not fence the writer; see Finalize.
	ErrChunkedFinalizeFailed = errors.New("chunked: archive finalize failed; writer is unusable")

	// ErrChunkedInvalidSegmentIndex is returned when WriteSegment
	// receives a negative index.
	ErrChunkedInvalidSegmentIndex = errors.New("chunked: invalid segment index")

	// ErrChunkedMetadataChanged is returned by GetManifest and Finalize
	// when they are given encrypted metadata that differs from what an
	// earlier manifest build already sealed.
	//
	// Both re-resolve key access on every call, each with that call's own
	// WithChunkedEncryptedMetadata. Metadata is sealed at [metadataPart],
	// one part number, spent on the first value -- and for a single-split
	// TDF the share the metadata is sealed under is the DEK itself, so a
	// second value would be a second plaintext under the payload key and
	// the metadata part's IV. That is the IV reuse this construction
	// exists to make impossible, so the second value is refused rather
	// than silently ignored or silently reused.
	//
	// The pin is set even for empty metadata, and it survives a failed
	// build: what is spent is the part number, not the manifest. Build
	// again with the metadata you first passed, or start a new writer.
	//
	// Nothing was written and the writer is not fenced.
	ErrChunkedMetadataChanged = errors.New("chunked: encrypted metadata differs from an earlier manifest build")

	// ErrChunkedMissingSegmentZero is returned when Finalize is called
	// on a writer that never wrote segment 0. Only segment 0 emits the
	// payload's ZIP local file header, and every offset in the manifest
	// and central directory is measured from it.
	ErrChunkedMissingSegmentZero = errors.New("chunked: segment 0 was never written; it carries the payload's ZIP local file header")

	// ErrChunkedSegmentAlreadyWritten is returned when WriteSegment
	// receives an index that was already written.
	ErrChunkedSegmentAlreadyWritten = errors.New("chunked: segment already written")

	// ErrChunkedSegmentIndexExhausted is returned when WriteSegment
	// receives an index past [maxPayloadSegments], the number of
	// segments one key may encrypt.
	//
	// Distinct from ErrChunkedInvalidSegmentIndex on purpose: a
	// negative index is a bug in the caller, while this is a capacity
	// limit the caller can act on, and the remedy is named in the
	// message. It is reachable in normal use where the IV must come
	// from an RBG -- 1 TiB at the minimum segment size -- because
	// uniqueness is only probabilistic there and the ceiling drops to
	// hold the collision probability down. See
	// [ocrypto.MaxMessageParts].
	//
	// Nothing was written and the writer is not fenced; the index
	// never entered the segment table.
	ErrChunkedSegmentIndexExhausted = errors.New("chunked: too many segments for one key; use a larger segment size")

	// ErrChunkedWriteInFlight is returned by Finalize when a
	// WriteSegment has reserved an index but the archive has not yet
	// accepted its bytes. Finalizing inside that window would omit the
	// segment from the manifest while the racing WriteSegment still
	// returned success, so the caller would have no signal at all.
	//
	// Nothing was written and the writer is not fenced: join the
	// outstanding goroutines and call Finalize again.
	ErrChunkedWriteInFlight = errors.New("chunked: a segment write is still in flight; every WriteSegment must return before Finalize")
)

// ChunkedWriter creates a TDF from segments that may arrive in any
// order. Callers write each segment independently — typically
// off-thread or in parallel — then call Finalize to close the
// archive. Contrast with SDK.CreateTDF, which requires the full
// plaintext up front.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type ChunkedWriter interface {
	// Finalize completes TDF creation. Every option applies only to
	// this Finalize call; writer-level defaults set at NewChunked*
	// remain otherwise. Returns the closing bytes (the payload's data
	// descriptor, the embedded manifest entry, and the central
	// directory + end-of-central-directory record) that must be
	// appended after every segment's TDFData. Returns
	// ErrChunkedMissingSegmentZero if segment 0 was never written,
	// ErrChunkedAlreadyFinalized on a second call, and
	// ErrChunkedWriteInFlight if a WriteSegment has not yet returned.
	//
	// Only a mutation of the archive fences the writer. A refusal made
	// before the archive is touched -- an in-flight write, a cancelled
	// ctx, a rejected option, a splitter fault -- leaves the writer
	// usable: fix the cause and call Finalize again. A failure from the
	// archive itself after it has begun mutating, or a Close failure
	// after Finalize succeeded, leaves the writer unusable
	// (ErrChunkedFinalizeFailed / ErrChunkedCloseFailed), and every
	// subsequent call on it returns that same error rather than
	// retrying.
	//
	// A permitted retry is safe, not idempotent: each call mints a
	// fresh policy UUID and re-splits the DEK, so the manifest it
	// produces differs from the one the failed call would have.
	//
	// Finalize must happen-after every WriteSegment call returns.
	// Sequencing that is the caller's job -- wait on the errgroup,
	// close the channel, join the pool. Finalize does not block waiting
	// for in-flight writes (it cannot know how many are still coming);
	// it refuses with ErrChunkedWriteInFlight instead, so a missed join
	// is a deterministic error rather than a silently short TDF.
	Finalize(ctx context.Context, opts ...ChunkedFinalizeOption) (*ChunkedFinalizeResult, error)

	// GetManifest returns the manifest for the TDF. After Finalize it
	// is exactly the manifest that was written.
	//
	// Before Finalize it is a preview of the manifest's *shape* --
	// segment count, sizes, hashes, which KASes appear -- and nothing
	// more. It is not byte-stable and is not what Finalize will
	// produce: each call re-runs the whole manifest build, minting a
	// fresh policy UUID, re-splitting the DEK (so ephemeral wrapping
	// keys, and therefore every key access object, differ), and
	// re-signing any assertions. Two back-to-back calls with identical
	// options disagree, and so will Finalize. Use it to inspect
	// progress, never to predict or cache the final manifest.
	//
	// The one thing that may not vary across builds is the encrypted
	// metadata: the first build pins it, and any later build offering
	// a different value fails with ErrChunkedMetadataChanged. See that
	// error for why one value is all there is.
	//
	// It reflects only segments the archive has already accepted;
	// writes still in flight are skipped rather than waited on or
	// reported. Unlike Finalize it produces nothing durable, so a
	// snapshot one segment short is a correct snapshot of that instant
	// -- which is why, unlike Finalize, it does not refuse them.
	//
	// It is safe to call concurrently with WriteSegment. The writer lock
	// is held only long enough to copy segment metadata out; the key
	// split, which may make network calls to resolve KAS keys, runs
	// unlocked. That is why the result describes the writer as of the
	// snapshot rather than as of the return: a segment that lands while
	// the split is in flight is absent here and present in the next
	// call. Finalize, being terminal, keeps the lock throughout instead.
	GetManifest(ctx context.Context, opts ...ChunkedFinalizeOption) (*Manifest, error)

	// WriteSegment encrypts data as segment index and returns the ZIP
	// bytes for that segment: segment 0 is preceded by the payload's
	// ZIP local file header, every other segment is nonce + ciphertext
	// only. Callers upload or buffer those bytes; Finalize does not
	// re-emit them. Indices need not arrive in order and need not be
	// contiguous, but index 0 is mandatory: it carries that local file
	// header, so Finalize refuses a write set without it.
	//
	// data is neither retained nor modified; the caller may reuse the
	// buffer as soon as the call returns.
	WriteSegment(ctx context.Context, index int, data []byte) (*ChunkedSegmentResult, error)
}

// ChunkedSegmentResult carries the ZIP bytes for one segment plus its
// integrity metadata.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type ChunkedSegmentResult struct {
	// EncryptedSize is the ciphertext byte length including nonce and
	// GCM tag. It is the size the manifest records for this segment,
	// which for segment 0 is *not* the number of bytes TDFData yields:
	// that reader is prefixed with the payload's ZIP local file header,
	// which the manifest does not count. Size an upload from TDFData
	// itself (or from len(header)+EncryptedSize), never from
	// EncryptedSize alone.
	EncryptedSize int64

	// Hash is the base64-encoded segment integrity hash.
	Hash string

	// Index is the zero-based segment index.
	Index int

	// PlaintextSize is the byte length of the pre-encryption input.
	PlaintextSize int64

	// TDFData is a reader over the segment's ZIP-embedded ciphertext:
	// for segment 0 this is the payload's local file header + nonce +
	// AES-GCM output; every other segment omits the local header and
	// is nonce + AES-GCM output only. Callers assemble the TDF by
	// concatenating each segment's TDFData in emission order followed
	// by ChunkedFinalizeResult.Data.
	//
	// It may be read only once -- it is a stream over the buffers this
	// call produced, not a rewindable view of them. A second read
	// yields zero bytes and no error, so an upload that retries by
	// re-reading it silently writes nothing. Buffer the bytes yourself
	// if you need them twice.
	TDFData io.Reader
}

// ChunkedFinalizeResult carries the finalized TDF's closing bytes and
// metadata about what was written.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type ChunkedFinalizeResult struct {
	// Data is the ZIP closing bytes, in order: the payload's data
	// descriptor, the embedded manifest entry (its own local file
	// header + JSON data), and the central directory + EOCD record.
	// Append after every segment's TDFData to form the complete TDF
	// file -- including any segment WithChunkedSegments excluded from
	// the manifest; the archive's recorded size and CRC already
	// account for it regardless.
	Data []byte

	// EncryptedSize is the total ciphertext byte length across the
	// segments the manifest describes -- post-trim if
	// WithChunkedSegments was used.
	//
	// This is a property of the manifest, not of the file. It is not
	// the number of bytes to append: it counts nonce+ciphertext only,
	// where segment 0's TDFData additionally carries the payload's ZIP
	// local file header, and it omits any segment WithChunkedSegments
	// dropped, whose bytes the caller must still append. Size an upload
	// by measuring the TDFData readers as they are consumed -- the only
	// quantity that counts every byte exactly once. Sizing it from this
	// field truncates the payload, and the corruption surfaces only at
	// decrypt.
	EncryptedSize int64

	// Manifest is the finalized manifest that was serialized into the
	// archive.
	Manifest *Manifest

	// TotalSegments is the number of segments in the finalized
	// manifest (post-trim if WithChunkedSegments was used).
	TotalSegments int

	// TotalSize is the total plaintext byte length across the segments
	// the manifest describes, post-trim on the same basis as
	// EncryptedSize.
	TotalSize int64
}

// chunkedWriterConfig captures the settings supplied at
// NewChunkedWriter time. Fields are unexported; use options.
type chunkedWriterConfig struct {
	// archiveFactory builds the ZIP archive writer that lays out the
	// TDF. Defaults to defaultArchiveWriterFactory.
	archiveFactory archiveWriterFactory

	// sealerFactory builds a segment sealer from a key and the message
	// ID. Defaults to defaultSegmentSealerFactory (AES-256-GCM).
	// Ignored when sealers is set, which brings its own.
	sealerFactory segmentSealerFactory

	// sealers is the message's sealer registry. When nil the writer
	// draws a message ID from rand -- after the DEK, so that
	// withChunkedRand stays a deterministic 32-then-8-byte draw -- and
	// builds one. SDK.CreateTDF presets the registry it already used to
	// seal key access metadata, so that path's metadata and payload
	// share one message ID, one sealer per key, and one encryption
	// budget.
	sealers *messageSealers

	// clock supplies the current time to the writer and the
	// underlying zipstream. Defaults to systemClock. Tests inject
	// fixedClock for deterministic ZIP output.
	clock clock

	// dek is a pre-generated Data Encryption Key. When nil the writer
	// draws one from rand. SDK.CreateTDF presets it so that it can
	// resolve key access before emitting any payload bytes.
	dek []byte

	// excludeVersion omits the schemaVersion field from the manifest.
	// Set together with useHex by WithChunkedTargetMode; readers use
	// the field's absence as the pre-4.3.0 marker, so the two must
	// agree.
	excludeVersion bool

	// initialAttributes are the attribute values used at Finalize
	// when the Finalize call does not supply its own.
	initialAttributes []*policy.Value

	// initialDefaultKAS is the default KAS used at Finalize when the
	// Finalize call does not supply its own.
	initialDefaultKAS *policy.SimpleKasKey

	// keyAccess resolves the manifest policy and key access objects.
	// Defaults to a splitterKeyAccess over splitter.
	keyAccess keyAccessResolver

	// rand is the entropy source used to generate the DEK. Defaults
	// to crypto/rand.Reader.
	rand io.Reader

	// segmentSize is the plaintext segment size advertised in the
	// manifest. Zero means "report the first segment's actual size",
	// which is right when every segment is the same length.
	segmentSize int64

	// splitter maps attribute values to DEK splits at Finalize time.
	// Defaults to DefaultKeySplitter (single-KAS only). Ignored when
	// keyAccess is set.
	splitter KeySplitter

	// useHex hex-encodes segment, root, and assertion signatures
	// before base64, producing the doubly-encoded form that readers
	// older than 4.3.0 require. Set by WithChunkedTargetMode.
	useHex bool
}

// chunkedFinalizeConfig captures Finalize-time overrides.
type chunkedFinalizeConfig struct {
	// assertions to sign and attach to the produced TDF. Each
	// AssertionConfig may carry a SigningKey; one that does not is
	// signed with HS256 over the writer's DEK.
	assertions []AssertionConfig

	// attributes overrides the writer's initialAttributes for this
	// Finalize call.
	attributes []*policy.Value

	// defaultKAS overrides the writer's initialDefaultKAS for this
	// Finalize call.
	defaultKAS *policy.SimpleKasKey

	// encryptedMetadata is opaque metadata AES-GCM-encrypted on each
	// KAO with the split share.
	encryptedMetadata string

	// excludeVersion omits the schemaVersion field from the manifest
	// for compatibility with older readers. Defaults to the writer's
	// setting; see WithChunkedTargetMode.
	excludeVersion bool

	// keepSegments names the segments the finalized manifest
	// describes: must be a prefix of the written segments in ascending
	// index order, dropping only from the end. Empty means every
	// written segment, ascending. See WithChunkedSegments.
	keepSegments []int

	// mimeType records the payload MIME type in the manifest.
	// Defaults to [defaultMimeType].
	mimeType string
}

// ChunkedWriterOption configures a ChunkedWriter at construction
// time.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type ChunkedWriterOption func(*chunkedWriterConfig) error

// ChunkedFinalizeOption configures a single Finalize call.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type ChunkedFinalizeOption func(*chunkedFinalizeConfig) error

// segmentSlot is one entry in the writer's segment table. The slot
// appears the moment WriteSegment reserves an index, which is what
// makes a second write to that index fail, but written stays false
// until the archive has durably accepted the bytes. Only a written
// slot is visible to the manifest: a reservation describes bytes that
// may yet never exist.
//
// The two are separate fields rather than a sentinel in seg.Size
// because zero-length segments are legal, so no size value is free to
// mean "not yet".
type segmentSlot struct {
	// seg is the manifest metadata for this segment. Meaningful only
	// once written is true.
	seg Segment

	// written is true once the archive has accepted the segment's
	// bytes and seg has been filled in.
	written bool
}

// chunkedWriter is the concrete ChunkedWriter.
type chunkedWriter struct {
	// archiveWriter handles the underlying ZIP archive creation.
	archiveWriter zipstream.SegmentWriter

	// stream seals payload segments. It is the DEK's entry in sealers,
	// resolved once at construction so the payload hot path never takes the
	// registry lock.
	stream segmentSealer

	// sealers holds one sealer per key this message is sealed under, all
	// sharing one message ID. Retained past construction because key access
	// metadata is sealed under the split shares, whose keys are not known
	// until Finalize.
	sealers *messageSealers

	// sealMetadata seals key access object metadata at [metadataPart] through
	// sealers. Built once, because the registry it closes over carries the
	// per-key encryption budget and the once-only metadata cache.
	sealMetadata metadataSealer

	// dek is the Data Encryption Key. 32 bytes (AES-256).
	dek []byte

	// excludeVersion omits schemaVersion from the manifest unless a
	// Finalize option overrides it.
	excludeVersion bool

	// unusable is non-nil once the archive has been left in a state no
	// later call can recover from: its Finalize failed partway through
	// its own mutations, its Close failed after Finalize had succeeded,
	// or a failed WriteSegment could not roll its partial write back
	// out. In each case w.finalized stays false, yet the archive can no
	// longer be trusted, so every method returns this error instead of
	// continuing. It holds the wrapped original, so callers see both
	// the sentinel and the underlying cause.
	//
	// Only an unrecoverable mutation sets it. A Finalize that fails
	// before the archive is touched -- an in-flight write, a cancelled
	// ctx, a bad option, a splitter fault, or an archive error reported
	// as non-mutating -- leaves this nil and the writer retryable, as
	// does a failed WriteSegment whose cleanup succeeded.
	unusable error

	// finalized is true once Finalize returns successfully.
	finalized bool

	// initialAttributes captured at construction; used by Finalize
	// when the caller does not override.
	initialAttributes []*policy.Value

	// initialDefaultKAS captured at construction; used by Finalize
	// when the caller does not override.
	initialDefaultKAS *policy.SimpleKasKey

	// keyAccess resolves the manifest policy and key access objects
	// for the DEK.
	keyAccess keyAccessResolver

	// manifest holds the finalized manifest for post-Finalize
	// GetManifest calls.
	manifest *Manifest

	// metadataMu guards metadataPin. Separate from mu because buildManifest
	// deliberately runs with mu released.
	metadataMu sync.Mutex

	// metadataPin is the encrypted metadata the first manifest build used,
	// nil until then. A later build offering a different value is refused
	// with ErrChunkedMetadataChanged. See pinMetadata.
	metadataPin *string

	// mu guards writer state that spans WriteSegment and Finalize.
	mu sync.RWMutex

	// segments records per-index slots, reserved and then written.
	segments map[int]*segmentSlot

	// segmentSize is the plaintext segment size to advertise in the
	// manifest, or zero to infer it from the first segment.
	segmentSize int64

	// useHex selects the pre-4.3.0 doubly-encoded signature form.
	// Read by WriteSegment, so it is fixed at construction rather
	// than at Finalize.
	useHex bool
}

// NewChunkedWriter constructs a per-segment TDF writer. WriteSegment
// may be called from several goroutines at once so long as each
// targets a distinct segment index; two concurrent calls for the same
// index are not allowed, and one of them will fail with
// ErrChunkedSegmentAlreadyWritten rather than corrupt the archive.
//
// Finalize must happen-after every WriteSegment returns. The writer
// cannot sequence that for you, but it will not paper over a missed
// join either: Finalize refuses with ErrChunkedWriteInFlight while any
// index is reserved but not yet accepted by the archive, rather than
// emitting a TDF that is short by however many writes lost the race.
// It does not block — it has no way to know how many more writes are
// coming — so join your goroutines and call it again.
//
// No SDK value is needed. The key splitter (WithChunkedKeySplitter)
// and the attribute and KAS defaults (WithChunkedInitialAttributes,
// WithChunkedDefaultKAS) are supplied through options; the clock,
// sealer, archive-writer and entropy seams are unexported test seams
// and are not reachable from outside this package.
//
// Experimental: not part of the stable SDK API; may change or be removed.
func NewChunkedWriter(_ context.Context, opts ...ChunkedWriterOption) (ChunkedWriter, error) {
	cfg := chunkedWriterConfig{
		archiveFactory: defaultArchiveWriterFactory,
		sealerFactory:  defaultSegmentSealerFactory,
		clock:          systemClock{},
		rand:           rand.Reader,
		splitter:       DefaultKeySplitter(),
	}
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	return newChunkedWriter(cfg)
}

// newChunkedWriter builds the writer from a fully-populated config.
// SDK.CreateTDF calls this directly with the unexported knobs its
// classic behavior needs — a preset DEK, key access resolved before
// the first payload byte, a fixed segment size — rather than going
// through the public option set.
func newChunkedWriter(cfg chunkedWriterConfig) (*chunkedWriter, error) {
	dek := cfg.dek
	if dek == nil {
		dek = make([]byte, kKeySize)
		if _, err := io.ReadFull(cfg.rand, dek); err != nil {
			return nil, fmt.Errorf("generate DEK: %w", err)
		}
	}
	// Drawn after the DEK, so an injected rand stays a deterministic
	// 32-then-8-byte draw and existing fixtures keep their DEK.
	sealers := cfg.sealers
	if sealers == nil {
		id, err := ocrypto.NewMessageID(cfg.rand)
		if err != nil {
			return nil, fmt.Errorf("generate message id: %w", err)
		}
		sealers = newMessageSealers(id, cfg.sealerFactory)
	}
	stream, err := sealers.sealerFor(dek)
	if err != nil {
		return nil, fmt.Errorf("build segment sealer: %w", err)
	}
	keyAccess := cfg.keyAccess
	if keyAccess == nil {
		keyAccess = splitterKeyAccess{splitter: cfg.splitter}
	}
	return &chunkedWriter{
		archiveWriter:     cfg.archiveFactory(cfg.clock),
		dek:               dek,
		excludeVersion:    cfg.excludeVersion,
		initialAttributes: cfg.initialAttributes,
		initialDefaultKAS: cfg.initialDefaultKAS,
		keyAccess:         keyAccess,
		sealMetadata:      newMetadataSealer(sealers),
		sealers:           sealers,
		segments:          make(map[int]*segmentSlot),
		segmentSize:       cfg.segmentSize,
		stream:            stream,
		useHex:            cfg.useHex,
	}, nil
}

// Finalize serializes the manifest, closes the archive, and returns
// the trailing bytes.
func (w *chunkedWriter) Finalize(ctx context.Context, opts ...ChunkedFinalizeOption) (*ChunkedFinalizeResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.unusable != nil {
		return nil, w.unusable
	}
	if w.finalized {
		return nil, ErrChunkedAlreadyFinalized
	}

	// Refuse before diagnosing anything else. A write still in flight makes
	// every later check unsound: the segment-0 check below would report a
	// missing segment 0 when segment 0 is merely unfinished, sending the caller
	// hunting an indexing bug. Nothing has been touched at this point, so the
	// writer stays usable -- join the goroutines and call again.
	if reserved := w.reservedIndicesLocked(); len(reserved) > 0 {
		return nil, fmt.Errorf("%w: %d in flight, indices %s",
			ErrChunkedWriteInFlight, len(reserved), summarizeSegmentIndices(reserved))
	}

	// Segment 0 is the only one that emits the payload's ZIP local file
	// header (see zipstream.segmentWriter.WriteSegment), and the archive
	// measures every offset it records from that header being at the
	// front of the assembled stream. It cannot be synthesized here: by
	// Finalize the caller has already encrypted and uploaded the bytes it
	// would have to precede.
	if slot, ok := w.segments[0]; !ok || !slot.written {
		return nil, ErrChunkedMissingSegmentZero
	}

	cfg, err := w.applyFinalizeOptions(opts)
	if err != nil {
		return nil, err
	}

	// Finalize keeps the write lock across the split, where GetManifest
	// releases it. It is terminal -- no later WriteSegment can succeed, and
	// ErrChunkedWriteInFlight above has already established that none is
	// outstanding -- so there is no concurrency left to preserve, and dropping
	// the lock would only reopen the window in which a segment lands in the
	// archive after the snapshot that determines the manifest.
	snap, err := w.snapshotLocked(cfg.keepSegments)
	if err != nil {
		return nil, err
	}

	manifest, totals, err := w.buildManifest(ctx, cfg, snap)
	if err != nil {
		return nil, err
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

	// ctx is checked here rather than inferred from the archive's error. A
	// cancellation the archive notices after it has started mutating is
	// indistinguishable at the error site from one it notices before, and only
	// the second is safe to retry. Checking immediately beforehand makes the
	// distinction structural: nothing has been touched, so nothing to fence.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("chunked: finalize: %w", err)
	}

	finalBytes, err := w.archiveWriter.Finalize(ctx, manifestBytes)
	if err != nil {
		// Fence unless the archive affirmatively reports that it failed before
		// changing itself. Fail safe: "we mutated" and "we did not say" get the
		// same answer, because the cost of guessing wrong is a central
		// directory with two entries for one payload -- an archive some readers
		// accept and silently misread. See ErrChunkedFinalizeFailed.
		var zerr *zipstream.Error
		if errors.As(err, &zerr) && !zerr.Mutated {
			// Not fenced: w.unusable and w.finalized are untouched, so the
			// caller may write more segments and finalize again.
			return nil, fmt.Errorf("chunked: finalize archive: %w", err)
		}
		w.unusable = fmt.Errorf("%w: %w", ErrChunkedFinalizeFailed, err)
		return nil, w.unusable
	}
	if err := w.archiveWriter.Close(); err != nil {
		// The archive is terminally finalized internally regardless of
		// this error, so a retry can only ever hit the same failure.
		w.unusable = fmt.Errorf("%w: %w", ErrChunkedCloseFailed, err)
		return nil, w.unusable
	}

	w.finalized = true
	w.manifest = manifest
	return &ChunkedFinalizeResult{
		Data:          finalBytes,
		EncryptedSize: totals.encrypted,
		// Cloned for the same reason GetManifest clones: w.manifest is
		// the writer's own record of what the archive bytes say, and
		// handing out that pointer would let a caller edit it and see
		// the edit come back from a later GetManifest, or race one.
		Manifest:      cloneChunkedManifest(manifest),
		TotalSegments: len(manifest.Segments),
		TotalSize:     totals.plaintext,
	}, nil
}

// GetManifest returns the manifest snapshot.
func (w *chunkedWriter) GetManifest(ctx context.Context, opts ...ChunkedFinalizeOption) (*Manifest, error) {
	written, cfg, snap, err := w.getManifestSnapshot(opts)
	if err != nil {
		return nil, err
	}
	if written != nil {
		return written, nil
	}
	// Built outside the lock. KeySplitter.Split may resolve KAS keys over the
	// network, and RWMutex bars new readers once a writer is queued, so holding
	// RLock across it would stall not just every WriteSegment commit but every
	// other GetManifest behind it, for as long as that I/O takes.
	manifest, _, err := w.buildManifest(ctx, cfg, snap)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

// WriteSegment encrypts data as segment index and returns the ZIP
// bytes for that segment.
func (w *chunkedWriter) WriteSegment(ctx context.Context, index int, data []byte) (*ChunkedSegmentResult, error) {
	w.mu.Lock()
	if w.unusable != nil {
		err := w.unusable
		w.mu.Unlock()
		return nil, err
	}
	if w.finalized {
		w.mu.Unlock()
		return nil, ErrChunkedAlreadyFinalized
	}
	// Resolved here, alongside the other index checks and before the
	// reservation below, so an index this writer can never seal is rejected
	// without ever entering w.segments.
	part, err := segmentPart(index)
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	if _, ok := w.segments[index]; ok {
		w.mu.Unlock()
		return nil, ErrChunkedSegmentAlreadyWritten
	}
	// Reserve the index so a concurrent write to the same one is
	// rejected, but leave the slot unwritten: the segment does not
	// count as written until its bytes are in the archive.
	slot := &segmentSlot{}
	w.segments[index] = slot
	w.mu.Unlock()

	// release drops the reservation so the caller can retry this index
	// after a failure. It matches on identity and on the placeholder
	// still being unwritten, so it can never discard a segment some
	// other call has since completed.
	// cleanupErr, when non-nil, additionally fences the writer: the
	// reservation is gone but the archive may still carry the failed
	// attempt, so no later call can be trusted.
	release := func(cleanupErr error) {
		w.mu.Lock()
		if cur, ok := w.segments[index]; ok && cur == slot && !cur.written {
			delete(w.segments, index)
		}
		if cleanupErr != nil && w.unusable == nil {
			w.unusable = fmt.Errorf("%w: segment %d: %w", ErrChunkedCleanupFailed, index, cleanupErr)
		}
		w.mu.Unlock()
	}

	// committed marks the point past which the archive has durably
	// accepted the write. Until then, every exit path -- including a
	// panic unwinding through an injected cipher or archive-writer seam
	// -- must release the reservation, or the index is wedged forever:
	// retries see ErrChunkedSegmentAlreadyWritten and default-mode
	// Finalize can never find every index accounted for.
	committed := false
	archiveWriteAttempted := false
	defer func() {
		if committed {
			return
		}
		var cleanupErr error
		if archiveWriteAttempted {
			// The archive may have partially recorded the write before
			// failing; CleanupSegment undoes that so a retry starts
			// from a state indistinguishable from never having been
			// attempted (see zipstream.SegmentWriter's contract). The
			// concrete writer's CleanupSegment cannot itself fail; a
			// custom archiveWriterFactory that does fail here leaves
			// the archive in a state this code cannot characterize, so
			// release() fences the writer. It does not change what this
			// call returns -- the original write error is the cause,
			// and reporting the rollback instead would hide it.
			//
			// This must precede release(): the reservation is the only
			// thing keeping another goroutine out of this index, and
			// CleanupSegment addresses the index rather than a
			// particular attempt at it. Releasing first lets a racing
			// write claim the index and get its bytes accepted by the
			// archive, whereupon this call deletes that attempt's
			// record and rolls back its size accounting -- leaving the
			// winner to publish segment metadata for bytes the archive
			// no longer knows about.
			//
			// The two locks are taken sequentially here -- CleanupSegment
			// takes and drops the archive's, then release() takes and drops
			// w.mu -- never nested. Finalize nests them the other way, w.mu
			// across archiveWriter.Finalize, so hoisting w.mu.Lock() above
			// this call to "simplify" the defer closes the cycle and
			// deadlocks the writer.
			cleanupErr = w.archiveWriter.CleanupSegment(index)
		}
		release(cleanupErr)
	}()

	// Retry analysis, because the IV is now a pure function of the index.
	// Retrying a failed index re-derives the same IV, so a retry carrying
	// *different* bytes would be a second encryption under one key and IV --
	// which leaks the XOR of the two plaintexts and the GHASH subkey.
	//
	// That cannot happen as this function is written today. Every failure path
	// from here to the archive write is a bare `return nil, err` that
	// constructs no ChunkedSegmentResult; the archive is handed a length and a
	// CRC, never bytes; the deferred CleanupSegment rolls even that back or
	// else fences the writer; and an index the archive did accept can never be
	// retried (ErrChunkedSegmentAlreadyWritten, above). At most one ciphertext
	// per (key, IV) ever leaves this function.
	//
	// That is a property of this error handling, not of the IV construction,
	// and one refactor away from being false. Anything added below that can
	// emit segment bytes on a path that later fails has to preserve it.
	//
	// On the RBG fallback the same retry is harmless -- a fresh IV is drawn --
	// but not free: the attempt is charged against the key's encryption budget
	// whether or not the archive goes on to accept it. Cleanup releases the
	// index, never the budget. Failures before this call, an invalid part
	// among them, cost nothing.
	header, ciphertext, err := w.stream.Seal(part, data)
	if err != nil {
		return nil, fmt.Errorf("encrypt segment %d: %w", index, err)
	}
	// SegmentGMAC reads the trailing AEAD tag, so hashing ciphertext alone is
	// equivalent to hashing header||ciphertext -- which is why there is no
	// concatenation here. An algorithm that MACs the whole segment (HS256)
	// would need the header prepended back.
	sig, err := segmentIntegrity(ciphertext, w.dek, SegmentGMAC, w.useHex)
	if err != nil {
		return nil, fmt.Errorf("segment %d signature: %w", index, err)
	}
	hash := string(ocrypto.Base64Encode([]byte(sig)))
	encryptedSize := int64(len(header) + len(ciphertext))

	crc := crc32.Update(crc32.ChecksumIEEE(header), crc32.IEEETable, ciphertext)
	// Deliberately outside w.mu. Finalize's ErrChunkedWriteInFlight exists
	// because this call is unsynchronized against it; holding w.mu here would
	// close that window by serializing every segment write, which is the one
	// thing this writer exists not to do.
	archiveWriteAttempted = true
	zipHeader, err := w.archiveWriter.WriteSegment(ctx, index, uint64(encryptedSize), crc)
	if err != nil {
		return nil, fmt.Errorf("write segment %d to archive: %w", index, err)
	}

	// Commit only once the archive has accepted the segment. Publishing
	// the metadata earlier would let Finalize emit a manifest that
	// describes bytes the archive never received.
	w.mu.Lock()
	slot.seg = Segment{
		EncryptedSize: encryptedSize,
		Hash:          hash,
		Size:          int64(len(data)),
	}
	slot.written = true
	// Set under the same lock that publishes the slot, not after it. Once
	// written is true, release() declines to drop the reservation, so a panic
	// unwinding between the two would run CleanupSegment -- deleting the
	// archive's record and rolling back its size accounting -- while leaving a
	// slot the manifest still describes. Publication and commit are one step.
	committed = true
	w.mu.Unlock()

	// Two distinct prefixes: zipHeader is the segment's ZIP local file header,
	// emitted only for segment 0, and header is the part's 12-byte AES-GCM IV,
	// which every segment carries.
	var reader io.Reader
	if len(zipHeader) == 0 {
		reader = io.MultiReader(bytes.NewReader(header), bytes.NewReader(ciphertext))
	} else {
		reader = io.MultiReader(bytes.NewReader(zipHeader), bytes.NewReader(header), bytes.NewReader(ciphertext))
	}
	// Reported from the locals rather than from seg, which is shared with
	// concurrent readers of w.segments once the lock is released.
	return &ChunkedSegmentResult{
		EncryptedSize: encryptedSize,
		Hash:          hash,
		Index:         index,
		PlaintextSize: int64(len(data)),
		TDFData:       reader,
	}, nil
}

// reservedIndicesLocked returns the indices WriteSegment has claimed but the
// archive has not accepted, in ascending order. Caller holds mu.
//
// This is the in-flight set, computed rather than counted. A separate counter
// would have to be incremented with the reservation and decremented at both
// exits -- commit and release -- and would drift silently if either exit were
// ever missed; the drift direction that matters (undercount) reopens exactly
// the race this guards. The map is the reservation, so reading it cannot
// disagree with it.
//
// Cost is one pass over w.segments, on a path that already sorts it
// (segmentOrderLocked) and walks it again (buildManifest).
func (w *chunkedWriter) reservedIndicesLocked() []int {
	var reserved []int
	for idx, slot := range w.segments {
		if !slot.written {
			reserved = append(reserved, idx)
		}
	}
	slices.Sort(reserved)
	return reserved
}

// maxReportedSegmentIndices caps how many indices an error message lists, so a
// writer with thousands of segments in flight does not produce an error string
// measured in kilobytes.
const maxReportedSegmentIndices = 8

// summarizeSegmentIndices renders indices for an error message, truncating
// past maxReportedSegmentIndices.
func summarizeSegmentIndices(indices []int) string {
	if len(indices) <= maxReportedSegmentIndices {
		return fmt.Sprint(indices)
	}
	return fmt.Sprintf("%v ... (%d more)",
		indices[:maxReportedSegmentIndices], len(indices)-maxReportedSegmentIndices)
}

// applyFinalizeOptions builds a chunkedFinalizeConfig with defaults
// then applies each option in order.
func (w *chunkedWriter) applyFinalizeOptions(opts []ChunkedFinalizeOption) (*chunkedFinalizeConfig, error) {
	cfg := &chunkedFinalizeConfig{
		attributes:        nil,
		encryptedMetadata: "",
		excludeVersion:    w.excludeVersion,
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	// Every default below is resolved after the option loop, so the zero value
	// uniformly reads as "not specified" and falls back. Defaulting mimeType
	// before the loop instead would make WithChunkedMimeType("") the one option
	// whose empty argument is taken literally, writing a manifest with no MIME
	// type rather than the default one.
	if len(cfg.attributes) == 0 && len(w.initialAttributes) > 0 {
		cfg.attributes = w.initialAttributes
	}
	if cfg.defaultKAS == nil && w.initialDefaultKAS != nil {
		cfg.defaultKAS = w.initialDefaultKAS
	}
	if cfg.mimeType == "" {
		cfg.mimeType = defaultMimeType
	}
	return cfg, nil
}

// chunkedSnapshot is the mutable writer state buildManifest needs, copied out
// from under the lock so the build itself -- which calls KeySplitter.Split --
// can run unlocked.
//
// Segment values, not the *segmentSlot pointers w.segments holds: WriteSegment
// mutates a slot in place when the archive accepts its bytes, so reading one
// after the lock is released would race.
type chunkedSnapshot struct {
	// segments are the per-segment metadata records in emission order.
	segments []Segment
}

// snapshotLocked resolves the emission order and copies each named segment's
// metadata out of w.segments. Caller holds mu.
func (w *chunkedWriter) snapshotLocked(keep []int) (*chunkedSnapshot, error) {
	order, err := w.segmentOrderLocked(keep)
	if err != nil {
		return nil, err
	}
	snap := &chunkedSnapshot{segments: make([]Segment, len(order))}
	for i, idx := range order {
		// segmentOrderLocked only ever names written slots, whether it
		// derived the order itself or validated a caller-supplied one.
		slot, ok := w.segments[idx]
		if !ok || !slot.written {
			return nil, fmt.Errorf("segment %d not written; cannot finalize", idx)
		}
		if slot.seg.Hash == "" {
			return nil, fmt.Errorf("segment %d has empty hash", idx)
		}
		snap.segments[i] = slot.seg
	}
	return snap, nil
}

// getManifestSnapshot is the locked half of GetManifest: the state checks, the
// option pass, and the segment copy. Split out so the read lock is released by
// a defer rather than tracked by hand across the several exits, one of which
// (the already-finalized clone) returns a manifest and the rest of which return
// the inputs the unlocked half needs. A non-nil first result means the caller
// is done and must not build anything.
func (w *chunkedWriter) getManifestSnapshot(opts []ChunkedFinalizeOption) (*Manifest, *chunkedFinalizeConfig, *chunkedSnapshot, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.unusable != nil {
		return nil, nil, nil, w.unusable
	}
	if w.finalized {
		if w.manifest == nil {
			// Unreachable unless Finalize is changed to set finalized without
			// recording what it wrote. Refuse rather than fall through to the
			// rebuild below: after finalize the caller is asking what shipped,
			// and a rebuild does not answer that. It mints a fresh policy UUID
			// and fresh key splits, so it would hand back a plausible manifest
			// that does not describe the bytes -- and a caller that stored it
			// alongside them could not decrypt.
			return nil, nil, nil, errors.New("chunked: writer is finalized but recorded no manifest")
		}
		return cloneChunkedManifest(w.manifest), nil, nil, nil
	}
	cfg, err := w.applyFinalizeOptions(opts)
	if err != nil {
		return nil, nil, nil, err
	}
	// No in-flight check here, deliberately: see GetManifest's interface doc.
	snap, err := w.snapshotLocked(cfg.keepSegments)
	if err != nil {
		return nil, nil, nil, err
	}
	return nil, cfg, snap, nil
}

// chunkedTotals are the byte counts across the segments the manifest
// describes. They are reported for information only; neither is the number of
// bytes the caller must append, which is what the TDFData readers yield and
// nothing here tracks. See ChunkedFinalizeResult.EncryptedSize.
type chunkedTotals struct {
	// encrypted is the ciphertext length across the segments in the manifest.
	encrypted int64

	// plaintext is the plaintext length across the segments in the manifest.
	plaintext int64
}

// pinMetadata records the encrypted metadata of the first manifest build and
// refuses any later build that offers a different value, returning
// ErrChunkedMetadataChanged. See that error for why one value is all there is.
//
// The check and the set are one critical section so that two concurrent first
// builds cannot both pass; the lock is released before the resolver runs,
// which may call a KAS. The pin is never cleared: a failed build has already
// spent the part number, and the point is to bound what is sealed under it,
// not what is published.
func (w *chunkedWriter) pinMetadata(metadata string) error {
	w.metadataMu.Lock()
	defer w.metadataMu.Unlock()

	if w.metadataPin == nil {
		w.metadataPin = &metadata
		return nil
	}
	if *w.metadataPin != metadata {
		return ErrChunkedMetadataChanged
	}
	return nil
}

// buildManifest composes the manifest from a snapshot, resolves the key
// access objects, and computes the root signature.
//
// Apart from the metadata pin -- which has its own lock, precisely because of
// this -- it reads no mutable writer state and takes no lock: every other
// field it touches (dek, keyAccess, sealMetadata, useHex) is fixed at
// construction. Keep it that way: GetManifest calls it with the read lock
// released.
func (w *chunkedWriter) buildManifest(ctx context.Context, cfg *chunkedFinalizeConfig, snap *chunkedSnapshot) (*Manifest, chunkedTotals, error) {
	var totals chunkedTotals

	if err := w.pinMetadata(cfg.encryptedMetadata); err != nil {
		return nil, totals, err
	}

	base64Policy, kaos, err := w.keyAccess.resolve(ctx, w.dek, w.sealMetadata, cfg)
	if err != nil {
		return nil, totals, err
	}

	encInfo := EncryptionInformation{
		KeyAccessObjs: kaos,
		KeyAccessType: kSplitKeyType,
		Policy:        base64Policy,
		Method: Method{
			Algorithm:    kGCMCipherAlgorithm,
			IsStreamable: true,
		},
		IntegrityInformation: IntegrityInformation{
			SegmentHashAlgorithm: SegmentGMAC.String(),
			Segments:             make([]Segment, len(snap.segments)),
		},
	}

	var aggregate bytes.Buffer
	for i, seg := range snap.segments {
		encInfo.Segments[i] = seg
		totals.plaintext += seg.Size
		totals.encrypted += seg.EncryptedSize
		decoded, err := ocrypto.Base64Decode([]byte(seg.Hash))
		if err != nil {
			// Position in the emission order, not the segment index: the
			// snapshot no longer carries the indices, and the two coincide for
			// the default (untrimmed, contiguous) write set anyway.
			return nil, totals, fmt.Errorf("decode segment at position %d hash: %w", i, err)
		}
		aggregate.Write(decoded)
	}

	// A caller that knows the segment size says so, because the first
	// segment's actual length is only the right answer when every
	// segment is full — and the last one usually is not, so a
	// single-segment TDF would otherwise advertise a short default.
	switch {
	case w.segmentSize > 0:
		encInfo.DefaultSegmentSize = w.segmentSize
		encInfo.DefaultEncryptedSegSize = w.segmentSize + gcmIvSize + aesBlockSize
	case len(snap.segments) > 0:
		encInfo.DefaultEncryptedSegSize = snap.segments[0].EncryptedSize
		encInfo.DefaultSegmentSize = snap.segments[0].Size
	}

	rootSig, err := rootIntegrity(aggregate.Bytes(), w.dek, RootHS256, w.useHex)
	if err != nil {
		return nil, totals, err
	}
	encInfo.RootSignature = RootSignature{
		Algorithm: RootHS256.String(),
		Signature: string(ocrypto.Base64Encode([]byte(rootSig))),
	}

	// Assertions bind to the same aggregate hash the root signature
	// covers, so they can only be signed once every segment is in.
	assertions, err := signAssertions(aggregate.Bytes(), cfg.assertions, w.dek, w.useHex)
	if err != nil {
		return nil, totals, err
	}

	manifest := &Manifest{
		Assertions:            assertions,
		EncryptionInformation: encInfo,
		Payload: Payload{
			IsEncrypted: true,
			MimeType:    cfg.mimeType,
			Protocol:    tdfAsZip,
			Type:        tdfZipReference,
			URL:         zipstream.TDFPayloadFileName,
		},
	}
	if !cfg.excludeVersion {
		manifest.TDFVersion = TDFSpecVersion
	}
	return manifest, totals, nil
}

// segmentOrderLocked returns the emission order given the current
// writer state and an optional keepSegments subset. Caller holds mu.
//
// With no subset, every written segment is emitted in ascending index
// order. Indices that are merely reserved -- WriteSegment has claimed
// them but the archive has not accepted their bytes yet -- are not
// written and are skipped. That is what lets GetManifest run
// concurrently with in-flight writes, which is its whole purpose: a
// reservation describes bytes that may never exist, so including one
// would make every such call fail on a segment that is not late, just
// unfinished.
//
// A supplied subset must be a prefix of that same ascending sequence.
// Note this constrains position, not value: the written indices
// themselves may be sparse (a caller reserving a block of indices per
// upload part and filling only part of each block writes e.g.
// 0,1,5000,5001), and any such set is accepted so long as the subset
// names its members in order and drops only from the end. Whether
// index 0 is among them is Finalize's business, not this function's:
// GetManifest shares this path and legitimately runs before segment 0
// has been written.
//
// Both halves of that rule are forced by the archive layout, which
// stores segments sorted by index. Reordering would make the manifest
// disagree with the bytes on disk; dropping a segment that has bytes
// after it would shift every later segment's offset.
func (w *chunkedWriter) segmentOrderLocked(keep []int) ([]int, error) {
	written := make([]int, 0, len(w.segments))
	for idx, slot := range w.segments {
		if !slot.written {
			continue
		}
		written = append(written, idx)
	}
	slices.Sort(written)
	if len(keep) == 0 {
		return written, nil
	}
	if len(keep) > len(written) {
		return nil, fmt.Errorf("WithChunkedSegments names %d segments but only %d were written", len(keep), len(written))
	}
	for i, idx := range keep {
		if idx == written[i] {
			continue
		}
		// A reserved-but-unwritten index reads as "not written" here,
		// the same as one never claimed at all: naming it in the
		// manifest would describe bytes the archive has not accepted.
		if slot, ok := w.segments[idx]; !ok || !slot.written {
			return nil, fmt.Errorf("WithChunkedSegments references segment %d which was not written", idx)
		}
		return nil, fmt.Errorf(
			"WithChunkedSegments must name written segments in ascending index order and may drop only from the end; got %d at position %d where %d was expected",
			idx, i, written[i],
		)
	}
	out := make([]int, len(keep))
	copy(out, keep)
	return out, nil
}

// cloneChunkedManifest copies the manifest struct and clones its three
// slices, which is what makes the result safe to hand to a caller: it
// can append to or overwrite elements of Segments, KeyAccessObjs and
// Assertions without the writer's copy changing. The clones are
// shallow, so a caller reaching into a pointer or map inside an
// element -- an Assertion's binding, a KeyAccess's policy binding --
// still shares that state. Nothing in this package hands out a
// manifest a caller has any reason to mutate that deeply.
func cloneChunkedManifest(in *Manifest) *Manifest {
	if in == nil {
		return nil
	}
	out := *in
	if in.KeyAccessObjs != nil {
		out.KeyAccessObjs = slices.Clone(in.KeyAccessObjs)
	}
	if in.Segments != nil {
		out.Segments = slices.Clone(in.Segments)
	}
	if in.Assertions != nil {
		out.Assertions = slices.Clone(in.Assertions)
	}
	return &out
}
