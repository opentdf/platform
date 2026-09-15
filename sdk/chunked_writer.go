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

	"github.com/google/uuid"
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

// defaultRand is the production entropy source used by the chunked writer when
// no other io.Reader is injected.
var defaultRand io.Reader = rand.Reader

// segmentCipher encrypts a single payload segment. Implementations must be
// safe for concurrent use by segment writers.
//
// The output must be AEAD in the shape the TDF reader expects: a fresh nonce
// per call, and a ciphertext ending in a 16-byte authentication tag.
// WriteSegment concatenates nonce+ciphertext and hands the result to
// segmentIntegrity, which under SegmentGMAC reads the tag straight off the
// tail; a cipher that omits the tag or returns a repeated nonce produces a
// manifest that verifies against nothing.
type segmentCipher interface {
	// EncryptInPlace returns (ciphertext, nonce, error). Despite the name --
	// inherited from ocrypto.AesGcm -- nothing is encrypted in place: the
	// implementation must allocate its output and must neither retain nor
	// modify data, which WriteSegment passes through from its caller.
	EncryptInPlace(data []byte) ([]byte, []byte, error)
}

// segmentCipherFactory builds a segmentCipher from the writer-generated DEK.
// Tests inject deterministic ciphers for reproducible fixtures.
type segmentCipherFactory func(dek []byte) (segmentCipher, error)

// defaultSegmentCipherFactory wraps ocrypto.NewAESGcm (AES-256-GCM).
func defaultSegmentCipherFactory(dek []byte) (segmentCipher, error) {
	return ocrypto.NewAESGcm(dek)
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

	// ErrChunkedCloseFailed is returned when the archive's Close fails
	// after its Finalize already succeeded. The archive is terminally
	// finalized internally at that point regardless, so the writer is
	// unusable: every subsequent call returns this same error rather
	// than retrying against an archive that can only fail again.
	//
	// Unreachable with the default archive writer, whose Close cannot
	// fail; it is the injected-factory case this guards.
	ErrChunkedCloseFailed = errors.New("chunked: archive close failed after finalize; writer is unusable")

	// ErrChunkedFinalizeFailed is returned when the archive's Finalize
	// fails, and by every later call on that writer. Unlike a failure
	// before the archive was touched, this one is not retryable: the
	// archive mutates as it finalizes -- zipstream appends the payload
	// entry to the central directory partway through, then can still
	// fail on the manifest entry, on a ZIP64 requirement, or on
	// generating the directory bytes -- and it does not roll that back
	// or mark itself finalized. A second attempt would append the
	// payload entry again, yielding a central directory with two
	// entries for one payload: an archive some readers accept and
	// silently misread. Failing fast is the only safe answer.
	ErrChunkedFinalizeFailed = errors.New("chunked: archive finalize failed; writer is unusable")

	// ErrChunkedInvalidSegmentIndex is returned when WriteSegment
	// receives a negative index.
	ErrChunkedInvalidSegmentIndex = errors.New("chunked: invalid segment index")

	// ErrChunkedMissingSegmentZero is returned when Finalize is called
	// on a writer that never wrote segment 0. Only segment 0 emits the
	// payload's ZIP local file header, and every offset in the manifest
	// and central directory is measured from it.
	ErrChunkedMissingSegmentZero = errors.New("chunked: segment 0 was never written; it carries the payload's ZIP local file header")

	// ErrChunkedSegmentAlreadyWritten is returned when WriteSegment
	// receives an index that was already written.
	ErrChunkedSegmentAlreadyWritten = errors.New("chunked: segment already written")

	// ErrChunkedVersionHexMismatch is returned when Finalize is asked
	// to omit schemaVersion on a writer that was not constructed in
	// legacy signature mode. Use WithChunkedTargetMode to set both.
	ErrChunkedVersionHexMismatch = errors.New("chunked: excluding schemaVersion requires a pre-4.3.0 target mode; use WithChunkedTargetMode")
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
	// ErrChunkedMissingSegmentZero if segment 0 was never written, or
	// ErrChunkedMissingSegmentZero if segment 0 was never written.
	//
	// A failure from the archive itself -- ErrChunkedFinalizeFailed, or
	// ErrChunkedCloseFailed if only the Close after it failed -- leaves
	// the writer unusable, and every subsequent call on it returns that
	// same error rather than retrying.
	//
	// Finalize must happen-after every WriteSegment call returns.
	// Calling it while a write is still in flight is not an error and
	// does not block: the writer simply finalizes without that segment,
	// since a segment counts only once the archive has accepted its
	// bytes. Sequencing that is the caller's job -- wait on the
	// errgroup, close the channel, join the pool -- and getting it wrong
	// costs you the segment silently.
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
	// It reflects only segments the archive has already accepted;
	// writes still in flight are skipped, which is what lets it run
	// concurrently with them.
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

	// EncryptedSize is the total ciphertext byte length across
	// emitted segments.
	EncryptedSize int64

	// Manifest is the finalized manifest that was serialized into the
	// archive.
	Manifest *Manifest

	// TotalSegments is the number of segments in the finalized
	// manifest (post-trim if WithChunkedSegments was used).
	TotalSegments int

	// TotalSize is the total plaintext byte length across emitted
	// segments.
	TotalSize int64
}

// chunkedWriterConfig captures the settings supplied at
// NewChunkedWriter time. Fields are unexported; use options.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type chunkedWriterConfig struct {
	// archiveFactory builds the ZIP archive writer that lays out the
	// TDF. Defaults to defaultArchiveWriterFactory.
	archiveFactory archiveWriterFactory

	// cipherFactory builds the segment cipher from the DEK. Defaults
	// to defaultSegmentCipherFactory (AES-256-GCM).
	cipherFactory segmentCipherFactory

	// clock supplies the current time to the writer and the
	// underlying zipstream. Defaults to systemClock. Tests inject
	// fixedClock for deterministic ZIP output.
	clock clock

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

	// rand is the entropy source used to generate the DEK. Defaults
	// to crypto/rand.Reader.
	rand io.Reader

	// splitter maps attribute values to DEK splits at Finalize time.
	// Defaults to DefaultKeySplitter (single-KAS only).
	splitter KeySplitter

	// useHex hex-encodes segment, root, and assertion signatures
	// before base64, producing the doubly-encoded form that readers
	// older than 4.3.0 require. Set by WithChunkedTargetMode.
	useHex bool
}

// chunkedFinalizeConfig captures Finalize-time overrides.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type chunkedFinalizeConfig struct {
	// assertions to sign and attach to the produced TDF. Each
	// AssertionConfig must carry a SigningKey (or the writer's DEK
	// will be used with HS256).
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
	// Defaults to "application/octet-stream".
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

	// block is the segment cipher built from the DEK.
	block segmentCipher

	// dek is the Data Encryption Key. 32 bytes (AES-256).
	dek []byte

	// excludeVersion omits schemaVersion from the manifest unless a
	// Finalize option overrides it.
	excludeVersion bool

	// unusable is non-nil once a Finalize attempt has left the archive
	// in a state no later call can recover from: either the archive's
	// Finalize failed partway through its own mutations, or its Close
	// failed after Finalize had succeeded. In both cases w.finalized
	// stays false -- nothing usable was produced -- yet the archive
	// cannot be finalized again, so every method returns this error
	// instead of retrying. It holds the wrapped original, so callers
	// see both the sentinel and the underlying cause.
	unusable error

	// finalized is true once Finalize returns successfully.
	finalized bool

	// initialAttributes captured at construction; used by Finalize
	// when the caller does not override.
	initialAttributes []*policy.Value

	// initialDefaultKAS captured at construction; used by Finalize
	// when the caller does not override.
	initialDefaultKAS *policy.SimpleKasKey

	// manifest holds the finalized manifest for post-Finalize
	// GetManifest calls.
	manifest *Manifest

	// mu guards writer state that spans WriteSegment and Finalize.
	mu sync.RWMutex

	// segments records per-index slots, reserved and then written.
	segments map[int]*segmentSlot

	// splitter converts attributes + DEK into key splits at
	// Finalize time.
	splitter KeySplitter

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
// The one ordering constraint the writer cannot enforce is that
// Finalize must happen-after every WriteSegment returns. Finalize does
// not wait for in-flight writes and does not report them: it takes the
// segments the archive has accepted by the time it acquires the lock,
// and a write still running is simply absent from the result. The
// produced TDF is well-formed, just short — so join your goroutines
// before finalizing.
//
// No SDK value is needed: everything the writer depends on — the key
// splitter, the archive and cipher factories, the entropy source — is
// supplied through options.
//
// Experimental: not part of the stable SDK API; may change or be removed.
func NewChunkedWriter(_ context.Context, opts ...ChunkedWriterOption) (ChunkedWriter, error) {
	cfg := chunkedWriterConfig{
		archiveFactory: defaultArchiveWriterFactory,
		cipherFactory:  defaultSegmentCipherFactory,
		clock:          systemClock{},
		rand:           defaultRand,
		splitter:       DefaultKeySplitter(),
	}
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	dek := make([]byte, kKeySize)
	if _, err := io.ReadFull(cfg.rand, dek); err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}
	block, err := cfg.cipherFactory(dek)
	if err != nil {
		return nil, fmt.Errorf("build segment cipher: %w", err)
	}
	return &chunkedWriter{
		archiveWriter:     cfg.archiveFactory(cfg.clock),
		block:             block,
		dek:               dek,
		excludeVersion:    cfg.excludeVersion,
		initialAttributes: cfg.initialAttributes,
		initialDefaultKAS: cfg.initialDefaultKAS,
		segments:          make(map[int]*segmentSlot),
		splitter:          cfg.splitter,
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

	// Segment 0 is the only one that emits the payload's ZIP local file
	// header (see zipstream.segmentWriter.WriteSegment), and the archive
	// measures every offset it records from that header being at the
	// front of the assembled stream. It cannot be synthesized here: by
	// Finalize the caller has already encrypted and uploaded the bytes it
	// would have to precede. A slot stays unwritten until the archive
	// accepts the write, so a reservation in flight does not count.
	if slot, ok := w.segments[0]; !ok || !slot.written {
		return nil, ErrChunkedMissingSegmentZero
	}

	cfg, err := w.applyFinalizeOptions(opts)
	if err != nil {
		return nil, err
	}

	manifest, totalPlaintext, totalEncrypted, err := w.buildManifest(ctx, cfg)
	if err != nil {
		return nil, err
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	finalBytes, err := w.archiveWriter.Finalize(ctx, manifestBytes)
	if err != nil {
		// A failure here means the archive got partway through
		// finalizing and stopped, having already mutated itself without
		// marking itself done. Retrying would compound that rather than
		// recover from it -- see ErrChunkedFinalizeFailed -- so fence
		// the writer instead of leaving it looking retryable.
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
		EncryptedSize: totalEncrypted,
		// Cloned for the same reason GetManifest clones: w.manifest is
		// the writer's own record of what the archive bytes say, and
		// handing out that pointer would let a caller edit it and see
		// the edit come back from a later GetManifest, or race one.
		Manifest:      cloneChunkedManifest(manifest),
		TotalSegments: len(manifest.Segments),
		TotalSize:     totalPlaintext,
	}, nil
}

// GetManifest returns the manifest snapshot.
func (w *chunkedWriter) GetManifest(ctx context.Context, opts ...ChunkedFinalizeOption) (*Manifest, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.unusable != nil {
		return nil, w.unusable
	}
	if w.finalized && w.manifest != nil {
		return cloneChunkedManifest(w.manifest), nil
	}
	cfg, err := w.applyFinalizeOptions(opts)
	if err != nil {
		return nil, err
	}
	manifest, _, _, err := w.buildManifest(ctx, cfg)
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
	if index < 0 {
		w.mu.Unlock()
		return nil, ErrChunkedInvalidSegmentIndex
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
	release := func() {
		w.mu.Lock()
		if cur, ok := w.segments[index]; ok && cur == slot && !cur.written {
			delete(w.segments, index)
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
		if archiveWriteAttempted {
			// The archive may have partially recorded the write before
			// failing; CleanupSegment undoes that so a retry starts
			// from a state indistinguishable from never having been
			// attempted (see zipstream.SegmentWriter's contract). The
			// concrete writer's CleanupSegment cannot itself fail; a
			// custom archiveWriterFactory's failure here is best-effort
			// and does not change what this call returns.
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
			_ = w.archiveWriter.CleanupSegment(index)
		}
		release()
	}()

	ciphertext, nonce, err := w.block.EncryptInPlace(data)
	if err != nil {
		return nil, fmt.Errorf("encrypt segment %d: %w", index, err)
	}
	sealed := make([]byte, 0, len(nonce)+len(ciphertext))
	sealed = append(sealed, nonce...)
	sealed = append(sealed, ciphertext...)
	// GMAC reads the tag back out of sealed, which is the AEAD output
	// the cipher just produced -- segmentIntegrity's precondition.
	sig, err := segmentIntegrity(sealed, w.dek, SegmentGMAC, w.useHex)
	if err != nil {
		return nil, fmt.Errorf("segment %d signature: %w", index, err)
	}
	hash := string(ocrypto.Base64Encode([]byte(sig)))
	encryptedSize := int64(len(sealed))

	crc := crc32.NewIEEE()
	if _, err := crc.Write(nonce); err != nil {
		return nil, err
	}
	if _, err := crc.Write(ciphertext); err != nil {
		return nil, err
	}
	archiveWriteAttempted = true
	header, err := w.archiveWriter.WriteSegment(ctx, index, uint64(encryptedSize), crc.Sum32())
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
	w.mu.Unlock()
	committed = true

	var reader io.Reader
	if len(header) == 0 {
		reader = io.MultiReader(bytes.NewReader(nonce), bytes.NewReader(ciphertext))
	} else {
		reader = io.MultiReader(bytes.NewReader(header), bytes.NewReader(nonce), bytes.NewReader(ciphertext))
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

// applyFinalizeOptions builds a chunkedFinalizeConfig with defaults
// then applies each option in order.
func (w *chunkedWriter) applyFinalizeOptions(opts []ChunkedFinalizeOption) (*chunkedFinalizeConfig, error) {
	cfg := &chunkedFinalizeConfig{
		attributes:        nil,
		encryptedMetadata: "",
		excludeVersion:    w.excludeVersion,
		mimeType:          "application/octet-stream",
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	// Omitting schemaVersion is how a reader is told the TDF predates
	// 4.3.0, and such a reader expects hex-then-base64 signatures. The
	// segment signatures were already written by then, so the two
	// settings cannot be reconciled here -- refuse rather than emit a
	// TDF that no reader can verify.
	if cfg.excludeVersion && !w.useHex {
		return nil, ErrChunkedVersionHexMismatch
	}
	if len(cfg.attributes) == 0 && len(w.initialAttributes) > 0 {
		cfg.attributes = w.initialAttributes
	}
	if cfg.defaultKAS == nil && w.initialDefaultKAS != nil {
		cfg.defaultKAS = w.initialDefaultKAS
	}
	return cfg, nil
}

// buildManifest composes the manifest from writer state, splits the
// DEK, wraps splits into KAOs, and computes the root signature.
func (w *chunkedWriter) buildManifest(ctx context.Context, cfg *chunkedFinalizeConfig) (*Manifest, int64, int64, error) {
	order, err := w.segmentOrderLocked(cfg.keepSegments)
	if err != nil {
		return nil, 0, 0, err
	}

	splits, err := w.splitter.Split(ctx, cfg.attributes, w.dek, cfg.defaultKAS)
	if err != nil {
		return nil, 0, 0, err
	}
	policyBytes, err := buildChunkedPolicy(cfg.attributes)
	if err != nil {
		return nil, 0, 0, err
	}
	kaos, err := buildChunkedKeyAccessObjects(splits, policyBytes, cfg.encryptedMetadata)
	if err != nil {
		return nil, 0, 0, err
	}

	encInfo := EncryptionInformation{
		KeyAccessObjs: kaos,
		KeyAccessType: kSplitKeyType,
		Policy:        string(ocrypto.Base64Encode(policyBytes)),
		Method: Method{
			Algorithm:    kGCMCipherAlgorithm,
			IsStreamable: true,
		},
		IntegrityInformation: IntegrityInformation{
			SegmentHashAlgorithm: SegmentGMAC.String(),
			Segments:             make([]Segment, len(order)),
		},
	}

	var aggregate bytes.Buffer
	var totalPlaintext, totalEncrypted int64
	for i, idx := range order {
		// segmentOrderLocked only ever names written slots, whether it
		// derived the order itself or validated a caller-supplied one.
		slot, ok := w.segments[idx]
		if !ok || !slot.written {
			return nil, 0, 0, fmt.Errorf("segment %d not written; cannot finalize", idx)
		}
		if slot.seg.Hash == "" {
			return nil, 0, 0, fmt.Errorf("segment %d has empty hash", idx)
		}
		encInfo.Segments[i] = slot.seg
		totalPlaintext += slot.seg.Size
		totalEncrypted += slot.seg.EncryptedSize
		decoded, err := ocrypto.Base64Decode([]byte(slot.seg.Hash))
		if err != nil {
			return nil, 0, 0, fmt.Errorf("decode segment %d hash: %w", idx, err)
		}
		aggregate.Write(decoded)
	}
	if len(order) > 0 {
		if first, ok := w.segments[order[0]]; ok {
			encInfo.DefaultEncryptedSegSize = first.seg.EncryptedSize
			encInfo.DefaultSegmentSize = first.seg.Size
		}
	}

	rootSig, err := rootIntegrity(aggregate.Bytes(), w.dek, RootHS256, w.useHex)
	if err != nil {
		return nil, 0, 0, err
	}
	encInfo.RootSignature = RootSignature{
		Algorithm: RootHS256.String(),
		Signature: string(ocrypto.Base64Encode([]byte(rootSig))),
	}

	// Assertions bind to the same aggregate hash the root signature
	// covers, so they can only be signed once every segment is in.
	assertions, err := signAssertions(aggregate.Bytes(), cfg.assertions, w.dek, w.useHex)
	if err != nil {
		return nil, 0, 0, err
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
	return manifest, totalPlaintext, totalEncrypted, nil
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

// buildChunkedKeyAccessObjects wraps each split share to each KAS
// listed by the splitter.
func buildChunkedKeyAccessObjects(splits *SplitResult, policyBytes []byte, metadata string) ([]KeyAccess, error) {
	// This is the one place caller-supplied split data is turned into
	// manifest content, so it is where the splitter's contract is
	// enforced -- for the default splitter and for anything injected
	// through WithChunkedKeySplitter alike. Validate guarantees every
	// invariant the loop below relies on: at least one split, every
	// split naming at least one KAS, every named KAS resolving to a
	// usable wrapping key, and split ids that the reader can group on.
	if err := splits.Validate(); err != nil {
		return nil, err
	}
	base64Policy := ocrypto.Base64Encode(policyBytes)

	out := make([]KeyAccess, 0, len(splits.Splits))
	for _, split := range splits.Splits {
		// Policy binding and metadata are keyed on the split share, not
		// on the KAS, so compute them once per split rather than once
		// per KAS URL in an OR-group.
		policyBinding := createPolicyBinding(split.Data, base64Policy)
		var encMeta string
		if metadata != "" {
			m, err := encryptMetadata(split.Data, metadata)
			if err != nil {
				return nil, fmt.Errorf("encrypt metadata for split %s: %w", split.ID, err)
			}
			encMeta = m
		}
		for _, url := range split.KASURLs {
			// Validate resolved every URL, so the lookup cannot miss.
			pk := splits.KASPublicKeys[url]
			kao, err := createKeyAccess(pk.toKASInfo(), split.Data, policyBinding, encMeta, split.ID)
			if err != nil {
				return nil, fmt.Errorf("wrap key for %s: %w", url, err)
			}
			out = append(out, kao)
		}
	}
	return out, nil
}

// buildChunkedPolicy composes the TDF Policy document from attribute
// values.
func buildChunkedPolicy(values []*policy.Value) ([]byte, error) {
	p := PolicyObject{UUID: uuid.NewString()}
	p.Body.DataAttributes = make([]attributeObject, 0, len(values))
	p.Body.Dissem = make([]string, 0)
	for _, v := range values {
		p.Body.DataAttributes = append(p.Body.DataAttributes, attributeObject{
			Attribute: v.GetFqn(),
		})
	}
	return json.Marshal(p)
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
