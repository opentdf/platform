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
	"sort"
	"sync"
	"time"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/internal/zipstream"
)

// The injection seams below — the clock, the segment cipher, the archive
// writer and the entropy source — are unexported on purpose. Each exists so
// in-package tests can pin non-deterministic behavior; none is usable from
// outside. archiveWriterFactory in particular returns a
// zipstream.SegmentWriter, which lives under internal/, so no external package
// could implement it even if the type were exported.

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
type segmentCipher interface {
	// EncryptInPlace returns (ciphertext, nonce, error).
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

// defaultArchiveWriterFactory returns a ZIP64-enabled segment writer sized for
// a single starting segment (it grows as more segments arrive), with its clock
// plumbed to the caller-supplied clock.
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
	// remain otherwise. Returns the closing bytes (central directory
	// + end-of-central-directory record) that must be appended after
	// every segment's TDFData. Returns ErrChunkedMissingSegmentZero if
	// segment 0 was never written.
	Finalize(ctx context.Context, opts ...ChunkedFinalizeOption) (*ChunkedFinalizeResult, error)

	// GetManifest returns the manifest for the TDF. Before Finalize
	// this is a snapshot built from currently-written segments; after
	// Finalize it is the manifest that was written.
	GetManifest(ctx context.Context, opts ...ChunkedFinalizeOption) (*Manifest, error)

	// WriteSegment encrypts data as segment index and returns the
	// ZIP bytes for that segment (local header + nonce + ciphertext).
	// Callers upload or buffer those bytes; Finalize does not
	// re-emit them. Indices need not arrive in order and need not be
	// contiguous, but index 0 is mandatory: it carries the payload's
	// ZIP local file header, so Finalize refuses a write set without
	// it.
	WriteSegment(ctx context.Context, index int, data []byte) (*ChunkedSegmentResult, error)
}

// ChunkedSegmentResult carries the ZIP bytes for one segment plus its
// integrity metadata.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type ChunkedSegmentResult struct {
	// EncryptedSize is the ciphertext byte length including nonce and
	// GCM tag.
	EncryptedSize int64

	// Hash is the base64-encoded segment integrity hash.
	Hash string

	// Index is the zero-based segment index.
	Index int

	// PlaintextSize is the byte length of the pre-encryption input.
	PlaintextSize int64

	// TDFData is a reader over the segment's ZIP-embedded ciphertext
	// (local header + nonce + AES-GCM output). Callers assemble the
	// TDF by concatenating each segment's TDFData in emission order
	// followed by ChunkedFinalizeResult.Data.
	TDFData io.Reader
}

// ChunkedFinalizeResult carries the finalized TDF's closing bytes and
// metadata about what was written.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type ChunkedFinalizeResult struct {
	// Data is the ZIP closing bytes (central directory + EOCD + data
	// descriptor). Append after every segment's TDFData to form the
	// complete TDF file.
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

// ChunkedWriterConfig captures the settings supplied at
// NewChunkedWriter time. Fields are unexported; use options.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type ChunkedWriterConfig struct {
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

	// integrityAlgorithm is the algorithm used for the root
	// signature. Defaults to HS256.
	integrityAlgorithm IntegrityAlgorithm

	// keyAccess resolves the manifest policy and key access objects.
	// Defaults to a splitterKeyAccess over splitter.
	keyAccess keyAccessResolver

	// rand is the entropy source used to generate the DEK. Defaults
	// to crypto/rand.Reader.
	rand io.Reader

	// segmentIntegrityAlgorithm is the algorithm used for per-segment
	// integrity hashes. Defaults to HS256.
	segmentIntegrityAlgorithm IntegrityAlgorithm

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

// ChunkedFinalizeConfig captures Finalize-time overrides.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type ChunkedFinalizeConfig struct {
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
	// describes, strictly ascending but not necessarily contiguous.
	// Empty means every written segment, ascending.
	keepSegments []int

	// mimeType records the payload MIME type in the manifest.
	// Defaults to "application/octet-stream".
	mimeType string
}

// ChunkedWriterOption configures a ChunkedWriter at construction
// time.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type ChunkedWriterOption func(*ChunkedWriterConfig) error

// ChunkedFinalizeOption configures a single Finalize call.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type ChunkedFinalizeOption func(*ChunkedFinalizeConfig) error

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

	// finalized is true once Finalize returns successfully.
	finalized bool

	// initialAttributes captured at construction; used by Finalize
	// when the caller does not override.
	initialAttributes []*policy.Value

	// initialDefaultKAS captured at construction; used by Finalize
	// when the caller does not override.
	initialDefaultKAS *policy.SimpleKasKey

	// integrityAlgorithm is used for the root signature.
	integrityAlgorithm IntegrityAlgorithm

	// keyAccess resolves the manifest policy and key access objects
	// for the DEK.
	keyAccess keyAccessResolver

	// manifest holds the finalized manifest for post-Finalize
	// GetManifest calls.
	manifest *Manifest

	// maxSegmentIndex tracks the highest index written so far.
	maxSegmentIndex int

	// mu guards writer state that spans WriteSegment and Finalize.
	mu sync.RWMutex

	// segmentIntegrityAlgorithm is used for per-segment hashes.
	segmentIntegrityAlgorithm IntegrityAlgorithm

	// segments records per-index Segment metadata (hash + sizes).
	segments map[int]*Segment

	// segmentSize is the plaintext segment size to advertise in the
	// manifest, or zero to infer it from the first segment.
	segmentSize int64

	// useHex selects the pre-4.3.0 doubly-encoded signature form.
	// Read by WriteSegment, so it is fixed at construction rather
	// than at Finalize.
	useHex bool
}

// NewChunkedWriter constructs a per-segment TDF writer. The returned
// ChunkedWriter is not safe for concurrent WriteSegment calls on the
// same index but tolerates concurrent writes to distinct indices.
//
// No SDK value is needed: everything the writer depends on — the key
// splitter, the archive and cipher factories, the entropy source — is
// supplied through options.
//
// Experimental: not part of the stable SDK API; may change or be removed.
func NewChunkedWriter(_ context.Context, opts ...ChunkedWriterOption) (ChunkedWriter, error) {
	cfg := ChunkedWriterConfig{
		archiveFactory:            defaultArchiveWriterFactory,
		cipherFactory:             defaultSegmentCipherFactory,
		clock:                     systemClock{},
		integrityAlgorithm:        HS256,
		rand:                      defaultRand,
		segmentIntegrityAlgorithm: HS256,
		splitter:                  DefaultKeySplitter(),
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
func newChunkedWriter(cfg ChunkedWriterConfig) (*chunkedWriter, error) {
	dek := cfg.dek
	if dek == nil {
		dek = make([]byte, kKeySize)
		if _, err := io.ReadFull(cfg.rand, dek); err != nil {
			return nil, fmt.Errorf("generate DEK: %w", err)
		}
	}
	block, err := cfg.cipherFactory(dek)
	if err != nil {
		return nil, fmt.Errorf("build segment cipher: %w", err)
	}
	keyAccess := cfg.keyAccess
	if keyAccess == nil {
		keyAccess = splitterKeyAccess{splitter: cfg.splitter}
	}
	return &chunkedWriter{
		archiveWriter:             cfg.archiveFactory(cfg.clock),
		block:                     block,
		dek:                       dek,
		excludeVersion:            cfg.excludeVersion,
		initialAttributes:         cfg.initialAttributes,
		initialDefaultKAS:         cfg.initialDefaultKAS,
		integrityAlgorithm:        cfg.integrityAlgorithm,
		keyAccess:                 keyAccess,
		segmentIntegrityAlgorithm: cfg.segmentIntegrityAlgorithm,
		segments:                  make(map[int]*Segment),
		segmentSize:               cfg.segmentSize,
		useHex:                    cfg.useHex,
	}, nil
}

// Finalize serializes the manifest, closes the archive, and returns
// the trailing bytes.
func (w *chunkedWriter) Finalize(ctx context.Context, opts ...ChunkedFinalizeOption) (*ChunkedFinalizeResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finalized {
		return nil, ErrChunkedAlreadyFinalized
	}

	// Segment 0 is the only one that emits the payload's ZIP local file
	// header (see zipstream.segmentWriter.WriteSegment), and the archive
	// measures every offset it records from that header being at the
	// front of the assembled stream. It cannot be synthesized here: by
	// Finalize the caller has already encrypted and uploaded the bytes it
	// would have to precede. Size stays negative until the archive
	// accepts the write, so a reservation in flight does not count.
	if seg, ok := w.segments[0]; !ok || seg.Size < 0 {
		return nil, ErrChunkedMissingSegmentZero
	}

	cfg, err := w.applyFinalizeOptions(opts)
	if err != nil {
		return nil, err
	}

	// Finalize keeps the write lock across the split. It is terminal --
	// no further WriteSegment may succeed after it returns -- so there is
	// no concurrency to preserve, and releasing the lock to split would
	// open a window where a segment lands in the archive after the
	// snapshot that determines the manifest.
	snap, err := w.snapshotLocked(cfg.keepSegments)
	if err != nil {
		return nil, err
	}

	manifest, totalPlaintext, totalEncrypted, err := w.buildManifest(ctx, cfg, snap)
	if err != nil {
		return nil, err
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	finalBytes, err := w.archiveWriter.Finalize(ctx, manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("finalize archive: %w", err)
	}
	if err := w.archiveWriter.Close(); err != nil {
		return nil, fmt.Errorf("close archive: %w", err)
	}

	w.finalized = true
	w.manifest = manifest
	return &ChunkedFinalizeResult{
		Data:          finalBytes,
		EncryptedSize: totalEncrypted,
		Manifest:      manifest,
		TotalSegments: len(manifest.Segments),
		TotalSize:     totalPlaintext,
	}, nil
}

// GetManifest returns the manifest snapshot.
//
// The lock is held only long enough to copy segment metadata; the key
// split -- which may make network calls to resolve KAS keys -- runs
// unlocked. Holding RLock across it would block every WriteSegment
// waiting on the write lock for the duration of those calls, and
// RWMutex bars new readers once a writer is queued, so concurrent
// GetManifest calls would serialize behind it too.
func (w *chunkedWriter) GetManifest(ctx context.Context, opts ...ChunkedFinalizeOption) (*Manifest, error) {
	w.mu.RLock()
	if w.finalized && w.manifest != nil {
		manifest := cloneChunkedManifest(w.manifest)
		w.mu.RUnlock()
		return manifest, nil
	}
	cfg, err := w.applyFinalizeOptions(opts)
	if err != nil {
		w.mu.RUnlock()
		return nil, err
	}
	snap, err := w.snapshotLocked(cfg.keepSegments)
	w.mu.RUnlock()
	if err != nil {
		return nil, err
	}

	manifest, _, _, err := w.buildManifest(ctx, cfg, snap)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

// WriteSegment encrypts data as segment index and returns the ZIP
// bytes for that segment.
func (w *chunkedWriter) WriteSegment(ctx context.Context, index int, data []byte) (*ChunkedSegmentResult, error) {
	w.mu.Lock()
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
	if index > w.maxSegmentIndex {
		w.maxSegmentIndex = index
	}
	// Reserve the index so a concurrent write to the same one is
	// rejected, but leave Size negative: the segment does not count as
	// written until its bytes are in the archive.
	seg := &Segment{Size: -1}
	w.segments[index] = seg
	w.mu.Unlock()

	// release drops the reservation so the caller can retry this index
	// after a failure. It matches on identity and on the placeholder
	// still being unwritten, so it can never discard a segment some
	// other call has since completed.
	release := func() {
		w.mu.Lock()
		if cur, ok := w.segments[index]; ok && cur == seg && cur.Size < 0 {
			delete(w.segments, index)
		}
		w.mu.Unlock()
	}

	ciphertext, nonce, err := w.block.EncryptInPlace(data)
	if err != nil {
		release()
		return nil, fmt.Errorf("encrypt segment %d: %w", index, err)
	}
	sealed := make([]byte, 0, len(nonce)+len(ciphertext))
	sealed = append(sealed, nonce...)
	sealed = append(sealed, ciphertext...)
	sig, err := calculateSignature(sealed, w.dek, w.segmentIntegrityAlgorithm, w.useHex)
	if err != nil {
		release()
		return nil, fmt.Errorf("segment %d signature: %w", index, err)
	}
	hash := string(ocrypto.Base64Encode([]byte(sig)))
	encryptedSize := int64(len(sealed))

	crc := crc32.NewIEEE()
	if _, err := crc.Write(nonce); err != nil {
		release()
		return nil, err
	}
	if _, err := crc.Write(ciphertext); err != nil {
		release()
		return nil, err
	}
	header, err := w.archiveWriter.WriteSegment(ctx, index, uint64(encryptedSize), crc.Sum32())
	if err != nil {
		release()
		return nil, fmt.Errorf("write segment %d to archive: %w", index, err)
	}

	// Commit only once the archive has accepted the segment. Publishing
	// the metadata earlier would let Finalize emit a manifest that
	// describes bytes the archive never received.
	w.mu.Lock()
	seg.EncryptedSize = encryptedSize
	seg.Hash = hash
	seg.Size = int64(len(data))
	w.mu.Unlock()

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

// applyFinalizeOptions builds a ChunkedFinalizeConfig with defaults
// then applies each option in order.
func (w *chunkedWriter) applyFinalizeOptions(opts []ChunkedFinalizeOption) (*ChunkedFinalizeConfig, error) {
	cfg := &ChunkedFinalizeConfig{
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
// chunkedSnapshot is the mutable writer state buildManifest needs,
// copied out from under the lock. Segment values rather than the
// pointers held in w.segments: WriteSegment mutates those in place when
// the archive accepts a write, so reading them after the lock is
// released would race.
type chunkedSnapshot struct {
	// segments are the per-segment metadata records in emission order.
	segments []Segment
}

// snapshotLocked resolves the emission order and copies each segment's
// metadata out of w.segments. The caller must hold w.mu for reading.
func (w *chunkedWriter) snapshotLocked(keep []int) (*chunkedSnapshot, error) {
	order, err := w.segmentOrderLocked(keep)
	if err != nil {
		return nil, err
	}
	segments := make([]Segment, len(order))
	for i, idx := range order {
		seg, ok := w.segments[idx]
		if !ok || seg.Size < 0 {
			return nil, fmt.Errorf("segment %d not written; cannot finalize", idx)
		}
		if seg.Hash == "" {
			return nil, fmt.Errorf("segment %d has empty hash", idx)
		}
		segments[i] = *seg
	}
	return &chunkedSnapshot{segments: segments}, nil
}

// buildManifest assembles the manifest from a snapshot. It reads no
// mutable writer state and holds no lock: every other field it touches
// (dek, keyAccess, the integrity algorithms, useHex) is fixed at
// construction.
func (w *chunkedWriter) buildManifest(ctx context.Context, cfg *ChunkedFinalizeConfig, snap *chunkedSnapshot) (*Manifest, int64, int64, error) {
	base64Policy, kaos, err := w.keyAccess.resolve(ctx, w.dek, cfg)
	if err != nil {
		return nil, 0, 0, err
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
			SegmentHashAlgorithm: integrityAlgorithmString(w.segmentIntegrityAlgorithm),
			Segments:             make([]Segment, len(snap.segments)),
		},
	}

	var aggregate bytes.Buffer
	var totalPlaintext, totalEncrypted int64
	for i, seg := range snap.segments {
		encInfo.Segments[i] = seg
		totalPlaintext += seg.Size
		totalEncrypted += seg.EncryptedSize
		decoded, err := ocrypto.Base64Decode([]byte(seg.Hash))
		if err != nil {
			return nil, 0, 0, fmt.Errorf("decode segment %d hash: %w", i, err)
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

	rootSig, err := calculateSignature(aggregate.Bytes(), w.dek, w.integrityAlgorithm, w.useHex)
	if err != nil {
		return nil, 0, 0, err
	}
	encInfo.RootSignature = RootSignature{
		Algorithm: integrityAlgorithmString(w.integrityAlgorithm),
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
// order. A supplied subset must be a prefix of that same ascending
// sequence. Note this constrains position, not value: the written
// indices themselves may be sparse (a caller reserving a block of
// indices per upload part and filling only part of each block writes
// e.g. 0,1,5000,5001), and any such set is accepted so long as the
// subset names its members in order and drops only from the end.
// Whether index 0 is among them is Finalize's business, not this
// function's: GetManifest shares this path and legitimately runs
// before segment 0 has been written.
//
// Both halves of that rule are forced by the archive layout, which
// stores segments sorted by index. Reordering would make the manifest
// disagree with the bytes on disk; dropping a segment that has bytes
// after it would shift every later segment's offset.
func (w *chunkedWriter) segmentOrderLocked(keep []int) ([]int, error) {
	written := make([]int, 0, len(w.segments))
	for idx := range w.segments {
		written = append(written, idx)
	}
	sort.Ints(written)
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
		if _, ok := w.segments[idx]; !ok {
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

// cloneChunkedManifest returns a shallow-deep copy safe to hand out.
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
