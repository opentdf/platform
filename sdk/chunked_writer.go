package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"slices"
	"sort"
	"sync"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/internal/zipstream"
)

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
type ChunkedWriterConfig struct {
	// archiveFactory builds the ZIP archive writer that lays out the
	// TDF. Defaults to DefaultArchiveWriterFactory.
	archiveFactory ArchiveWriterFactory

	// cipherFactory builds the segment cipher from the DEK. Defaults
	// to DefaultSegmentCipherFactory (AES-256-GCM).
	cipherFactory SegmentCipherFactory

	// clock supplies the current time to the writer and the
	// underlying zipstream. Defaults to SystemClock. Tests inject
	// FixedClock for deterministic ZIP output.
	clock Clock

	// dek is a pre-generated Data Encryption Key. When nil the writer
	// draws one from rand. SDK.CreateTDF presets it so that it can
	// resolve key access before emitting any payload bytes.
	dek []byte

	// excludeVersion omits the schemaVersion field from the manifest.
	// Set together with useHex by WithChunkedTargetMode; readers use
	// the field's absence as the pre-4.3.0 marker, so the two must
	// agree.
	excludeVersion bool

	// keyAccess resolves the manifest policy and key access objects.
	// Defaults to a splitterKeyAccess over splitter.
	keyAccess keyAccessResolver

	// initialAttributes are the attribute values used at Finalize
	// when the Finalize call does not supply its own.
	initialAttributes []*policy.Value

	// initialDefaultKAS is the default KAS used at Finalize when the
	// Finalize call does not supply its own.
	initialDefaultKAS *policy.SimpleKasKey

	// integrityAlgorithm is the algorithm used for the root
	// signature. Defaults to HS256.
	integrityAlgorithm IntegrityAlgorithm

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
type ChunkedWriterOption func(*ChunkedWriterConfig) error

// ChunkedFinalizeOption configures a single Finalize call.
type ChunkedFinalizeOption func(*ChunkedFinalizeConfig) error

// chunkedWriter is the concrete ChunkedWriter.
type chunkedWriter struct {
	// archiveWriter handles the underlying ZIP archive creation.
	archiveWriter zipstream.SegmentWriter

	// block is the segment cipher built from the DEK.
	block SegmentCipher

	// clock is the time source captured at construction; passed to
	// the archive factory and referenced anywhere the writer stamps
	// a timestamp.
	clock Clock

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

	// useHex emits hex-encoded integrity signatures for pre-4.3.0
	// TDF spec versions.
	useHex bool
}

// NewChunkedWriter constructs a per-segment TDF writer. The returned
// ChunkedWriter is not safe for concurrent WriteSegment calls on the
// same index but tolerates concurrent writes to distinct indices.
//
// This method is equivalent to the package-level [NewChunkedWriter];
// the writer holds no reference to the SDK.
func (s SDK) NewChunkedWriter(ctx context.Context, opts ...ChunkedWriterOption) (ChunkedWriter, error) {
	return NewChunkedWriter(ctx, opts...)
}

// NewChunkedWriter constructs a per-segment TDF writer. The returned
// ChunkedWriter is not safe for concurrent WriteSegment calls on the
// same index but tolerates concurrent writes to distinct indices.
//
// No SDK value is needed: everything the writer depends on — the key
// splitter, the archive and cipher factories, the entropy source — is
// supplied through options.
func NewChunkedWriter(_ context.Context, opts ...ChunkedWriterOption) (ChunkedWriter, error) {
	cfg := ChunkedWriterConfig{
		archiveFactory:            DefaultArchiveWriterFactory,
		cipherFactory:             DefaultSegmentCipherFactory,
		clock:                     SystemClock{},
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
// legacy behavior needs (preset DEK, hex signatures, fixed segment
// size) rather than going through the public option set.
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
		clock:                     cfg.clock,
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
func (w *chunkedWriter) GetManifest(ctx context.Context, opts ...ChunkedFinalizeOption) (*Manifest, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
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
	sealed := joinSealed(nonce, ciphertext)
	sig, err := calculateSignature(sealed, w.dek, w.segmentIntegrityAlgorithm, w.useHex)
	if err != nil {
		release()
		return nil, fmt.Errorf("segment %d signature: %w", index, err)
	}
	hash := string(ocrypto.Base64Encode([]byte(sig)))
	encryptedSize := int64(len(sealed))

	header, err := w.archiveWriter.WriteSegment(ctx, index, uint64(encryptedSize), crc32.ChecksumIEEE(sealed))
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

	var reader io.Reader = bytes.NewReader(sealed)
	if len(header) > 0 {
		reader = io.MultiReader(bytes.NewReader(header), reader)
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
		mimeType:          defaultMimeType,
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

// buildManifest composes the manifest from writer state, resolves the
// key access objects for the DEK, signs any assertions, and computes
// the root signature.
func (w *chunkedWriter) buildManifest(ctx context.Context, cfg *ChunkedFinalizeConfig) (*Manifest, int64, int64, error) {
	order, err := w.segmentOrderLocked(cfg.keepSegments)
	if err != nil {
		return nil, 0, 0, err
	}

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
			Segments:             make([]Segment, len(order)),
		},
	}

	var aggregate bytes.Buffer
	var totalPlaintext, totalEncrypted int64
	for i, idx := range order {
		seg, ok := w.segments[idx]
		if !ok || seg.Size < 0 {
			return nil, 0, 0, fmt.Errorf("segment %d not written; cannot finalize", idx)
		}
		if seg.Hash == "" {
			return nil, 0, 0, fmt.Errorf("segment %d has empty hash", idx)
		}
		encInfo.Segments[i] = *seg
		totalPlaintext += seg.Size
		totalEncrypted += seg.EncryptedSize
		decoded, err := ocrypto.Base64Decode([]byte(seg.Hash))
		if err != nil {
			return nil, 0, 0, fmt.Errorf("decode segment %d hash: %w", idx, err)
		}
		aggregate.Write(decoded)
	}
	switch {
	case w.segmentSize > 0:
		encInfo.DefaultSegmentSize = w.segmentSize
		encInfo.DefaultEncryptedSegSize = w.segmentSize + gcmIvSize + aesBlockSize
	case len(order) > 0:
		if first, ok := w.segments[order[0]]; ok {
			encInfo.DefaultEncryptedSegSize = first.EncryptedSize
			encInfo.DefaultSegmentSize = first.Size
		}
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

// integrityAlgorithmString maps an IntegrityAlgorithm to its manifest
// string form.
func integrityAlgorithmString(a IntegrityAlgorithm) string {
	switch a {
	case GMAC:
		return gmacIntegrityAlgorithm
	default:
		return hmacIntegrityAlgorithm
	}
}

// joinSealed returns nonce||ciphertext, the on-disk form of a segment.
// A SegmentCipher backed by crypto/cipher hands back two views of the
// single buffer Seal allocated, so the common case is free; anything
// else pays one copy.
func joinSealed(nonce, ciphertext []byte) []byte {
	if len(nonce) > 0 && len(ciphertext) > 0 &&
		cap(nonce) >= len(nonce)+len(ciphertext) &&
		&nonce[:cap(nonce)][len(nonce)] == &ciphertext[0] {
		return nonce[:len(nonce)+len(ciphertext)]
	}
	sealed := make([]byte, 0, len(nonce)+len(ciphertext))
	sealed = append(sealed, nonce...)
	return append(sealed, ciphertext...)
}
