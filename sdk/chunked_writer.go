package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"slices"
	"sort"
	"sync"

	"github.com/google/uuid"
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

	// ErrChunkedSegmentAlreadyWritten is returned when WriteSegment
	// receives an index that was already written.
	ErrChunkedSegmentAlreadyWritten = errors.New("chunked: segment already written")

	// ErrChunkedAssertionsUnsupported is returned when Finalize
	// receives assertions but signing them is not yet implemented.
	ErrChunkedAssertionsUnsupported = errors.New("chunked: assertions not supported by ChunkedWriter; use SDK.CreateTDF")
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
	// every segment's TDFData.
	Finalize(ctx context.Context, opts ...ChunkedFinalizeOption) (*ChunkedFinalizeResult, error)

	// GetManifest returns the manifest for the TDF. Before Finalize
	// this is a snapshot built from currently-written segments; after
	// Finalize it is the manifest that was written.
	GetManifest(ctx context.Context, opts ...ChunkedFinalizeOption) (*Manifest, error)

	// WriteSegment encrypts data as segment index and returns the
	// ZIP bytes for that segment (local header + nonce + ciphertext).
	// Callers upload or buffer those bytes; Finalize does not
	// re-emit them. Indices need not arrive in order and need not be
	// contiguous.
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

	// clock supplies the current time for manifest metadata.
	// Defaults to SystemClock.
	clock Clock

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

	// splitter maps attribute values to DEK splits at Finalize time.
	// Defaults to DefaultKeySplitter (single-KAS only).
	splitter KeySplitter
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
	// for compatibility with older readers.
	excludeVersion bool

	// keepSegments restricts the finalized manifest to a contiguous
	// prefix [0..K] of the written segments.
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

	// clock is the time source for manifest metadata.
	clock Clock

	// dek is the Data Encryption Key. 32 bytes (AES-256).
	dek []byte

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

	// splitter converts attributes + DEK into key splits at
	// Finalize time.
	splitter KeySplitter
}

// NewChunkedWriter constructs a per-segment TDF writer. The returned
// ChunkedWriter is not safe for concurrent WriteSegment calls on the
// same index but tolerates concurrent writes to distinct indices.
func (s SDK) NewChunkedWriter(_ context.Context, opts ...ChunkedWriterOption) (ChunkedWriter, error) {
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

	dek := make([]byte, kKeySize)
	if _, err := io.ReadFull(cfg.rand, dek); err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}
	block, err := cfg.cipherFactory(dek)
	if err != nil {
		return nil, fmt.Errorf("build segment cipher: %w", err)
	}
	return &chunkedWriter{
		archiveWriter:             cfg.archiveFactory(),
		block:                     block,
		clock:                     cfg.clock,
		dek:                       dek,
		initialAttributes:         cfg.initialAttributes,
		initialDefaultKAS:         cfg.initialDefaultKAS,
		integrityAlgorithm:        cfg.integrityAlgorithm,
		segmentIntegrityAlgorithm: cfg.segmentIntegrityAlgorithm,
		segments:                  make(map[int]*Segment),
		splitter:                  cfg.splitter,
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

	cfg, err := w.applyFinalizeOptions(opts)
	if err != nil {
		return nil, err
	}
	if len(cfg.assertions) > 0 {
		return nil, ErrChunkedAssertionsUnsupported
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
	seg := &Segment{Size: -1}
	w.segments[index] = seg
	w.mu.Unlock()

	ciphertext, nonce, err := w.block.EncryptInPlace(data)
	if err != nil {
		return nil, fmt.Errorf("encrypt segment %d: %w", index, err)
	}
	sealed := make([]byte, 0, len(nonce)+len(ciphertext))
	sealed = append(sealed, nonce...)
	sealed = append(sealed, ciphertext...)
	sig, err := calculateSignature(sealed, w.dek, w.segmentIntegrityAlgorithm, false)
	if err != nil {
		return nil, fmt.Errorf("segment %d signature: %w", index, err)
	}
	hash := string(ocrypto.Base64Encode([]byte(sig)))

	w.mu.Lock()
	seg.EncryptedSize = int64(len(sealed))
	seg.Hash = hash
	seg.Size = int64(len(data))
	w.mu.Unlock()

	crc := crc32.NewIEEE()
	if _, err := crc.Write(nonce); err != nil {
		return nil, err
	}
	if _, err := crc.Write(ciphertext); err != nil {
		return nil, err
	}
	header, err := w.archiveWriter.WriteSegment(ctx, index, uint64(seg.EncryptedSize), crc.Sum32())
	if err != nil {
		return nil, fmt.Errorf("write segment %d to archive: %w", index, err)
	}
	var reader io.Reader
	if len(header) == 0 {
		reader = io.MultiReader(bytes.NewReader(nonce), bytes.NewReader(ciphertext))
	} else {
		reader = io.MultiReader(bytes.NewReader(header), bytes.NewReader(nonce), bytes.NewReader(ciphertext))
	}
	return &ChunkedSegmentResult{
		EncryptedSize: seg.EncryptedSize,
		Hash:          hash,
		Index:         index,
		PlaintextSize: seg.Size,
		TDFData:       reader,
	}, nil
}

// applyFinalizeOptions builds a ChunkedFinalizeConfig with defaults
// then applies each option in order.
func (w *chunkedWriter) applyFinalizeOptions(opts []ChunkedFinalizeOption) (*ChunkedFinalizeConfig, error) {
	cfg := &ChunkedFinalizeConfig{
		attributes:        nil,
		encryptedMetadata: "",
		mimeType:          "application/octet-stream",
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
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
func (w *chunkedWriter) buildManifest(ctx context.Context, cfg *ChunkedFinalizeConfig) (*Manifest, int64, int64, error) {
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
	if len(order) > 0 {
		if first, ok := w.segments[order[0]]; ok {
			encInfo.DefaultEncryptedSegSize = first.EncryptedSize
			encInfo.DefaultSegmentSize = first.Size
		}
	}

	rootSig, err := calculateSignature(aggregate.Bytes(), w.dek, w.integrityAlgorithm, false)
	if err != nil {
		return nil, 0, 0, err
	}
	encInfo.RootSignature = RootSignature{
		Algorithm: integrityAlgorithmString(w.integrityAlgorithm),
		Signature: string(ocrypto.Base64Encode([]byte(rootSig))),
	}

	manifest := &Manifest{
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
// writer state and an optional keepSegments prefix. Caller holds mu.
func (w *chunkedWriter) segmentOrderLocked(keep []int) ([]int, error) {
	if len(keep) == 0 {
		order := make([]int, 0, len(w.segments))
		for idx := range w.segments {
			order = append(order, idx)
		}
		sort.Ints(order)
		return order, nil
	}
	seen := make(map[int]struct{}, len(keep))
	for i, idx := range keep {
		if idx < 0 {
			return nil, fmt.Errorf("WithChunkedSegments contains invalid index %d (must be >= 0)", idx)
		}
		if idx != i {
			return nil, fmt.Errorf("WithChunkedSegments must form a contiguous prefix [0..K]; got %d at position %d", idx, i)
		}
		if _, dup := seen[idx]; dup {
			return nil, fmt.Errorf("WithChunkedSegments contains duplicate index %d", idx)
		}
		if _, ok := w.segments[idx]; !ok {
			return nil, fmt.Errorf("WithChunkedSegments references segment %d which was not written", idx)
		}
		seen[idx] = struct{}{}
	}
	out := make([]int, len(keep))
	copy(out, keep)
	return out, nil
}

// buildChunkedKeyAccessObjects wraps each split share to each KAS
// listed by the splitter.
func buildChunkedKeyAccessObjects(splits *SplitResult, policyBytes []byte, metadata string) ([]KeyAccess, error) {
	if splits == nil || len(splits.Splits) == 0 {
		return nil, errors.New("no splits produced")
	}
	base64Policy := string(ocrypto.Base64Encode(policyBytes))

	var out []KeyAccess
	for _, split := range splits.Splits {
		for _, url := range split.KASURLs {
			pk, ok := splits.KASPublicKeys[url]
			if !ok {
				continue
			}
			var encMeta string
			if metadata != "" {
				m, err := chunkedEncryptMetadata(split.Data, metadata)
				if err != nil {
					return nil, fmt.Errorf("encrypt metadata for %s: %w", url, err)
				}
				encMeta = m
			}
			wrappedKey, keyType, ephemeralPub, err := chunkedWrapKeyWithPublicKey(split.Data, pk)
			if err != nil {
				return nil, fmt.Errorf("wrap key for %s: %w", url, err)
			}
			out = append(out, KeyAccess{
				EncryptedMetadata:  encMeta,
				EphemeralPublicKey: ephemeralPub,
				KasURL:             url,
				KeyType:            keyType,
				KID:                pk.KID,
				PolicyBinding:      chunkedCreatePolicyBinding(split.Data, base64Policy),
				Protocol:           "kas",
				SplitID:            split.ID,
				WrappedKey:         wrappedKey,
			})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no valid key access objects generated")
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

// chunkedCreatePolicyBinding produces an HMAC-SHA256 binding value
// keyed on the split share, over the base64-encoded policy.
func chunkedCreatePolicyBinding(symKey []byte, base64Policy string) any {
	mac := ocrypto.CalculateSHA256Hmac(symKey, []byte(base64Policy))
	hashHex := hex.EncodeToString(mac)
	return PolicyBinding{
		Alg:  hmacIntegrityAlgorithm,
		Hash: string(ocrypto.Base64Encode([]byte(hashHex))),
	}
}

// chunkedEncryptMetadata wraps opaque metadata with AES-GCM keyed on
// the split share, returning a base64-encoded EncryptedMetadata JSON
// blob suitable for the KAO's encryptedMetadata field.
func chunkedEncryptMetadata(symKey []byte, metadata string) (string, error) {
	gcm, err := ocrypto.NewAESGcm(symKey)
	if err != nil {
		return "", fmt.Errorf("aes-gcm: %w", err)
	}
	sealed, err := gcm.Encrypt([]byte(metadata))
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	iv := sealed[:ocrypto.GcmStandardNonceSize]
	blob, err := json.Marshal(EncryptedMetadata{
		Cipher: string(ocrypto.Base64Encode(sealed)),
		Iv:     string(ocrypto.Base64Encode(iv)),
	})
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	return string(ocrypto.Base64Encode(blob)), nil
}

// chunkedWrapKeyWithEC wraps symKey using an ECIES-style envelope:
// derive a wrapping key from ECDH(ephemeral, kas) via HKDF and
// XOR-wrap.
func chunkedWrapKeyWithEC(keyType ocrypto.KeyType, kasPubPEM string, symKey []byte) (string, string, string, error) {
	mode, err := ocrypto.ECKeyTypeToMode(keyType)
	if err != nil {
		return "", "", "", fmt.Errorf("ec key type mode: %w", err)
	}
	pair, err := ocrypto.NewECKeyPair(mode)
	if err != nil {
		return "", "", "", fmt.Errorf("ec keypair: %w", err)
	}
	ephemeralPub, err := pair.PublicKeyInPemFormat()
	if err != nil {
		return "", "", "", fmt.Errorf("ephemeral pub: %w", err)
	}
	ephemeralPriv, err := pair.PrivateKeyInPemFormat()
	if err != nil {
		return "", "", "", fmt.Errorf("ephemeral priv: %w", err)
	}
	shared, err := ocrypto.ComputeECDHKey([]byte(ephemeralPriv), []byte(kasPubPEM))
	if err != nil {
		return "", "", "", fmt.Errorf("ecdh: %w", err)
	}
	salt := sha256.Sum256([]byte("TDF"))
	wrapKey, err := ocrypto.CalculateHKDF(salt[:], shared)
	if err != nil {
		return "", "", "", fmt.Errorf("hkdf: %w", err)
	}
	switch {
	case len(wrapKey) > len(symKey):
		wrapKey = wrapKey[:len(symKey)]
	case len(wrapKey) < len(symKey):
		return "", "", "", fmt.Errorf("wrap key too short: got %d expected %d", len(wrapKey), len(symKey))
	}
	sealed := make([]byte, len(symKey))
	for i := range symKey {
		sealed[i] = symKey[i] ^ wrapKey[i]
	}
	return string(ocrypto.Base64Encode(sealed)), "eccWrapped", ephemeralPub, nil
}

// chunkedWrapKeyWithKEM wraps a DEK share with any KEM scheme (ML-KEM
// or hybrid).
func chunkedWrapKeyWithKEM(keyType ocrypto.KeyType, kasPubPEM string, symKey []byte) (string, string, string, error) {
	envelope, err := ocrypto.WrapDEK(keyType, kasPubPEM, symKey)
	if err != nil {
		return "", "", "", fmt.Errorf("kem wrap: %w", err)
	}
	scheme := "hybrid-wrapped"
	if ocrypto.IsMLKEMKeyType(keyType) {
		scheme = "mlkem-wrapped"
	}
	return string(ocrypto.Base64Encode(envelope)), scheme, "", nil
}

// chunkedWrapKeyWithRSA wraps symKey using RSA-OAEP against the KAS
// public key.
func chunkedWrapKeyWithRSA(kasPubPEM string, symKey []byte) (string, string, string, error) {
	enc, err := ocrypto.FromPublicPEM(kasPubPEM)
	if err != nil {
		return "", "", "", fmt.Errorf("rsa encryptor: %w", err)
	}
	sealed, err := enc.Encrypt(symKey)
	if err != nil {
		return "", "", "", fmt.Errorf("rsa encrypt: %w", err)
	}
	return string(ocrypto.Base64Encode(sealed)), kWrapped, "", nil
}

// chunkedWrapKeyWithPublicKey dispatches to the right KAS wrapping
// scheme based on the algorithm advertised by the splitter.
func chunkedWrapKeyWithPublicKey(symKey []byte, pk KASPublicKey) (string, string, string, error) {
	if pk.PEM == "" {
		return "", "", "", fmt.Errorf("public key PEM is empty for kas %s", pk.URL)
	}
	ktype := ocrypto.KeyType(pk.Algorithm)
	switch {
	case ocrypto.IsKEMKeyType(ktype):
		return chunkedWrapKeyWithKEM(ktype, pk.PEM, symKey)
	case ocrypto.IsECKeyType(ktype):
		return chunkedWrapKeyWithEC(ktype, pk.PEM, symKey)
	default:
		return chunkedWrapKeyWithRSA(pk.PEM, symKey)
	}
}
