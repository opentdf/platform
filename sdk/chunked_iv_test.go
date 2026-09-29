package sdk

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"sync"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/internal/zipstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These cover the per-key IV counter from the SDK side: that the payload is
// sealed by one sealer whose counter every segment write advances, and that key
// access metadata is sealed by a sealer of its own. The construction's own byte
// layout is pinned in lib/ocrypto/message_sealer_test.go.

// recordingSealers wraps defaultSegmentSealerFactory and records the header of
// every Seal that passes through it, in call order.
type recordingSealers struct {
	mu      sync.Mutex
	built   int
	headers [][]byte
}

// option returns the writer option that installs this recorder.
func (r *recordingSealers) option() ChunkedWriterOption {
	return withChunkedSealerFactory(r.factory)
}

func (r *recordingSealers) factory(dek []byte) (segmentSealer, error) {
	inner, err := defaultSegmentSealerFactory(dek)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.built++
	return &recordingSealer{inner: inner, parent: r}, nil
}

// snapshot copies the headers out, so an assertion cannot race a write.
func (r *recordingSealers) snapshot() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.headers...)
}

// recordingSealer is one key's sealer inside a recordingSealers.
type recordingSealer struct {
	inner  segmentSealer
	parent *recordingSealers
}

func (r *recordingSealer) Seal(data []byte) ([]byte, []byte, error) {
	header, ciphertext, err := r.inner.Seal(data)
	if err != nil {
		return nil, nil, err
	}
	r.parent.mu.Lock()
	defer r.parent.mu.Unlock()
	r.parent.headers = append(r.parent.headers, bytes.Clone(header))
	return header, ciphertext, nil
}

// fixedFieldSize is the width of the per-sealer random prefix of every IV the
// counter construction produces; the remainder is the counter.
const fixedFieldSize = ocrypto.GcmStandardNonceSize - 4

// deterministicSegmentIVs reports whether this build counts IVs. Where ocrypto
// falls back to an RBG -- under FIPS 140-3, where a caller-supplied IV is not
// an approved service -- the header is random and carries neither field.
//
// Probed by sealing twice rather than read off a mode, because ocrypto
// deliberately exposes no such flag: the fallback is meant to be invisible
// above it. Only assertions about the header *bytes* need to know.
var deterministicSegmentIVs = sync.OnceValue(func() bool {
	sealer, err := ocrypto.NewAESGcmSealer(make([]byte, kKeySize))
	if err != nil {
		return false
	}
	first, _, err := sealer.Seal(nil)
	if err != nil {
		return false
	}
	second, _, err := sealer.Seal(nil)
	if err != nil {
		return false
	}
	return bytes.Equal(first[:fixedFieldSize], second[:fixedFieldSize]) &&
		counterOf(first) == 0 && counterOf(second) == 1
})

// requireDeterministicSegmentIVs skips a test that can only assert something
// about a counted header.
func requireDeterministicSegmentIVs(t *testing.T) {
	t.Helper()
	if !deterministicSegmentIVs() {
		t.Skip("segment IVs come from an RBG on this build; there is no counted layout to check")
	}
}

// counterOf returns the big-endian counter tail of a header.
func counterOf(header []byte) uint32 {
	return binary.BigEndian.Uint32(header[fixedFieldSize:])
}

// assertCountedHeaders checks that headers share one fixed field and that
// their counters are exactly 0..len-1, in any order. Every header must be the
// standard width in either mode, and distinct -- the property that matters.
func assertCountedHeaders(t *testing.T, headers [][]byte) {
	t.Helper()
	seen := make(map[string]bool, len(headers))
	for i, header := range headers {
		require.Len(t, header, ocrypto.GcmStandardNonceSize)
		require.False(t, seen[string(header)], "header %d repeats an earlier IV", i)
		seen[string(header)] = true
	}
	if !deterministicSegmentIVs() {
		return
	}
	counters := make(map[uint32]bool, len(headers))
	for _, header := range headers {
		assert.Equal(t, headers[0][:fixedFieldSize], header[:fixedFieldSize], "one sealer, one fixed field")
		counters[counterOf(header)] = true
	}
	for n := range uint32(len(headers)) {
		assert.True(t, counters[n], "counter %d never taken", n)
	}
}

// readTDFPayload pulls the stored 0.payload entry out of a finished TDF. Its
// first 12 bytes are segment 0's IV, which is the only place the payload
// sealer's fixed field is observable from outside the writer.
func readTDFPayload(t *testing.T, tdf []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(tdf), int64(len(tdf)))
	require.NoError(t, err)
	for _, f := range zr.File {
		if f.Name != zipstream.TDFPayloadFileName {
			continue
		}
		rc, err := f.Open()
		require.NoError(t, err)
		defer rc.Close()
		payload, err := io.ReadAll(rc)
		require.NoError(t, err)
		return payload
	}
	t.Fatalf("no %s entry in the archive", zipstream.TDFPayloadFileName)
	return nil
}

// metadataIV decodes the IV out of a KAO's EncryptedMetadata envelope.
func metadataIV(t *testing.T, encrypted string) []byte {
	t.Helper()
	decodedJSON, err := ocrypto.Base64Decode([]byte(encrypted))
	require.NoError(t, err)
	var encMeta EncryptedMetadata
	require.NoError(t, json.Unmarshal(decodedJSON, &encMeta))
	iv, err := ocrypto.Base64Decode([]byte(encMeta.Iv))
	require.NoError(t, err)
	return iv
}

// TestChunkedSegmentIVLayout: sequential segment writes take counters 0, 1, 2,
// ... from one sealer.
func TestChunkedSegmentIVLayout(t *testing.T) {
	ctx := context.Background()
	rec := &recordingSealers{}
	writer, _ := newChunkedWriterForTest(ctx, t, rec.option())

	const segments = 5
	for i := range segments {
		_, err := writer.WriteSegment(ctx, i, []byte{byte(i)})
		require.NoError(t, err)
	}

	headers := rec.snapshot()
	require.Len(t, headers, segments)
	assert.Equal(t, 1, rec.built)
	assertCountedHeaders(t, headers)
	if deterministicSegmentIVs() {
		for i, header := range headers {
			assert.Equal(t, uint32(i), counterOf(header))
		}
	}
}

// TestChunkedSegmentIVOutOfOrder writes a sparse, out-of-order index set. The
// counter follows call order, not the index: that correspondence is what the
// construction gives up in exchange for never needing one.
func TestChunkedSegmentIVOutOfOrder(t *testing.T) {
	ctx := context.Background()
	rec := &recordingSealers{}
	writer, _ := newChunkedWriterForTest(ctx, t, rec.option())

	for _, index := range []int{7, 0, 3} {
		_, err := writer.WriteSegment(ctx, index, []byte("chunk"))
		require.NoError(t, err)
	}

	headers := rec.snapshot()
	require.Len(t, headers, 3)
	assertCountedHeaders(t, headers)
	if deterministicSegmentIVs() {
		for i, header := range headers {
			assert.Equal(t, uint32(i), counterOf(header), "the counter follows the call order")
		}
	}
}

// TestChunkedSegmentIVConcurrent checks that concurrent writers still get
// distinct IVs: the atomic counter hands each goroutine its own value.
func TestChunkedSegmentIVConcurrent(t *testing.T) {
	ctx := context.Background()
	rec := &recordingSealers{}
	writer, _ := newChunkedWriterForTest(ctx, t, rec.option())

	const segments = 32
	var wg sync.WaitGroup
	for i := range segments {
		wg.Go(func() {
			_, err := writer.WriteSegment(ctx, i, []byte("concurrent"))
			assert.NoError(t, err)
		})
	}
	wg.Wait()

	headers := rec.snapshot()
	require.Len(t, headers, segments)
	assertCountedHeaders(t, headers)
}

// TestChunkedMetadataUsesItsOwnSealer: with one KAS the sole split share is
// the DEK, yet the metadata is sealed by a throwaway sealer rather than the
// payload's. Both start at counter 0, so only their fixed fields keep the two
// IVs apart.
func TestChunkedMetadataUsesItsOwnSealer(t *testing.T) {
	ctx := context.Background()
	rec := &recordingSealers{}
	writer, _ := newChunkedWriterForTest(ctx, t, rec.option())

	_, err := writer.WriteSegment(ctx, 0, []byte("payload"))
	require.NoError(t, err)
	fin, err := writer.Finalize(ctx, WithChunkedEncryptedMetadata("meta"))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.KeyAccessObjs, 1)

	assert.Equal(t, 1, rec.built, "metadata must not go through the payload's sealer factory")
	headers := rec.snapshot()
	require.Len(t, headers, 1, "metadata must not advance the payload counter")

	iv := metadataIV(t, fin.Manifest.KeyAccessObjs[0].EncryptedMetadata)
	require.Len(t, iv, ocrypto.GcmStandardNonceSize)
	assert.NotEqual(t, headers[0], iv)
	if deterministicSegmentIVs() {
		assert.NotEqual(t, headers[0][:fixedFieldSize], iv[:fixedFieldSize])
		assert.Equal(t, uint32(0), counterOf(iv))
	}
}

// TestCreateTDFMetadataUsesItsOwnSealer is the same check for SDK.CreateTDF,
// which seals the metadata before it builds the writer.
func TestCreateTDFMetadataUsesItsOwnSealer(t *testing.T) {
	requireDeterministicSegmentIVs(t)

	s := newChunkedTestSDK(t)
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	var tdf bytes.Buffer
	obj, err := s.CreateTDF(&tdf, bytes.NewReader([]byte("payload bytes")),
		WithKasInformation(KASInfo{
			URL:       kasBundle.url,
			PublicKey: kasBundle.publicPEM,
			KID:       kasBundle.kid,
			Algorithm: string(ocrypto.RSA2048Key),
		}),
		WithMetaData("meta"),
		WithAutoconfigure(false),
	)
	require.NoError(t, err)
	require.Len(t, obj.manifest.KeyAccessObjs, 1)

	payload := readTDFPayload(t, tdf.Bytes())
	require.GreaterOrEqual(t, len(payload), ocrypto.GcmStandardNonceSize)
	segmentIV := payload[:ocrypto.GcmStandardNonceSize]
	iv := metadataIV(t, obj.manifest.KeyAccessObjs[0].EncryptedMetadata)

	assert.Equal(t, uint32(0), counterOf(segmentIV))
	assert.Equal(t, uint32(0), counterOf(iv))
	assert.NotEqual(t, segmentIV[:fixedFieldSize], iv[:fixedFieldSize])
}

// TestChunkedMetadataMayChangeBetweenBuilds: every manifest build seals the
// metadata afresh under a fresh IV, so nothing has to pin the first value.
func TestChunkedMetadataMayChangeBetweenBuilds(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t)
	_, err := writer.WriteSegment(ctx, 0, []byte("payload"))
	require.NoError(t, err)

	first, err := writer.GetManifest(ctx, WithChunkedEncryptedMetadata("A"))
	require.NoError(t, err)
	second, err := writer.GetManifest(ctx, WithChunkedEncryptedMetadata("A"))
	require.NoError(t, err)
	require.Len(t, first.KeyAccessObjs, 1)
	require.Len(t, second.KeyAccessObjs, 1)
	assert.NotEqual(t,
		metadataIV(t, first.KeyAccessObjs[0].EncryptedMetadata),
		metadataIV(t, second.KeyAccessObjs[0].EncryptedMetadata),
		"re-sealing the same metadata must not repeat an IV")

	_, err = writer.Finalize(ctx, WithChunkedEncryptedMetadata("B"))
	require.NoError(t, err)
}

// TestChunkedWriteSegmentRejectsExhaustedIndex checks the ceiling is enforced
// before the index is reserved, so a refused write leaves nothing behind for
// the caller to trip over.
func TestChunkedWriteSegmentRejectsExhaustedIndex(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t)

	for _, index := range []int{int(maxPayloadSegments), math.MaxInt} {
		_, err := writer.WriteSegment(ctx, index, []byte("too far"))
		require.ErrorIs(t, err, ErrChunkedSegmentIndexExhausted)
	}

	inner, ok := writer.(*chunkedWriter)
	require.True(t, ok)
	inner.mu.RLock()
	defer inner.mu.RUnlock()
	assert.Empty(t, inner.segments, "a refused index must never enter the segment table")
}

// TestChunkedSegmentIVRetryTakesFreshIV pins that a segment sealed and then
// discarded does not leave its IV for the retry: the retry takes the next
// counter value, so two different plaintexts never share one.
func TestChunkedSegmentIVRetryTakesFreshIV(t *testing.T) {
	ctx := context.Background()
	rec := &recordingSealers{}

	var fail bool
	writer, _ := newChunkedWriterForTest(ctx, t, withChunkedSealerFactory(
		func(dek []byte) (segmentSealer, error) {
			inner, err := rec.factory(dek)
			if err != nil {
				return nil, err
			}
			return &flakySealer{inner: inner, fail: &fail}, nil
		}))

	fail = true
	_, err := writer.WriteSegment(ctx, 0, []byte("doomed"))
	require.ErrorIs(t, err, errCipherFailed)

	fail = false
	_, err = writer.WriteSegment(ctx, 0, []byte("retried"))
	require.NoError(t, err)

	headers := rec.snapshot()
	require.Len(t, headers, 2, "the failed attempt was sealed before it was discarded")
	assertCountedHeaders(t, headers)
}

// flakySealer seals, then discards the result and fails while *fail is set --
// the shape of any failure after encryption. Unlike failingSealer it can be
// switched off, so one writer can see both a failure and the retry that
// follows it.
type flakySealer struct {
	inner segmentSealer
	fail  *bool
}

func (f *flakySealer) Seal(data []byte) ([]byte, []byte, error) {
	header, ciphertext, err := f.inner.Seal(data)
	if *f.fail {
		return nil, nil, errCipherFailed
	}
	return header, ciphertext, err
}

// TestDerivedSegmentSizing pins the arithmetic that keeps the reachable
// payload at targetPayloadCapacity as the seal ceiling moves. It is the whole
// application-visible consequence of the RBG fallback, and it must hold
// without a FIPS build to check it in.
func TestDerivedSegmentSizing(t *testing.T) {
	assert.GreaterOrEqual(t, defaultSegmentSize, int64(preferredSegmentSize))
	assert.LessOrEqual(t, defaultSegmentSize, int64(maxSegmentSize))
	assert.Positive(t, maxPayloadSegments)
	assert.LessOrEqual(t, maxPayloadSegments, int64(math.MaxInt32))
	assert.GreaterOrEqual(t, maxPayloadSegments*defaultSegmentSize, int64(targetPayloadCapacity),
		"the default segment size must keep targetPayloadCapacity reachable")

	// Both ceilings, checked against the derivation rather than against
	// whichever one this build happens to use.
	for _, maxSeals := range []uint32{math.MaxUint32, 1 << 26} {
		segments := min(int64(maxSeals), int64(math.MaxInt32))
		size := int64(preferredSegmentSize)
		for size < maxSegmentSize && segments*size < targetPayloadCapacity {
			size *= 2
		}
		assert.GreaterOrEqual(t, segments*size, int64(targetPayloadCapacity),
			"max seals %d needs a segment size the cap does not allow", maxSeals)
	}
}
