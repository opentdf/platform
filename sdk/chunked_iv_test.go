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

// These cover the deterministic IV construction from the SDK side: that the
// writer numbers parts the way segmentPart says, that key access metadata
// shares the message ID at metadataPart, and that nothing can seal a second
// plaintext under a part that is already spent. The construction's own byte
// layout is pinned in lib/ocrypto/message_sealer_test.go.

// sealRecord is one Seal call: the part number the writer asked for and the
// header the sealer derived for it.
type sealRecord struct {
	part   uint32
	header []byte
}

// recordingSealers wraps defaultSegmentSealerFactory and records every Seal
// that passes through it, in call order.
//
// It records across every key the message seals under. That is only
// unambiguous because these tests use a single KAS, where the sole split share
// is the DEK and so one sealer handles both the metadata and the payload --
// which is exactly the aliasing the reserved metadata part exists to survive.
type recordingSealers struct {
	mu      sync.Mutex
	built   int
	records []sealRecord
}

// option returns the writer option that installs this recorder.
func (r *recordingSealers) option() ChunkedWriterOption {
	return withChunkedSealerFactory(func(dek []byte, id ocrypto.MessageID) (segmentSealer, error) {
		inner, err := defaultSegmentSealerFactory(dek, id)
		if err != nil {
			return nil, err
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.built++
		return &recordingSealer{inner: inner, parent: r}, nil
	})
}

// snapshot copies the records out, so an assertion cannot race a write.
func (r *recordingSealers) snapshot() []sealRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]sealRecord(nil), r.records...)
}

// headerFor returns the header recorded for part, failing if there is none.
func (r *recordingSealers) headerFor(t *testing.T, part uint32) []byte {
	t.Helper()
	for _, rec := range r.snapshot() {
		if rec.part == part {
			return rec.header
		}
	}
	t.Fatalf("no seal recorded for part %d", part)
	return nil
}

// recordingSealer is one key's sealer inside a recordingSealers.
type recordingSealer struct {
	inner  segmentSealer
	parent *recordingSealers
}

func (r *recordingSealer) Seal(part uint32, data []byte) ([]byte, []byte, error) {
	header, ciphertext, err := r.inner.Seal(part, data)
	if err != nil {
		return nil, nil, err
	}
	r.parent.mu.Lock()
	defer r.parent.mu.Unlock()
	r.parent.records = append(r.parent.records, sealRecord{part: part, header: bytes.Clone(header)})
	return header, ciphertext, nil
}

// deterministicSegmentIVs reports whether this build derives segment IVs from
// the message ID and part number. Where ocrypto falls back to an RBG -- under
// FIPS 140-3, where a caller-supplied IV is not an approved service -- the
// header is random and carries neither field.
//
// Probed by sealing a known ID rather than read off a mode, because ocrypto
// deliberately exposes no such flag: the fallback is meant to be invisible
// above it, and the part numbers this package chooses do not change either
// way. Only assertions about the header *bytes* need to know.
var deterministicSegmentIVs = sync.OnceValue(func() bool {
	id, err := ocrypto.MessageIDFromBytes(bytes.Repeat([]byte{0xA5}, ocrypto.MessageIDSize))
	if err != nil {
		return false
	}
	sealer, err := ocrypto.NewAESGcmSealer(make([]byte, kKeySize), id)
	if err != nil {
		return false
	}
	header, _, err := sealer.Seal(1, nil)
	if err != nil {
		return false
	}
	return len(header) == ocrypto.GcmStandardNonceSize &&
		bytes.Equal(header[:ocrypto.MessageIDSize], id.Bytes())
})

// requireDeterministicSegmentIVs skips a test that can only assert something
// about a derived header.
func requireDeterministicSegmentIVs(t *testing.T) {
	t.Helper()
	if !deterministicSegmentIVs() {
		t.Skip("segment IVs come from an RBG on this build; there is no derived layout to check")
	}
}

// assertPartHeader checks one header against the message ID prefix and the
// part number it should carry. On the RBG fallback there is nothing in the
// header to check beyond its width; the part numbers themselves are asserted
// separately and are the same in both modes.
func assertPartHeader(t *testing.T, header, wantPrefix []byte, wantPart uint32) {
	t.Helper()
	require.Len(t, header, ocrypto.GcmStandardNonceSize)
	if !deterministicSegmentIVs() {
		return
	}
	assert.Equal(t, wantPrefix, header[:ocrypto.MessageIDSize], "every part of one message shares the fixed field")
	assert.Equal(t, wantPart, binary.BigEndian.Uint32(header[ocrypto.MessageIDSize:]), "the part number is the big-endian tail")
}

// readTDFPayload pulls the stored 0.payload entry out of a finished TDF. Its
// first 12 bytes are segment 0's IV, which is the only place the payload's
// message ID is observable from outside the writer.
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

// TestChunkedSegmentIVLayout pins the writer's half of the construction:
// segment i is sealed at part i+1, under one fixed field for the whole
// message.
func TestChunkedSegmentIVLayout(t *testing.T) {
	ctx := context.Background()
	rec := &recordingSealers{}
	writer, _ := newChunkedWriterForTest(ctx, t, rec.option())

	const segments = 5
	for i := range segments {
		_, err := writer.WriteSegment(ctx, i, []byte{byte(i)})
		require.NoError(t, err)
	}

	records := rec.snapshot()
	require.Len(t, records, segments)
	prefix := records[0].header[:ocrypto.MessageIDSize]
	for i, rec := range records {
		want := uint32(i) + 1
		assert.Equal(t, want, rec.part, "segment %d must be sealed at part %d", i, want)
		assertPartHeader(t, rec.header, prefix, want)
	}
}

// TestChunkedSegmentIVSkipsMetadataPart is the whole reason payload segments
// start at 1. Nothing else in this file would notice an off-by-one that made
// segment 0 collide with the metadata.
func TestChunkedSegmentIVSkipsMetadataPart(t *testing.T) {
	ctx := context.Background()
	rec := &recordingSealers{}
	writer, _ := newChunkedWriterForTest(ctx, t, rec.option())

	_, err := writer.WriteSegment(ctx, 0, []byte("first"))
	require.NoError(t, err)

	records := rec.snapshot()
	require.Len(t, records, 1)
	assert.NotEqual(t, metadataPart, records[0].part, "segment 0 must not take the metadata part")
	assert.Equal(t, uint32(1), records[0].part)
}

// TestChunkedSegmentIVOutOfOrder writes a sparse, out-of-order index set. This
// is the test a stateful next()-style counter fails: it would number these 1,
// 2, 3 in call order and lose the index correspondence entirely.
func TestChunkedSegmentIVOutOfOrder(t *testing.T) {
	ctx := context.Background()
	rec := &recordingSealers{}
	writer, _ := newChunkedWriterForTest(ctx, t, rec.option())

	for _, index := range []int{7, 0, 3} {
		_, err := writer.WriteSegment(ctx, index, []byte("chunk"))
		require.NoError(t, err)
	}

	records := rec.snapshot()
	require.Len(t, records, 3)
	prefix := records[0].header[:ocrypto.MessageIDSize]
	for i, wantPart := range []uint32{8, 1, 4} {
		assert.Equal(t, wantPart, records[i].part, "the part follows the index, not the call order")
		assertPartHeader(t, records[i].header, prefix, wantPart)
	}
}

// TestChunkedSegmentIVConcurrent checks that concurrent writers still get
// distinct IVs. A shared mutable counter could hand two goroutines the same
// part; an index-derived one cannot.
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

	records := rec.snapshot()
	require.Len(t, records, segments)

	seen := make(map[string]uint32, segments)
	prefix := records[0].header[:ocrypto.MessageIDSize]
	for _, rec := range records {
		assertPartHeader(t, rec.header, prefix, rec.part)
		if prev, dup := seen[string(rec.header)]; dup {
			t.Fatalf("parts %d and %d produced the same IV", prev, rec.part)
		}
		seen[string(rec.header)] = rec.part
	}
	assert.Len(t, seen, segments)
}

// TestChunkedMetadataSealedAtMetadataPart checks the other end of the
// reservation: key access metadata takes part 0 of the same message, under a
// key that -- with one KAS and therefore one split share -- is the DEK itself.
func TestChunkedMetadataSealedAtMetadataPart(t *testing.T) {
	ctx := context.Background()
	rec := &recordingSealers{}
	writer, _ := newChunkedWriterForTest(ctx, t, rec.option())

	_, err := writer.WriteSegment(ctx, 0, []byte("payload"))
	require.NoError(t, err)
	fin, err := writer.Finalize(ctx, WithChunkedEncryptedMetadata("meta"))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.KeyAccessObjs, 1)

	assert.Equal(t, 1, rec.built, "the sole split share is the DEK, so one sealer must serve both")

	metadataHeader := rec.headerFor(t, metadataPart)
	require.Len(t, metadataHeader, ocrypto.GcmStandardNonceSize)

	payloadHeader := rec.headerFor(t, 1)
	iv := metadataIV(t, fin.Manifest.KeyAccessObjs[0].EncryptedMetadata)
	assertPartHeader(t, iv, payloadHeader[:ocrypto.MessageIDSize], metadataPart)
}

// TestCreateTDFMetadataSharesMessageID is the same check for SDK.CreateTDF,
// which resolves key access before it builds the writer. That ordering is
// where the two could be handed different registries -- and the resulting
// cross-message IV reuse would be invisible to every other test, because both
// halves would still decrypt.
func TestCreateTDFMetadataSharesMessageID(t *testing.T) {
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
	assertPartHeader(t, segmentIV, iv[:ocrypto.MessageIDSize], 1)
	assertPartHeader(t, iv, segmentIV[:ocrypto.MessageIDSize], metadataPart)
}

// TestSegmentPart tables the index-to-part mapping and its ceiling directly.
// Driving four billion indices through the writer is not an option, and the
// boundary is the only interesting part of the function.
func TestSegmentPart(t *testing.T) {
	last := int(maxPayloadSegments - 1)

	for _, tc := range []struct {
		name  string
		index int
		part  uint32
		err   error
	}{
		{name: "negative", index: -1, err: ErrChunkedInvalidSegmentIndex},
		{name: "most negative", index: math.MinInt, err: ErrChunkedInvalidSegmentIndex},
		{name: "zero takes the part after metadata", index: 0, part: metadataPart + 1},
		{name: "one", index: 1, part: 2},
		{name: "last allowed", index: last, part: uint32(maxPayloadSegments)},
		{name: "one past the last", index: last + 1, err: ErrChunkedSegmentIndexExhausted},
		{name: "max int", index: math.MaxInt, err: ErrChunkedSegmentIndexExhausted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			part, err := segmentPart(tc.index)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Zero(t, part)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.part, part)
		})
	}
}

// TestSegmentPartStaysBelowTheMessageLimit checks the two ceilings agree: the
// largest part the payload can ask for must still be one the sealer accepts.
func TestSegmentPartStaysBelowTheMessageLimit(t *testing.T) {
	part, err := segmentPart(int(maxPayloadSegments - 1))
	require.NoError(t, err)
	assert.Less(t, part, ocrypto.MaxMessageParts(), "the last payload part must be inside the sealer's range")
}

// TestChunkedWriteSegmentRejectsExhaustedIndex checks the ceiling is enforced
// before the index is reserved, so a refused write leaves nothing behind for
// the caller to trip over.
func TestChunkedWriteSegmentRejectsExhaustedIndex(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t)

	_, err := writer.WriteSegment(ctx, int(maxPayloadSegments), []byte("too far"))
	require.ErrorIs(t, err, ErrChunkedSegmentIndexExhausted)

	inner, ok := writer.(*chunkedWriter)
	require.True(t, ok)
	inner.mu.RLock()
	defer inner.mu.RUnlock()
	assert.Empty(t, inner.segments, "a refused index must never enter the segment table")
}

// TestChunkedSegmentIVRetryIsDeterministic pins that a retried index
// re-derives its part rather than consuming a new one. Documented behavior,
// and the reason WriteSegment carries a retry analysis: the same part means
// the same IV, so a retry must never carry different bytes.
func TestChunkedSegmentIVRetryIsDeterministic(t *testing.T) {
	ctx := context.Background()
	rec := &recordingSealers{}

	var fail bool
	writer, _ := newChunkedWriterForTest(ctx, t, withChunkedSealerFactory(
		func(dek []byte, id ocrypto.MessageID) (segmentSealer, error) {
			inner, err := defaultSegmentSealerFactory(dek, id)
			if err != nil {
				return nil, err
			}
			rec.mu.Lock()
			defer rec.mu.Unlock()
			rec.built++
			return &flakySealer{inner: &recordingSealer{inner: inner, parent: rec}, fail: &fail}, nil
		}))

	fail = true
	_, err := writer.WriteSegment(ctx, 0, []byte("doomed"))
	require.ErrorIs(t, err, errCipherFailed)

	fail = false
	_, err = writer.WriteSegment(ctx, 0, []byte("retried"))
	require.NoError(t, err)
	_, err = writer.WriteSegment(ctx, 1, []byte("next"))
	require.NoError(t, err)

	records := rec.snapshot()
	require.Len(t, records, 2, "the failed attempt never reached the sealer")
	prefix := records[0].header[:ocrypto.MessageIDSize]
	assert.Equal(t, uint32(1), records[0].part, "the retry re-derives index 0's part rather than consuming a new one")
	assert.Equal(t, uint32(2), records[1].part)
	assertPartHeader(t, records[0].header, prefix, 1)
	assertPartHeader(t, records[1].header, prefix, 2)
}

// flakySealer fails before delegating while *fail is set. Unlike
// failingSealer it can be switched off, so one writer can see both a failure
// and the retry that follows it.
type flakySealer struct {
	inner segmentSealer
	fail  *bool
}

func (f *flakySealer) Seal(part uint32, data []byte) ([]byte, []byte, error) {
	if *f.fail {
		return nil, nil, errCipherFailed
	}
	return f.inner.Seal(part, data)
}

// TestChunkedMetadataPin covers the hole reserving one metadata part opens:
// every manifest build re-resolves key access with that call's own metadata,
// and the part is spent on the first value.
func TestChunkedMetadataPin(t *testing.T) {
	ctx := context.Background()

	t.Run("a second value is refused", func(t *testing.T) {
		writer, _ := newChunkedWriterForTest(ctx, t)
		_, err := writer.WriteSegment(ctx, 0, []byte("payload"))
		require.NoError(t, err)

		_, err = writer.GetManifest(ctx, WithChunkedEncryptedMetadata("A"))
		require.NoError(t, err)

		_, err = writer.Finalize(ctx, WithChunkedEncryptedMetadata("B"))
		require.ErrorIs(t, err, ErrChunkedMetadataChanged)
	})

	// Repeating the first value is not an error, and must not re-encrypt:
	// the envelope is cached, so the answer is byte-identical even though
	// everything else about a rebuilt manifest -- policy UUID, wrapped keys
	// -- is freshly minted.
	t.Run("the same value rebuilds to identical bytes", func(t *testing.T) {
		writer, _ := newChunkedWriterForTest(ctx, t)
		_, err := writer.WriteSegment(ctx, 0, []byte("payload"))
		require.NoError(t, err)

		first, err := writer.GetManifest(ctx, WithChunkedEncryptedMetadata("A"))
		require.NoError(t, err)
		second, err := writer.GetManifest(ctx, WithChunkedEncryptedMetadata("A"))
		require.NoError(t, err)

		require.Len(t, first.KeyAccessObjs, 1)
		require.Len(t, second.KeyAccessObjs, 1)
		assert.Equal(t, first.KeyAccessObjs[0].EncryptedMetadata, second.KeyAccessObjs[0].EncryptedMetadata)
	})

	// Empty metadata pins too. Otherwise the default-options build that most
	// callers make first would leave the part unclaimed, and a later
	// Finalize could still spend it on something else.
	t.Run("an omitted value pins the empty string", func(t *testing.T) {
		writer, _ := newChunkedWriterForTest(ctx, t)
		_, err := writer.WriteSegment(ctx, 0, []byte("payload"))
		require.NoError(t, err)

		_, err = writer.GetManifest(ctx)
		require.NoError(t, err)

		_, err = writer.Finalize(ctx, WithChunkedEncryptedMetadata("late"))
		require.ErrorIs(t, err, ErrChunkedMetadataChanged)
	})
}

// TestDerivedSegmentSizing pins the arithmetic that keeps the reachable
// payload at targetPayloadCapacity as the part ceiling moves. It is the whole
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
	for _, maxParts := range []uint32{math.MaxUint32, 1 << 26} {
		segments := min(int64(maxParts-1), int64(math.MaxInt32))
		size := int64(preferredSegmentSize)
		for size < maxSegmentSize && segments*size < targetPayloadCapacity {
			size *= 2
		}
		assert.GreaterOrEqual(t, segments*size, int64(targetPayloadCapacity),
			"max parts %d needs a segment size the cap does not allow", maxParts)
	}
}
