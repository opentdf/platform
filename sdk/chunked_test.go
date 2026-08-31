package sdk

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/internal/zipstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestChunkedRoundTrip writes segments through NewChunkedWriter and
// reads the resulting TDF back through the mainline SDK.LoadTDF path
// (single-KAS, RSA-2048), verifying end-to-end interop.
func TestChunkedRoundTrip(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)

	chunks := [][]byte{[]byte("hello, "), []byte("chunked "), []byte("world!")}
	body := writeChunkedSegments(ctx, t, writer, chunks)

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	require.NotNil(t, fin.Manifest)

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello, chunked world!"), plain)
}

// TestChunkedKeepSegments verifies WithChunkedSegments trims trailing
// segments from the manifest and the mainline reader decrypts only the
// retained ones.
func TestChunkedKeepSegments(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)

	body := writeChunkedSegments(ctx, t, writer, [][]byte{
		[]byte("keep-0-"), []byte("keep-1-"), []byte("drop-2!"),
	})
	fin, err := writer.Finalize(ctx, WithChunkedSegments([]int{0, 1}))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, 2)

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("keep-0-keep-1-"), plain)
}

// TestChunkedFinalizeSignsAssertions verifies assertions supplied to
// Finalize land in the manifest signed with the default HS256-over-DEK
// key, and that the mainline reader verifies them on the way back out.
func TestChunkedFinalizeSignsAssertions(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)

	body := writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("asserted payload")})

	fin, err := writer.Finalize(ctx, WithChunkedAssertions([]AssertionConfig{{
		ID:             "a",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement:      Statement{Format: "json", Schema: "urn:test", Value: `{"k":"v"}`},
	}}))
	require.NoError(t, err)

	require.Len(t, fin.Manifest.Assertions, 1)
	got := fin.Manifest.Assertions[0]
	assert.Equal(t, "a", got.ID)
	assert.Equal(t, JWS.String(), got.Binding.Method)
	assert.NotEmpty(t, got.Binding.Signature)

	// The reader recomputes the aggregate hash and re-verifies the
	// binding, so a round trip is the real check that the assertion was
	// bound to this payload and not merely well-formed.
	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("asserted payload"), plain)
}

// TestChunkedOutOfOrderWrites exercises the core value proposition of
// ChunkedWriter: segments may be written in any order provided the
// caller concatenates TDFData in index order before Finalize.Data.
func TestChunkedOutOfOrderWrites(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)

	chunks := [][]byte{[]byte("aaa-"), []byte("bbb-"), []byte("ccc-"), []byte("ddd!")}

	// Write in scrambled order: 2, 0, 3, 1.
	segBytes := make([][]byte, len(chunks))
	for _, idx := range []int{2, 0, 3, 1} {
		seg, err := writer.WriteSegment(ctx, idx, chunks[idx])
		require.NoError(t, err)
		buf, err := io.ReadAll(seg.TDFData)
		require.NoError(t, err)
		segBytes[idx] = buf
	}

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	require.Equal(t, 4, fin.TotalSegments)

	// Concat in INDEX order (segment 0 carries the ZIP local header).
	var body bytes.Buffer
	for _, buf := range segBytes {
		body.Write(buf)
	}
	body.Write(fin.Data)

	reader, err := s.LoadTDF(bytes.NewReader(body.Bytes()),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("aaa-bbb-ccc-ddd!"), plain)
}

// TestChunkedClockThreadedToZipHeaders verifies WithChunkedClock is
// threaded into the zipstream layer so every ZIP entry ModTime
// stamps from the injected clock rather than time.Now. This is the
// invariant that enables byte-deterministic ZIP headers for xtest
// fixtures (DEK / session-key randomness still varies the payload
// and KAS-wrap ciphertexts, which is not the scope of this test).
func TestChunkedClockThreadedToZipHeaders(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	// Pick a 2-second-aligned instant so DOS timestamp truncation is
	// a no-op.
	pinned := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	s := newChunkedTestSDK(t)

	w, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
		WithChunkedClock(FixedClock{T: pinned}),
	)
	require.NoError(t, err)

	body := writeChunkedSegments(ctx, t, w, [][]byte{[]byte("payload-abc")})
	fin, err := w.Finalize(ctx)
	require.NoError(t, err)

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	zr, err := zip.NewReader(bytes.NewReader(tdfBytes), int64(len(tdfBytes)))
	require.NoError(t, err)
	require.NotEmpty(t, zr.File)

	for _, f := range zr.File {
		// archive/zip normalises DOS timestamps to the local zone; compare in UTC.
		assert.Equal(t, pinned, f.Modified.UTC(),
			"entry %q ModTime must match injected clock", f.Name)
	}
}

// TestChunkedDuplicateSegment verifies WriteSegment rejects an index
// that was already written.
func TestChunkedDuplicateSegment(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("first"))
	require.NoError(t, err)
	_, err = w.WriteSegment(ctx, 0, []byte("second"))
	require.ErrorIs(t, err, ErrChunkedSegmentAlreadyWritten)
}

// TestChunkedNegativeIndex verifies WriteSegment rejects a negative
// segment index.
func TestChunkedNegativeIndex(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, -1, []byte("x"))
	require.ErrorIs(t, err, ErrChunkedInvalidSegmentIndex)
}

// TestChunkedWriteAfterFinalize verifies WriteSegment fails once the
// writer has been finalized.
func TestChunkedWriteAfterFinalize(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("x"))
	require.NoError(t, err)
	_, err = w.Finalize(ctx)
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 1, []byte("late"))
	require.ErrorIs(t, err, ErrChunkedAlreadyFinalized)
}

// TestChunkedDoubleFinalize verifies Finalize is not idempotent and
// returns the sentinel on the second call.
func TestChunkedDoubleFinalize(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("x"))
	require.NoError(t, err)
	_, err = w.Finalize(ctx)
	require.NoError(t, err)
	_, err = w.Finalize(ctx)
	require.ErrorIs(t, err, ErrChunkedAlreadyFinalized)
}

// TestChunkedKeepSegmentsSparse verifies WithChunkedSegments accepts a
// sparse index set. This is the S3 multipart shape: each upload part
// reserves a fixed block of indices and fills only the front of it, so
// the written indices have large gaps but are still emitted in order.
func TestChunkedKeepSegmentsSparse(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	const stride = 5000
	chunks := map[int][]byte{
		0:          []byte("part1-a-"),
		1:          []byte("part1-b-"),
		stride:     []byte("part2-a-"),
		stride + 1: []byte("part2-b"),
	}
	indices := []int{0, 1, stride, stride + 1}

	// Write out of order to prove the index, not the call order,
	// determines layout.
	encrypted := make(map[int][]byte, len(indices))
	for _, idx := range []int{stride, 0, stride + 1, 1} {
		seg, err := w.WriteSegment(ctx, idx, chunks[idx])
		require.NoError(t, err)
		buf, err := io.ReadAll(seg.TDFData)
		require.NoError(t, err)
		encrypted[idx] = buf
	}

	// Concatenate in ascending index order, as the contract requires.
	var body bytes.Buffer
	for _, idx := range indices {
		body.Write(encrypted[idx])
	}

	fin, err := w.Finalize(ctx, WithChunkedSegments(indices))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, len(indices))

	tdfBytes := bytes.Join([][]byte{body.Bytes(), fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("part1-a-part1-b-part2-a-part2-b"), plain)
}

// TestChunkedKeepSegmentsSkipsWritten verifies WithChunkedSegments
// rejects a keep list that omits a written segment with bytes after
// it. Dropping segment 1 while keeping 2 would shift 2's offset and
// make the payload unreadable.
func TestChunkedKeepSegmentsSkipsWritten(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	for i, chunk := range [][]byte{[]byte("a"), []byte("b"), []byte("c")} {
		_, err = w.WriteSegment(ctx, i, chunk)
		require.NoError(t, err)
	}
	_, err = w.Finalize(ctx, WithChunkedSegments([]int{0, 2}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ascending index order")
}

// TestChunkedKeepSegmentsOutOfOrder verifies WithChunkedSegments
// rejects a descending keep list even though every index was written.
func TestChunkedKeepSegmentsOutOfOrder(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	for i, chunk := range [][]byte{[]byte("a"), []byte("b")} {
		_, err = w.WriteSegment(ctx, i, chunk)
		require.NoError(t, err)
	}
	_, err = w.Finalize(ctx, WithChunkedSegments([]int{1, 0}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ascending index order")
}

// TestChunkedKeepSegmentsUnwritten verifies WithChunkedSegments
// rejects a keep list that names an index the caller never wrote.
func TestChunkedKeepSegmentsUnwritten(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("zero"))
	require.NoError(t, err)
	_, err = w.WriteSegment(ctx, 5, []byte("five"))
	require.NoError(t, err)
	_, err = w.Finalize(ctx, WithChunkedSegments([]int{0, 1}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not written")
}

// TestChunkedKeepSegmentsTooMany verifies WithChunkedSegments rejects a
// keep list longer than the number of written segments.
func TestChunkedKeepSegmentsTooMany(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("only-zero"))
	require.NoError(t, err)
	_, err = w.Finalize(ctx, WithChunkedSegments([]int{0, 1}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only 1 were written")
}

// TestChunkedKeepSegmentsDuplicate verifies WithChunkedSegments rejects a
// keep list that names the same index twice. A repeat cannot be ascending,
// so it fails the ordering rule rather than needing its own check.
func TestChunkedKeepSegmentsDuplicate(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	for i, chunk := range [][]byte{[]byte("a"), []byte("b")} {
		_, err = w.WriteSegment(ctx, i, chunk)
		require.NoError(t, err)
	}
	_, err = w.Finalize(ctx, WithChunkedSegments([]int{0, 0}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ascending index order")
}

// TestChunkedKeepSegmentsNegative verifies WithChunkedSegments rejects a
// negative index. WriteSegment never accepts one, so it can only ever be
// reported as unwritten.
func TestChunkedKeepSegmentsNegative(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	for i, chunk := range [][]byte{[]byte("a"), []byte("b")} {
		_, err = w.WriteSegment(ctx, i, chunk)
		require.NoError(t, err)
	}
	_, err = w.Finalize(ctx, WithChunkedSegments([]int{-1, 0}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not written")
}

// TestChunkedSegmentsNotStartingAtZero covers a writer whose lowest
// written index is not 0 -- what a caller gets if it reserves a block of
// indices per upload part and part 0 never runs, or if it simply numbers
// parts from 1.
//
// Either answer is acceptable: Finalize may refuse the write set, or it
// may produce a TDF that reads back. What it must not do is return
// success alongside bytes that are not a readable archive, because by
// then the upload has happened and the plaintext is gone. Today only
// segment 0 emits the payload's ZIP local file header (see
// zipstream.segmentWriter.WriteSegment), so the third case is what
// happens.
func TestChunkedSegmentsNotStartingAtZero(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	chunks := map[int][]byte{5: []byte("hello-"), 6: []byte("world!")}
	indices := []int{5, 6}

	encrypted := make(map[int][]byte, len(indices))
	for _, idx := range indices {
		seg, err := w.WriteSegment(ctx, idx, chunks[idx])
		require.NoError(t, err)
		buf, err := io.ReadAll(seg.TDFData)
		require.NoError(t, err)
		encrypted[idx] = buf
	}

	fin, err := w.Finalize(ctx)
	if err != nil {
		// Refusing the write set is a valid outcome; nothing was
		// published, so there is nothing further to check.
		t.Logf("Finalize rejected a segment set starting at %d: %v", indices[0], err)
		return
	}

	// Finalize claimed success, so the bytes it told the caller to
	// assemble have to be a TDF.
	var body bytes.Buffer
	for _, idx := range indices {
		body.Write(encrypted[idx])
	}
	body.Write(fin.Data)

	reader, err := s.LoadTDF(bytes.NewReader(body.Bytes()),
		WithKasAllowlist([]string{kasBundle.url}),
	)

	// The specific defect: with no local file header the reader runs off
	// the end of the buffer parsing the ZIP structure, so the container
	// never opens. Anything else is some other test's business.
	require.NotErrorIs(t, err, io.ErrUnexpectedEOF,
		"Finalize succeeded but the assembled bytes are not a ZIP container")
	if err != nil {
		t.Logf("LoadTDF failed for an unrelated reason, not this test's subject: %v", err)
		return
	}

	plain, err := io.ReadAll(reader)
	require.NoError(t, err, "Finalize succeeded, so the payload must decrypt")
	assert.Equal(t, []byte("hello-world!"), plain)
}

// TestChunkedFinalizeRequiresSegmentZero pins the sentinel Finalize
// returns for a write set that omits segment 0, and that the rejection
// leaves the writer usable: the caller's only recovery is to write the
// missing segment and finalize again.
func TestChunkedFinalizeRequiresSegmentZero(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	encrypted := make(map[int][]byte, 3)
	write := func(index int, chunk string) {
		t.Helper()
		seg, err := w.WriteSegment(ctx, index, []byte(chunk))
		require.NoError(t, err)
		buf, err := io.ReadAll(seg.TDFData)
		require.NoError(t, err)
		encrypted[index] = buf
	}

	write(5, "hello-")
	write(6, "world!")

	_, err = w.Finalize(ctx)
	require.ErrorIs(t, err, ErrChunkedMissingSegmentZero)

	// A rejected Finalize must not consume the writer, or the caller has
	// no way back: the segments it already encrypted would be stranded.
	write(0, "zero-")
	fin, err := w.Finalize(ctx)
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, 3)

	var body bytes.Buffer
	for _, idx := range []int{0, 5, 6} {
		body.Write(encrypted[idx])
	}
	body.Write(fin.Data)

	reader, err := s.LoadTDF(bytes.NewReader(body.Bytes()),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("zero-hello-world!"), plain)
}

// TestChunkedFinalizeWithNoSegments verifies an untouched writer fails
// with the same sentinel rather than the archive layer's wrapped
// "segment missing".
func TestChunkedFinalizeWithNoSegments(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.Finalize(ctx)
	require.ErrorIs(t, err, ErrChunkedMissingSegmentZero)
}

// TestChunkedGetManifestWithoutSegmentZero guards the placement of the
// segment-0 check. GetManifest shares buildManifest with Finalize but
// is a pre-finalize snapshot, so it must keep working while segment 0
// is still outstanding.
func TestChunkedGetManifestWithoutSegmentZero(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 5, []byte("hello-"))
	require.NoError(t, err)
	_, err = w.WriteSegment(ctx, 6, []byte("world!"))
	require.NoError(t, err)

	snap, err := w.GetManifest(ctx)
	require.NoError(t, err)
	assert.Len(t, snap.Segments, 2)
}

// TestChunkedGetManifestBeforeFinalize verifies GetManifest returns a
// snapshot of the currently-written segments prior to Finalize and
// the frozen manifest afterwards.
func TestChunkedGetManifestBeforeFinalize(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("first"))
	require.NoError(t, err)
	_, err = w.WriteSegment(ctx, 1, []byte("second"))
	require.NoError(t, err)

	snap, err := w.GetManifest(ctx)
	require.NoError(t, err)
	require.NotNil(t, snap)
	assert.Len(t, snap.Segments, 2)

	fin, err := w.Finalize(ctx)
	require.NoError(t, err)

	frozen, err := w.GetManifest(ctx)
	require.NoError(t, err)
	assert.Equal(t, fin.Manifest.Method.Algorithm, frozen.Method.Algorithm)
	assert.Len(t, frozen.Segments, 2)
}

// writeChunkedSegments writes each element of segments as an ordered
// segment and returns the concatenated ciphertext produced by the
// writer.
func writeChunkedSegments(ctx context.Context, t *testing.T, w ChunkedWriter, segments [][]byte) []byte {
	t.Helper()
	var body bytes.Buffer
	for i, chunk := range segments {
		seg, err := w.WriteSegment(ctx, i, chunk)
		require.NoError(t, err)
		_, err = io.Copy(&body, seg.TDFData)
		require.NoError(t, err)
	}
	return body.Bytes()
}

// chunkedFakeKAS bundles an in-process RSA-2048 KAS + the httptest
// server it is registered on. Rewrap only handles the "wrapped"
// (RSA-OAEP) KeyType — matches what DefaultKeySplitter emits
// against an RSA-2048 KAS public key.
type chunkedFakeKAS struct {
	kasconnect.UnimplementedAccessServiceHandler
	privatePEM string
	publicPEM  string
	kid        string
	url        string
	server     *httptest.Server
}

// newChunkedFakeKAS starts an httptest server hosting a fake KAS with
// a freshly-generated RSA-2048 keypair.
func newChunkedFakeKAS(t *testing.T) *chunkedFakeKAS {
	t.Helper()
	pair, err := ocrypto.NewRSAKeyPair(2048)
	require.NoError(t, err)
	pubPEM, err := pair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privPEM, err := pair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	kas := &chunkedFakeKAS{
		privatePEM: privPEM,
		publicPEM:  pubPEM,
		kid:        "chunked-test-kid",
	}
	mux := http.NewServeMux()
	path, handler := kasconnect.NewAccessServiceHandler(kas)
	mux.Handle(path, handler)
	kas.server = httptest.NewServer(mux)
	kas.url = kas.server.URL
	return kas
}

// Rewrap unwraps every RSA-wrapped KAO under the KAS private key and
// re-wraps under the caller's session public key.
func (k *chunkedFakeKAS) Rewrap(_ context.Context, in *connect.Request[kaspb.RewrapRequest]) (*connect.Response[kaspb.RewrapResponse], error) {
	tok, err := jwt.ParseInsecure([]byte(in.Msg.GetSignedRequestToken()))
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}
	rawBody, ok := tok.Get("requestBody")
	if !ok {
		return nil, errors.New("requestBody missing from token")
	}
	bodyStr, ok := rawBody.(string)
	if !ok {
		return nil, errors.New("requestBody not a string")
	}
	body := kaspb.UnsignedRewrapRequest{}
	if err := protojson.Unmarshal([]byte(bodyStr), &body); err != nil {
		return nil, fmt.Errorf("unmarshal request body: %w", err)
	}

	dec, err := ocrypto.FromPrivatePEM(k.privatePEM)
	if err != nil {
		return nil, fmt.Errorf("kas priv: %w", err)
	}
	enc, err := ocrypto.FromPublicPEM(body.GetClientPublicKey())
	if err != nil {
		return nil, fmt.Errorf("client pub: %w", err)
	}

	resp := &kaspb.RewrapResponse{}
	for _, req := range body.GetRequests() {
		policyResult := &kaspb.PolicyRewrapResult{PolicyId: req.GetPolicy().GetId()}
		for _, kaoReq := range req.GetKeyAccessObjects() {
			kao := kaoReq.GetKeyAccessObject()
			if kao.GetKeyType() != kWrapped {
				return nil, fmt.Errorf("unsupported key type %q", kao.GetKeyType())
			}
			share, err := dec.Decrypt(kao.GetWrappedKey())
			if err != nil {
				return nil, fmt.Errorf("unwrap: %w", err)
			}
			wrapped, err := enc.Encrypt(share)
			if err != nil {
				return nil, fmt.Errorf("rewrap: %w", err)
			}
			policyResult.Results = append(policyResult.Results, &kaspb.KeyAccessRewrapResult{
				Result:            &kaspb.KeyAccessRewrapResult_KasWrappedKey{KasWrappedKey: wrapped},
				Status:            "permit",
				KeyAccessObjectId: kaoReq.GetKeyAccessObjectId(),
			})
		}
		resp.Responses = append(resp.Responses, policyResult)
	}
	return connect.NewResponse(resp), nil
}

// simpleKey returns the KAS descriptor the writer accepts.
func (k *chunkedFakeKAS) simpleKey() *policy.SimpleKasKey {
	return &policy.SimpleKasKey{
		KasUri: k.url,
		PublicKey: &policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       k.kid,
			Pem:       k.publicPEM,
		},
	}
}

// newChunkedTestSDK builds a minimal SDK value for these tests. It is
// constructed from package-private fields to skip New()'s
// platform-lookup requirement, since LoadTDF only needs conn and
// tokenSource.
//
// Deliberately not wired to the fake KAS: the SDK never learns the KAS
// address. Each key access object carries its own URL, so the reader
// reaches the fake through the manifest. Pass the fake's URL to
// WithChunkedDefaultKAS when writing and WithKasAllowlist when
// reading.
func newChunkedTestSDK(t *testing.T) SDK {
	t.Helper()
	ats := getTokenSource(t)
	return SDK{
		conn:        &ConnectRPCConnection{Client: http.DefaultClient},
		tokenSource: ats,
	}
}

// TestChunkedKAOShape pins the key access object fields the chunked
// writer emits, so they cannot silently drift from the ones
// SDK.CreateTDF produces via the shared createKeyAccess helper.
func TestChunkedKAOShape(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)
	writer, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("payload")})
	fin, err := writer.Finalize(ctx, WithChunkedEncryptedMetadata("meta"))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.KeyAccessObjs, 1)

	kao := fin.Manifest.KeyAccessObjs[0]
	assert.Equal(t, kWrapped, kao.KeyType)
	assert.Equal(t, kKasProtocol, kao.Protocol)
	assert.Equal(t, keyAccessSchemaVersion, kao.SchemaVersion)
	assert.Equal(t, kasBundle.url, kao.KasURL)
	assert.Equal(t, kasBundle.kid, kao.KID)
	assert.NotEmpty(t, kao.WrappedKey)
	assert.NotEmpty(t, kao.EncryptedMetadata)

	binding, ok := kao.PolicyBinding.(PolicyBinding)
	require.True(t, ok, "policy binding should be a PolicyBinding, got %T", kao.PolicyBinding)
	assert.Equal(t, hmacIntegrityAlgorithm, binding.Alg)
	assert.NotEmpty(t, binding.Hash)
}

// TestChunkedECKeyAccess covers the EC wrapping path, which the
// round-trip tests miss because the fake KAS is RSA-only. It asserts
// the manifest key type is the one the real KAS dispatches on
// ("ec-wrapped", not "eccWrapped") and that the wrapped key actually
// decrypts under the KAS private key using the AES-GCM envelope the
// KAS rewrap path expects.
func TestChunkedECKeyAccess(t *testing.T) {
	pair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	require.NoError(t, err)
	pubPEM, err := pair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privPEM, err := pair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	const kasURL = "https://kas.example.com"
	dek := make([]byte, kKeySize)
	for i := range dek {
		dek[i] = byte(i)
	}
	splits := &SplitResult{
		KASPublicKeys: map[string]KASPublicKey{
			kasURL: {
				Algorithm: string(ocrypto.EC256Key),
				KID:       "ec-kid",
				PEM:       pubPEM,
				URL:       kasURL,
			},
		},
		Splits: []Split{{Data: dek, KASURLs: []string{kasURL}}},
	}

	kaos, err := buildChunkedKeyAccessObjects(splits, []byte(`{"uuid":"test"}`), "")
	require.NoError(t, err)
	require.Len(t, kaos, 1)

	kao := kaos[0]
	assert.Equal(t, kECWrapped, kao.KeyType, "KAS dispatches on this exact string")
	require.NotEmpty(t, kao.EphemeralPublicKey)

	// Unwrap the way service/kas/access/rewrap.go does for "ec-wrapped".
	keySize, err := ocrypto.GetECKeySize([]byte(kao.EphemeralPublicKey))
	require.NoError(t, err)
	mode, err := ocrypto.ECSizeToMode(keySize)
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(kao.EphemeralPublicKey))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ecPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	compressed, err := ocrypto.CompressedECPublicKey(mode, *ecPub)
	require.NoError(t, err)

	priv, err := ocrypto.ECPrivateKeyFromPem([]byte(privPEM))
	require.NoError(t, err)
	dec, err := ocrypto.NewSaltedECDecryptor(priv, tdfSalt(), nil)
	require.NoError(t, err)

	wrapped, err := ocrypto.Base64Decode([]byte(kao.WrappedKey))
	require.NoError(t, err)
	unwrapped, err := dec.DecryptWithEphemeralKey(wrapped, compressed)
	require.NoError(t, err, "KAS must be able to unwrap the EC-wrapped DEK")
	assert.Equal(t, dek, unwrapped)
}

// TestChunkedLegacyTargetMode verifies that a pre-4.3.0 target mode
// produces the doubly-encoded (hex-then-base64) signatures that legacy
// readers require, and that the mainline reader -- which infers legacy
// mode solely from a missing schemaVersion -- still round-trips it.
func TestChunkedLegacyTargetMode(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
		WithChunkedTargetMode("4.2.2"),
	)
	require.NoError(t, err)

	body := writeChunkedSegments(ctx, t, writer, [][]byte{
		[]byte("legacy "), []byte("hex "), []byte("payload"),
	})
	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)

	// Absence of schemaVersion is the pre-4.3.0 marker readers key on.
	assert.Empty(t, fin.Manifest.TDFVersion, "legacy manifest must omit schemaVersion")

	// A legacy HS256 signature is base64(hex(hmac)): 32 HMAC bytes
	// rendered as 64 hex characters. The 4.3.0 form is base64(hmac),
	// which decodes to 32 bytes.
	rootSig, err := ocrypto.Base64Decode([]byte(fin.Manifest.Signature))
	require.NoError(t, err)
	assert.Len(t, rootSig, 64, "root signature must be hex-encoded before base64")

	for i, seg := range fin.Manifest.Segments {
		segSig, err := ocrypto.Base64Decode([]byte(seg.Hash))
		require.NoError(t, err)
		assert.Lenf(t, segSig, 64, "segment %d hash must be hex-encoded before base64", i)
	}

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("legacy hex payload"), plain)
}

// TestChunkedCurrentTargetMode pins the 4.3.0-and-later form so a
// regression in either direction is caught.
func TestChunkedCurrentTargetMode(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
		WithChunkedTargetMode("4.3.0"),
	)
	require.NoError(t, err)

	body := writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("current")})
	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)

	assert.Equal(t, TDFSpecVersion, fin.Manifest.TDFVersion)

	rootSig, err := ocrypto.Base64Decode([]byte(fin.Manifest.Signature))
	require.NoError(t, err)
	assert.Len(t, rootSig, 32, "root signature must be the raw HMAC, not hex")

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("current"), plain)
}

// TestChunkedExcludeVersionRequiresLegacyMode verifies that omitting
// schemaVersion without the matching signature encoding is refused
// rather than silently producing an unverifiable TDF.
func TestChunkedExcludeVersionRequiresLegacyMode(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)

	writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("mismatch")})

	_, err = writer.Finalize(ctx, WithChunkedExcludeVersion())
	require.ErrorIs(t, err, ErrChunkedVersionHexMismatch)
}

// TestChunkedTargetModeInvalid rejects a non-semver target mode at
// construction rather than at Finalize.
func TestChunkedTargetModeInvalid(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t)

	_, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
		WithChunkedTargetMode("not-a-version"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-version")
}

// chunkedSegmentShapes are segment-size sets fed to the chunked writer
// to exercise the reader's plaintext offset mapping. The non-uniform
// ones cannot be produced by SDK.CreateTDF, which always emits equal
// segments with a possibly-short tail.
func chunkedSegmentShapes() []struct {
	name  string
	sizes []int
} {
	return []struct {
		name  string
		sizes []int
	}{
		// Ascending: the manifest default comes from the smallest
		// segment, so a uniform mapping overshoots and indexes past the
		// decrypted bytes.
		{"ascending", []int{3, 5, 7}},
		// Descending: the default is the largest segment, so a uniform
		// mapping undershoots and lands inside the wrong segment --
		// wrong bytes, still in range, no error.
		{"descending", []int{7, 5, 3}},
		{"tiny-first", []int{1, 16, 1}},
		// A zero-length segment pins the boundary comparisons: it must
		// neither absorb a read that starts at its offset nor be
		// skipped in a way that shifts the ciphertext cursor.
		{"empty-middle", []int{4, 0, 4}},
		// Controls: shapes CreateTDF also produces.
		{"uniform", []int{5, 5, 5}},
		{"uniform-short-tail", []int{5, 5, 2}},
	}
}

// buildChunkedTDF writes one segment per entry in sizes and returns the
// assembled TDF bytes alongside the plaintext they encode.
func buildChunkedTDF(ctx context.Context, t *testing.T, s SDK, kasBundle *chunkedFakeKAS, sizes []int) ([]byte, []byte) {
	t.Helper()

	writer, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	total := 0
	for _, n := range sizes {
		total += n
	}
	plain := make([]byte, total)
	for i := range plain {
		plain[i] = byte('a' + i%26)
	}

	chunks := make([][]byte, 0, len(sizes))
	at := 0
	for _, n := range sizes {
		chunks = append(chunks, append([]byte(nil), plain[at:at+n]...))
		at += n
	}

	body := writeChunkedSegments(ctx, t, writer, chunks)
	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)

	return bytes.Join([][]byte{body, fin.Data}, nil), plain
}

// TestChunkedNonUniformReadAtSweep walks every (offset, length) pair
// against segment sets the chunked writer can emit but CreateTDF
// cannot. Reader.ReadAt used to map plaintext offsets with a single
// uniform DefaultSegmentSize, which silently returned wrong bytes for
// any non-uniform segment other than the last.
func TestChunkedNonUniformReadAtSweep(t *testing.T) {
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()
	s := newChunkedTestSDK(t)

	for _, shape := range chunkedSegmentShapes() {
		t.Run(shape.name, func(t *testing.T) {
			tdfBytes, plain := buildChunkedTDF(context.Background(), t, s, kasBundle, shape.sizes)
			size := int64(len(plain))

			reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
				WithKasAllowlist([]string{kasBundle.url}),
			)
			require.NoError(t, err)

			for offset := int64(0); offset <= size+1; offset++ {
				for length := 0; length <= len(plain)+3; length++ {
					buf := make([]byte, length)
					n, err := reader.ReadAt(buf, offset)

					where := fmt.Sprintf("offset=%d length=%d", offset, length)

					if offset > size {
						require.ErrorIs(t, err, ErrTDFPayloadReadFail, where)
						require.Equal(t, 0, n, where)
						continue
					}

					want := min(int64(length), size-offset)
					if offset+int64(length) > size {
						require.ErrorIs(t, err, io.EOF, where)
					} else {
						require.NoError(t, err, where)
					}
					require.Equal(t, int(want), n, where)
					require.Equal(t, plain[offset:offset+want], buf[:want], where)
				}
			}
		})
	}
}

// TestChunkedNonUniformReadAtEdges pins the boundary contract on one
// ascending shape, where every segment edge falls at a different
// multiple than the manifest default would predict.
func TestChunkedNonUniformReadAtEdges(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()
	s := newChunkedTestSDK(t)

	// Segment boundaries at 0, 3, 8, 15.
	tdfBytes, plain := buildChunkedTDF(ctx, t, s, kasBundle, []int{3, 5, 7})
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	// A zero-length read never reports EOF, including at the very end.
	for _, offset := range []int64{0, 3, 8, 15} {
		n, err := reader.ReadAt(nil, offset)
		require.NoError(t, err, "empty read at %d", offset)
		assert.Equal(t, 0, n)
	}

	// Reads that start exactly on a segment boundary and cover exactly
	// that segment.
	for _, tc := range []struct{ offset, length int64 }{{3, 5}, {8, 7}, {0, 3}} {
		buf := make([]byte, tc.length)
		n, err := reader.ReadAt(buf, tc.offset)
		require.NoError(t, err, "boundary read at %d", tc.offset)
		assert.Equal(t, int(tc.length), n)
		assert.Equal(t, plain[tc.offset:tc.offset+tc.length], buf)
	}

	// A read starting at the end yields nothing and EOF.
	n, err := reader.ReadAt(make([]byte, 1), 15)
	require.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 0, n)

	// Past the end, and negative, are rejected outright.
	_, err = reader.ReadAt(make([]byte, 1), 16)
	require.ErrorIs(t, err, ErrTDFPayloadReadFail)

	_, err = reader.ReadAt(make([]byte, 1), -1)
	require.ErrorIs(t, err, ErrTDFPayloadInvalidOffset)
}

// TestChunkedNonUniformSeekReadWriteTo checks that Seek, Read (which
// routes through ReadAt) and WriteTo agree with each other on
// non-uniform segments. WriteTo already walked cumulative sizes, so a
// disagreement here means the ReadAt mapping drifted from it.
func TestChunkedNonUniformSeekReadWriteTo(t *testing.T) {
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()
	s := newChunkedTestSDK(t)

	for _, shape := range chunkedSegmentShapes() {
		t.Run(shape.name, func(t *testing.T) {
			tdfBytes, plain := buildChunkedTDF(context.Background(), t, s, kasBundle, shape.sizes)

			load := func() *Reader {
				reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
					WithKasAllowlist([]string{kasBundle.url}),
				)
				require.NoError(t, err)
				return reader
			}

			for k := 0; k <= len(plain); k++ {
				reader := load()
				pos, err := reader.Seek(int64(k), io.SeekStart)
				require.NoError(t, err)
				require.Equal(t, int64(k), pos)

				got, err := io.ReadAll(reader)
				require.NoError(t, err, "ReadAll from %d", k)
				assert.Equal(t, plain[k:], got, "ReadAll from %d", k)

				reader = load()
				_, err = reader.Seek(int64(k), io.SeekStart)
				require.NoError(t, err)

				var out bytes.Buffer
				written, err := reader.WriteTo(&out)
				require.NoError(t, err, "WriteTo from %d", k)
				// Compared as strings: an empty bytes.Buffer reports a
				// nil slice, which is not Equal to an empty one.
				assert.Equal(t, string(plain[k:]), out.String(), "WriteTo from %d", k)
				assert.Equal(t, int64(len(plain)-k), written, "WriteTo from %d", k)
			}
		})
	}
}

// errArchiveWriteFailed is the injected archive failure used to drive
// WriteSegment's error paths.
var errArchiveWriteFailed = errors.New("archive write failed")

// flakyArchiveWriter fails the first failures writes of one chosen
// segment index and delegates everything else to a real segment
// writer, so the archive itself stays consistent.
type flakyArchiveWriter struct {
	zipstream.SegmentWriter
	failIndex int
	failures  int
}

func (f *flakyArchiveWriter) WriteSegment(ctx context.Context, index int, size uint64, crc32 uint32) ([]byte, error) {
	if index == f.failIndex && f.failures > 0 {
		f.failures--
		return nil, errArchiveWriteFailed
	}
	return f.SegmentWriter.WriteSegment(ctx, index, size, crc32)
}

// TestChunkedArchiveFailureKeepsManifestHonest checks that a segment
// whose bytes never reached the archive is not described in the
// manifest. WriteSegment used to publish the segment metadata before
// handing the bytes to the archive, so Finalize emitted a manifest
// covering a payload the archive had rejected and the caller never
// received: the reader then mapped every later segment at the wrong
// payload offset.
//
// Skipping the index rather than retrying it is legal here — segment
// indices are ordering keys, not positions, so a sparse set finalizes
// normally (see segmentOrderLocked). Only index 0 is special, because
// it carries the ZIP local file header.
func TestChunkedArchiveFailureKeepsManifestHonest(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()
	s := newChunkedTestSDK(t)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
		WithChunkedArchiveWriterFactory(func(clock Clock) zipstream.SegmentWriter {
			return &flakyArchiveWriter{
				SegmentWriter: DefaultArchiveWriterFactory(clock),
				failIndex:     1,
				failures:      1,
			}
		}),
	)
	require.NoError(t, err)

	var body bytes.Buffer
	write := func(index int, chunk string) error {
		seg, err := writer.WriteSegment(ctx, index, []byte(chunk))
		if err != nil {
			return err
		}
		_, err = io.Copy(&body, seg.TDFData)
		return err
	}

	require.NoError(t, write(0, "first "))

	// Rejected by the archive, so the caller gets no bytes to append.
	require.ErrorIs(t, write(1, "second "), errArchiveWriteFailed)

	require.NoError(t, write(2, "third"))

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	body.Write(fin.Data)

	require.Len(t, fin.Manifest.Segments, 2,
		"manifest must not describe the segment the archive rejected")

	reader, err := s.LoadTDF(bytes.NewReader(body.Bytes()),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "first third", string(plain))
}

// TestChunkedSegmentRetryAfterArchiveFailure checks that a failed write
// releases its index. WriteSegment used to reserve the index up front
// and never release it, so a single transient failure made the index
// permanently unwritable and left the writer unable to finalize.
func TestChunkedSegmentRetryAfterArchiveFailure(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()
	s := newChunkedTestSDK(t)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
		WithChunkedArchiveWriterFactory(func(clock Clock) zipstream.SegmentWriter {
			return &flakyArchiveWriter{
				SegmentWriter: DefaultArchiveWriterFactory(clock),
				failIndex:     1,
				failures:      1,
			}
		}),
	)
	require.NoError(t, err)

	var body bytes.Buffer
	write := func(index int, chunk string) error {
		seg, err := writer.WriteSegment(ctx, index, []byte(chunk))
		if err != nil {
			return err
		}
		_, err = io.Copy(&body, seg.TDFData)
		require.NoError(t, err)
		return nil
	}

	require.NoError(t, write(0, "hello, "))

	err = write(1, "chunked ")
	require.ErrorIs(t, err, errArchiveWriteFailed)

	// The same index must be usable again.
	require.NoError(t, write(1, "chunked "), "a failed segment must be retryable")
	require.NoError(t, write(2, "world!"))

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)

	tdfBytes := bytes.Join([][]byte{body.Bytes(), fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello, chunked world!"), plain)
}

// TestChunkedOptionsRejectNil checks that the injection-seam options
// refuse a nil value instead of storing it. A stored nil is
// indistinguishable from an unset field, so no default gets installed
// and the nil surfaces as a panic partway through writing -- for the
// key splitter, not until Finalize, after the caller has already
// encrypted and uploaded every segment.
func TestChunkedOptionsRejectNil(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()
	s := newChunkedTestSDK(t)

	for _, tc := range []struct {
		name string
		opt  ChunkedWriterOption
	}{
		{"archive writer factory", WithChunkedArchiveWriterFactory(nil)},
		{"cipher factory", WithChunkedCipherFactory(nil)},
		{"clock", WithChunkedClock(nil)},
		{"key splitter", WithChunkedKeySplitter(nil)},
		{"rand", WithChunkedRand(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer, err := s.NewChunkedWriter(ctx,
				WithChunkedDefaultKAS(kasBundle.simpleKey()),
				tc.opt,
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must not be nil")
			assert.Nil(t, writer)
		})
	}
}

// TestChunkedConcurrentWrites exercises the contract WriteSegment
// documents but nothing tested: distinct indices may be written
// concurrently. Every other out-of-order test drives a single
// goroutine, so -race never saw the locking around w.mu, and neither
// the reservation nor the rollback path was observed under contention.
func TestChunkedConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()
	s := newChunkedTestSDK(t)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)

	const segments = 16
	chunks := make([][]byte, segments)
	var want bytes.Buffer
	for i := range chunks {
		chunks[i] = []byte(fmt.Sprintf("segment-%02d;", i))
		want.Write(chunks[i])
	}

	// Index-keyed slices, so the goroutines share no mutable state of
	// this test's own making and any race -race reports belongs to the
	// writer.
	segBytes := make([][]byte, segments)
	errs := make([]error, segments)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range segments {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // widen the window in which the writes overlap
			seg, err := writer.WriteSegment(ctx, i, chunks[i])
			if err != nil {
				errs[i] = err
				return
			}
			segBytes[i], errs[i] = io.ReadAll(seg.TDFData)
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "segment %d", i)
	}

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	require.Equal(t, segments, fin.TotalSegments)

	// Concatenation is in index order regardless of write order.
	var body bytes.Buffer
	for _, buf := range segBytes {
		body.Write(buf)
	}
	body.Write(fin.Data)

	reader, err := s.LoadTDF(bytes.NewReader(body.Bytes()),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, want.String(), string(plain))
}

// TestChunkedConcurrentDuplicateIndex checks the other half of the
// contract: when several goroutines race on one index, exactly one
// wins and the rest are rejected. The reservation is what makes this
// deterministic, so it is worth pinning under -race.
func TestChunkedConcurrentDuplicateIndex(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()
	s := newChunkedTestSDK(t)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)

	const racers = 8
	errs := make([]error, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = writer.WriteSegment(ctx, 0, []byte("contested"))
		}()
	}
	close(start)
	wg.Wait()

	var won int
	for i, err := range errs {
		if err == nil {
			won++
			continue
		}
		require.ErrorIs(t, err, ErrChunkedSegmentAlreadyWritten, "racer %d", i)
	}
	assert.Equal(t, 1, won, "exactly one writer may claim an index")
}
