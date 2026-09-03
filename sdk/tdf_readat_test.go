package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"math/rand"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/internal/zipstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonUniformSegmentShapes are segment-size sets used to exercise the reader's
// plaintext offset mapping. The non-uniform ones cannot be produced by
// SDK.CreateTDF, which always emits equal segments with a possibly-short tail,
// but sdk/experimental/tdf does emit them and the format permits them.
func nonUniformSegmentShapes() []struct {
	name  string
	sizes []int
} {
	return []struct {
		name  string
		sizes []int
	}{
		// Ascending: the default is taken from the first segment, which here is
		// also the smallest, so a uniform stride overshoots -- it picks a later
		// segment than the offset belongs to and indexes past what decrypted.
		{"ascending", []int{3, 5, 7}},
		// Descending: the default is the first and largest segment, so a
		// uniform stride undershoots. Depending on the offset that is either
		// wrong bytes with no error or an index past the decrypted payload.
		{"descending", []int{7, 5, 3}},
		{"tiny-first", []int{1, 16, 1}},
		// A zero-length segment pins the boundary comparisons: it must not
		// absorb a read that starts at its offset, and skipping it must still
		// advance the ciphertext cursor, since an empty segment is still a
		// nonce and a tag on the wire.
		{"empty-middle", []int{4, 0, 4}},
		// Controls: shapes CreateTDF also produces.
		{"uniform", []int{5, 5, 5}},
		{"uniform-short-tail", []int{5, 5, 2}},
	}
}

// newNonUniformReader assembles a TDF whose payload holds one segment per entry
// in sizes, then returns a Reader over it along with the plaintext it encodes.
//
// The archive is built directly on internal/zipstream rather than through
// CreateTDF, which cannot emit segments of differing sizes. The payload key is
// planted on the Reader so no key unwrap -- and so no KAS -- is involved; the
// manifest carries no key access objects.
func newNonUniformReader(t *testing.T, sizes []int) (*Reader, []byte) {
	t.Helper()
	ctx := t.Context()

	key, err := ocrypto.RandomBytes(kKeySize)
	require.NoError(t, err)
	aesGcm, err := ocrypto.NewAESGcm(key)
	require.NoError(t, err)

	total := 0
	for _, n := range sizes {
		total += n
	}
	plain := make([]byte, total)
	for i := range plain {
		plain[i] = byte('a' + i%26)
	}

	archive := zipstream.NewSegmentTDFWriter(len(sizes))
	var body bytes.Buffer
	segments := make([]Segment, 0, len(sizes))

	at := 0
	for i, n := range sizes {
		cipherText, err := aesGcm.Encrypt(plain[at : at+n])
		require.NoError(t, err)
		at += n

		hdr, err := archive.WriteSegment(ctx, i, uint64(len(cipherText)), crc32.ChecksumIEEE(cipherText))
		require.NoError(t, err)
		body.Write(hdr)
		body.Write(cipherText)

		sig, err := calculateSignature(cipherText, key, HS256, false)
		require.NoError(t, err)

		segments = append(segments, Segment{
			Hash:          string(ocrypto.Base64Encode([]byte(sig))),
			Size:          int64(n),
			EncryptedSize: int64(len(cipherText)),
		})
	}

	manifest := Manifest{
		TDFVersion: TDFSpecVersion,
		Payload: Payload{
			Type:        "reference",
			URL:         "0.payload",
			Protocol:    "zip",
			MimeType:    "application/octet-stream",
			IsEncrypted: true,
		},
	}
	manifest.KeyAccessType = "split"
	manifest.IntegrityInformation = IntegrityInformation{
		SegmentHashAlgorithm: "HS256",
		// A writer emitting non-uniform segments still has to declare some
		// default. Reporting the first segment's size is the natural choice,
		// and whatever is declared here is the stride the old mapping stepped
		// by for every segment.
		DefaultSegmentSize:      segments[0].Size,
		DefaultEncryptedSegSize: segments[0].EncryptedSize,
		Segments:                segments,
	}

	manifestJSON, err := json.Marshal(manifest)
	require.NoError(t, err)

	trailer, err := archive.Finalize(ctx, manifestJSON)
	require.NoError(t, err)
	body.Write(trailer)

	tdfReader, err := zipstream.NewTDFReader(bytes.NewReader(body.Bytes()))
	require.NoError(t, err)

	return &Reader{
		manifest:    manifest,
		tdfReader:   tdfReader,
		payloadSize: int64(total),
		aesGcm:      aesGcm,
		payloadKey:  key,
	}, plain
}

// TestReaderReadAtNonUniform walks every (offset, length) pair against segment
// sets that CreateTDF cannot emit but the format allows. Reader.ReadAt used to
// map plaintext offsets with a single uniform DefaultSegmentSize stride, which
// on these shapes either returned the wrong bytes with no error or indexed past
// the decrypted payload, depending on whether the declared default over- or
// under-states the segment the offset really falls in.
func TestReaderReadAtNonUniform(t *testing.T) {
	for _, shape := range nonUniformSegmentShapes() {
		t.Run(shape.name, func(t *testing.T) {
			reader, plain := newNonUniformReader(t, shape.sizes)
			size := int64(len(plain))

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

// TestReaderReadAtNonUniformEdges pins the boundary contract on one ascending
// shape. Its declared default is 3, so the interior edge at 8 falls off the
// stride a uniform mapping would step by.
func TestReaderReadAtNonUniformEdges(t *testing.T) {
	// Segment boundaries at 0, 3, 8, 15.
	reader, plain := newNonUniformReader(t, []int{3, 5, 7})

	// A zero-length read never reports EOF, including at the very end.
	for _, offset := range []int64{0, 3, 8, 15} {
		n, err := reader.ReadAt(nil, offset)
		require.NoError(t, err, "empty read at %d", offset)
		assert.Equal(t, 0, n)
	}

	// Reads that start exactly on a segment boundary and cover exactly that
	// segment.
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

// TestReaderReadAtDeclaredSizeMismatch checks that a manifest whose declared
// segment sizes disagree with the AES-GCM framing is rejected rather than
// trusted.
//
// Nothing authenticates Segment.Size: the root signature aggregates only each
// segment's Hash, and the schema types the size as a bare number. ReadAt derives
// every plaintext offset from those sizes, so an altered Size shifts the mapping
// -- and because a segment before the requested offset is skipped rather than
// decrypted, checking the length that comes back from Decrypt is not enough on
// its own to catch it.
func TestReaderReadAtDeclaredSizeMismatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(segments []Segment)
		wantErr error
	}{
		// Understating the first segment shifts every later segment down by
		// five bytes. The read below starts past that segment, so it is skipped
		// and never decrypted.
		{"understated", func(segments []Segment) { segments[0].Size = 5 }, ErrSegSizeMismatch},
		{"overstated", func(segments []Segment) { segments[0].Size = 40 }, ErrSegSizeMismatch},
		// Sizes that sum back to something plausible: payloadSize is the sum of
		// every Size, so a pair that overflows to a small positive total gets
		// past the range check on offset and reaches the segment walk. A
		// negative declared Size is caught by resolveSegmentSizes itself,
		// before the arithmetic consistency check below it ever runs.
		{"negative", func(segments []Segment) {
			segments[0].Size = math.MinInt64 + 1
			segments[1].Size = math.MinInt64 + 7
		}, ErrSegSizeUnresolved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader, _ := newNonUniformReader(t, []int{10, 10, 10})
			tc.mutate(reader.manifest.Segments)

			// Mirror what LoadTDF derives from the tampered manifest.
			var payloadSize int64
			for _, seg := range reader.manifest.Segments {
				payloadSize += seg.Size
			}
			reader.payloadSize = payloadSize

			// The request spans the tampered segment and the one after it, so a
			// reader that trusted Size would report a full 20 bytes of shifted
			// plaintext rather than an error.
			n, err := reader.ReadAt(make([]byte, 20), 5)
			require.ErrorIs(t, err, tc.wantErr)
			assert.Zero(t, n)
		})
	}
}

// TestReaderNonUniformSeekReadWriteTo checks that Seek, Read (which routes
// through ReadAt) and WriteTo agree with each other on non-uniform segments.
// WriteTo already walked cumulative sizes, so a disagreement here means the
// ReadAt mapping drifted from it.
func TestReaderNonUniformSeekReadWriteTo(t *testing.T) {
	for _, shape := range nonUniformSegmentShapes() {
		t.Run(shape.name, func(t *testing.T) {
			reader, plain := newNonUniformReader(t, shape.sizes)
			for k := 0; k <= len(plain); k++ {
				pos, err := reader.Seek(int64(k), io.SeekStart)
				require.NoError(t, err)
				require.Equal(t, int64(k), pos)

				got, err := io.ReadAll(reader)
				require.NoError(t, err, "ReadAll from %d", k)
				assert.Equal(t, plain[k:], got, "ReadAll from %d", k)

				_, err = reader.Seek(int64(k), io.SeekStart)
				require.NoError(t, err)

				var out bytes.Buffer
				written, err := reader.WriteTo(&out)
				require.NoError(t, err, "WriteTo from %d", k)
				// Compared as strings: an empty bytes.Buffer reports a nil
				// slice, which is not Equal to an empty one.
				assert.Equal(t, string(plain[k:]), out.String(), "WriteTo from %d", k)
				assert.Equal(t, int64(len(plain)-k), written, "WriteTo from %d", k)
			}
		})
	}
}

// CreateTDF clamps WithSegmentSize up to minSegmentSize, so a payload has to run
// to several multiples of that constant before it spans more than one segment.
// These dimensions give four segments -- three full ones and a short tail --
// which puts two interior boundaries in play, so a mapping that only gets the
// first one right still fails, and leaves a final segment whose Size differs
// from DefaultSegmentSize.
const (
	readAtSegSize     = minSegmentSize
	readAtTailSize    = 137 // neither a divisor nor a multiple of readAtSegSize
	readAtSegCount    = 4
	readAtPayloadSize = 3*readAtSegSize + readAtTailSize
	readAtPayloadSeed = 20260902
)

// readAtSweepPayload returns a deterministic payload with no repeating
// structure. A payload of identical bytes, or one cycling over a short alphabet,
// would let a read that lands at the wrong offset still compare equal to the
// bytes it was supposed to return.
func readAtSweepPayload() []byte {
	src := rand.New(rand.NewSource(readAtPayloadSeed))
	plain := make([]byte, readAtPayloadSize)
	for i := range plain {
		plain[i] = byte(src.Uint64())
	}
	return plain
}

// newMultiSegmentTDF builds a multi-segment TDF through the ordinary CreateTDF
// path and returns a Reader over it along with the plaintext it encodes.
func (s *TDFSuite) newMultiSegmentTDF() (*Reader, []byte) {
	plain := readAtSweepPayload()

	var tdfBuf bytes.Buffer
	_, err := s.sdk.CreateTDF(
		&tdfBuf,
		bytes.NewReader(plain),
		// Deliberately no PublicKey, so loading has to fetch the key from the
		// fake KAS. That covers LoadTDF -> doPayloadKeyUnwrap -> ReadAt, which
		// the hand-assembled readers above cannot reach.
		WithKasInformation(KASInfo{URL: s.kasTestURLLookup["http://localhost:65432/"]}),
		WithSegmentSize(readAtSegSize),
	)
	s.Require().NoError(err)

	reader, err := s.sdk.LoadTDF(bytes.NewReader(tdfBuf.Bytes()))
	s.Require().NoError(err)

	// Pin the shape. Without this the test degenerates silently -- and stops
	// exercising segment boundaries at all -- if minSegmentSize or the
	// WithSegmentSize clamp ever moves.
	s.Require().Len(reader.manifest.Segments, readAtSegCount)
	s.Require().Equal(int64(readAtSegSize), reader.manifest.DefaultSegmentSize)
	s.Require().Equal(int64(readAtTailSize), reader.manifest.Segments[readAtSegCount-1].Size)

	return reader, plain
}

// Test_TDFReaderReadAtBoundaries samples ReadAt around every segment boundary of
// a multi-segment TDF. Mapping a plaintext offset onto a segment is easy to get
// wrong by one segment at the edges, so each boundary is probed one byte short
// of, exactly on, and one byte past it, against lengths that stop inside the
// segment, land exactly on the next boundary, and span several segments. The
// returned bytes, the count and the io.EOF/error contract are all pinned.
func (s *TDFSuite) Test_TDFReaderReadAtBoundaries() {
	reader, plain := s.newMultiSegmentTDF()
	size := int64(len(plain))

	// Cumulative plaintext boundaries, read back from the manifest so the probe
	// follows whatever shape CreateTDF produced: 0, 16384, 32768, 49152, 49289.
	edges := []int64{0}
	for _, seg := range reader.manifest.Segments {
		edges = append(edges, edges[len(edges)-1]+seg.Size)
	}

	// The tail is longer than two bytes, so no two of these windows overlap and
	// every offset stays distinct.
	var offsets []int64
	for _, edge := range edges {
		for _, delta := range []int64{-1, 0, 1} {
			if edge+delta >= 0 {
				offsets = append(offsets, edge+delta)
			}
		}
	}

	lengths := []int64{
		0, 1, 2, readAtTailSize,
		readAtSegSize - 1, readAtSegSize, readAtSegSize + 1,
		readAtSegSize + readAtTailSize, size,
	}

	for _, offset := range offsets {
		lens := lengths
		// Reading exactly to the end, and one byte past it. Guarded because the
		// last offset is past the end, where the remainder is negative and
		// make([]byte, rem) would panic before ReadAt could reject the offset.
		if rem := size - offset; rem >= 0 {
			lens = append(append([]int64(nil), lengths...), rem, rem+1)
		}

		for _, length := range lens {
			buf := make([]byte, length)
			n, err := reader.ReadAt(buf, offset)

			where := fmt.Sprintf("offset=%d length=%d", offset, length)

			if offset > size {
				s.Require().ErrorIs(err, ErrTDFPayloadReadFail, where)
				s.Require().Equal(0, n, where)
				continue
			}

			want := min(length, size-offset)
			if offset+length > size {
				s.Require().ErrorIs(err, io.EOF, where)
			} else {
				s.Require().NoError(err, where)
			}
			s.Require().Equal(int(want), n, where)
			s.Require().Equal(plain[offset:offset+want], buf[:want], where)
		}
	}
}

// Test_TDFReaderMultiSegmentSeekReadWriteTo checks that Read, which routes
// through ReadAt, and WriteTo agree on a multi-segment payload. WriteTo walks
// cumulative segment sizes on its own, so a disagreement means one of the two
// mappings drifted from the other.
func (s *TDFSuite) Test_TDFReaderMultiSegmentSeekReadWriteTo() {
	reader, plain := s.newMultiSegmentTDF()
	size := int64(len(plain))

	for _, start := range []int64{0, 1, readAtSegSize - 1, readAtSegSize, size - readAtTailSize, size} {
		_, err := reader.Seek(start, io.SeekStart)
		s.Require().NoError(err)

		got, err := io.ReadAll(reader)
		s.Require().NoError(err, "ReadAll from %d", start)
		s.Require().Equal(plain[start:], got, "ReadAll from %d", start)

		_, err = reader.Seek(start, io.SeekStart)
		s.Require().NoError(err)

		var out bytes.Buffer
		written, err := reader.WriteTo(&out)
		s.Require().NoError(err, "WriteTo from %d", start)
		s.Require().Equal(size-start, written, "WriteTo from %d", start)
		// Compared as strings: an empty bytes.Buffer reports a nil slice, which
		// is not Equal to an empty one.
		s.Require().Equal(string(plain[start:]), out.String(), "WriteTo from %d", start)
	}
}
