// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OpenTDF writers only emit STORED entries, but other TDF writers compress
// entries with DEFLATE (method 8). These tests cover reading those archives,
// which goes through archive/zip, so its errors are the ones expected here:
// ErrFormat for data past the declared size, io.ErrUnexpectedEOF for data
// short of it, ErrChecksum for a CRC-32 mismatch.

// deflateRaw compresses data as a raw DEFLATE stream, the form APPNOTE
// compression method 8 stores (no zlib or gzip framing).
func deflateRaw(t testing.TB, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)
	_, err = w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// deflatedEntry returns a method 8 entry holding plain and declaring its true
// uncompressed size and CRC-32. Callers lie about either by editing the field.
func deflatedEntry(t testing.TB, name string, plain []byte) rawZipEntry {
	t.Helper()

	return rawZipEntry{
		name:             name,
		data:             deflateRaw(t, plain),
		method:           zip.Deflate,
		uncompressedSize: uint64(len(plain)),
		crc32:            crc32.ChecksumIEEE(plain),
	}
}

// compressibleBytes returns n reproducible bytes drawn from a small alphabet:
// they deflate to well under their size, yet never repeat with a short period,
// so a read served from the wrong uncompressed offset cannot match by chance.
func compressibleBytes(n int) []byte {
	rng := rand.New(rand.NewPCG(uint64(n), 0x5eed))
	const alphabet = "abcdefgh"
	out := make([]byte, n)
	for i := range out {
		out[i] = alphabet[rng.IntN(len(alphabet))]
	}
	return out
}

// randomBytes returns n reproducible bytes that DEFLATE cannot shrink.
func randomBytes(n int) []byte {
	rng := rand.New(rand.NewPCG(uint64(n), 0xb0b))
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(rng.Uint32())
	}
	return out
}

// byteCountingSeeker tallies the bytes read through it, so a test can tell
// how much of an archive a call actually consumed.
type byteCountingSeeker struct {
	io.ReadSeeker
	n int64
}

func (c *byteCountingSeeker) Read(p []byte) (int, error) {
	n, err := c.ReadSeeker.Read(p)
	c.n += int64(n)
	return n, err
}

func TestReaderDeflatedEntry(t *testing.T) {
	plain := compressibleBytes(100 * oneKB)
	stored := []byte("a stored entry read between deflated reads")

	entry := deflatedEntry(t, "deflated.bin", plain)
	require.Less(t, len(entry.data), len(plain), "fixture must actually compress")

	data := buildRawZip(t, []rawZipEntry{entry, {name: "stored.bin", data: stored}}, false)
	reader, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	// The logical size is the uncompressed one.
	size, err := reader.ReadFileSize("deflated.bin")
	require.NoError(t, err)
	assert.Equal(t, int64(len(plain)), size)

	got, err := reader.ReadAllFileData("deflated.bin", oneMB)
	require.NoError(t, err)
	assert.Equal(t, plain, got)

	// Sequential reads in uncompressed coordinates, with a read of another
	// entry between each: they share the ReadSeeker, so the inflater must not
	// depend on where the last read left it.
	const chunk = 7 * oneKB
	for off := 0; off < len(plain); off += chunk {
		n := min(chunk, len(plain)-off)
		part, err := reader.ReadFileData("deflated.bin", int64(off), int64(n))
		require.NoError(t, err)
		require.Equal(t, plain[off:off+n], part, "chunk at %d", off)

		other, err := reader.ReadAllFileData("stored.bin", oneMB)
		require.NoError(t, err)
		require.Equal(t, stored, other)
	}

	// Reads are bounded by the uncompressed size, not the compressed one.
	_, err = reader.ReadFileData("deflated.bin", int64(len(plain)), 1)
	require.ErrorIs(t, err, errZipFileSizeError)
	got, err = reader.ReadFileData("deflated.bin", int64(len(plain)), 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestTDFReaderDeflatedEntries(t *testing.T) {
	payload := compressibleBytes(50 * oneKB)

	for _, manifestName := range []string{TDFManifestFileNameSpec, TDFManifestFileName} {
		for _, tc := range []struct {
			name            string
			deflateManifest bool
			deflatePayload  bool
		}{
			{"both stored", false, false},
			{"both deflated", true, true},
			{"stored manifest, deflated payload", false, true},
			{"deflated manifest, stored payload", true, false},
		} {
			t.Run(manifestName+"/"+tc.name, func(t *testing.T) {
				payloadEntry := rawZipEntry{name: TDFPayloadFileName, data: payload}
				if tc.deflatePayload {
					payloadEntry = deflatedEntry(t, TDFPayloadFileName, payload)
				}
				manifestEntry := rawZipEntry{name: manifestName, data: []byte(testManifest)}
				if tc.deflateManifest {
					manifestEntry = deflatedEntry(t, manifestName, []byte(testManifest))
				}

				data := buildRawZip(t, []rawZipEntry{payloadEntry, manifestEntry}, false)
				reader, err := NewTDFReader(bytes.NewReader(data))
				require.NoError(t, err)

				manifest, err := reader.Manifest()
				require.NoError(t, err)
				require.JSONEq(t, testManifest, manifest)

				size, err := reader.PayloadSize()
				require.NoError(t, err)
				require.Equal(t, int64(len(payload)), size)

				// Segments in reverse, the order hardest on a forward cursor.
				const segment = 3 * oneKB
				for off := (len(payload) - 1) / segment * segment; off >= 0; off -= segment {
					n := min(segment, len(payload)-off)
					got, err := reader.ReadPayload(int64(off), int64(n))
					require.NoError(t, err)
					require.Equal(t, payload[off:off+n], got, "segment at %d", off)
				}
			})
		}
	}
}

func TestReaderRejectsUnsupportedCompression(t *testing.T) {
	for _, method := range []uint16{1, 6, 9, 12, 14, 93, 95, 98, 99} {
		t.Run(strconv.Itoa(int(method)), func(t *testing.T) {
			data := buildRawZip(t, []rawZipEntry{
				{name: TDFPayloadFileName, data: []byte("payload bytes"), method: method, uncompressedSize: 13},
				{name: TDFManifestFileName, data: []byte(testManifest)},
			}, false)

			_, err := NewReader(bytes.NewReader(data))
			require.ErrorIs(t, err, zip.ErrAlgorithm)
			// The message has to say which entry and which method.
			require.ErrorContains(t, err, TDFPayloadFileName)
			require.ErrorContains(t, err, "method "+strconv.Itoa(int(method)))

			_, err = NewTDFReader(bytes.NewReader(data))
			require.ErrorIs(t, err, zip.ErrAlgorithm)
		})
	}

	// The manifest is checked the same way as the payload.
	data := buildRawZip(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
		{name: TDFManifestFileNameSpec, data: []byte(testManifest), method: 12, uncompressedSize: 99},
	}, false)
	_, err := NewTDFReader(bytes.NewReader(data))
	require.ErrorIs(t, err, zip.ErrAlgorithm)
	require.ErrorContains(t, err, TDFManifestFileNameSpec)
	require.ErrorContains(t, err, "method 12")
}

// A declared size below the real inflated length: a reader that trusted the
// stream rather than the header would hand back more than the entry claims.
func TestReaderDeflatedDeclaredSizeSmallerThanData(t *testing.T) {
	plain := compressibleBytes(10 * oneKB)
	declared := len(plain) / 2

	entry := deflatedEntry(t, "short.bin", plain)
	entry.uncompressedSize = uint64(declared)
	reader, err := NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{entry}, false)))
	require.NoError(t, err)

	size, err := reader.ReadFileSize("short.bin")
	require.NoError(t, err)
	require.Equal(t, int64(declared), size)

	got, err := reader.ReadAllFileData("short.bin", oneMB)
	require.ErrorIs(t, err, zip.ErrFormat)
	assert.Nil(t, got, "no data may accompany a read error")

	// A read that reaches the declared end finds the extra data.
	for _, r := range [][2]int{{0, declared}, {declared - 1, 1}} {
		part, err := reader.ReadFileData("short.bin", int64(r[0]), int64(r[1]))
		require.ErrorIs(t, err, zip.ErrFormat, "read of %d at %d", r[1], r[0])
		assert.Nil(t, part)
	}

	// One that stops short of it cannot know yet, and returns what it read.
	got, err = reader.ReadFileData("short.bin", 0, 100)
	require.NoError(t, err)
	assert.Equal(t, plain[:100], got)
}

// A declared size above the real inflated length: the reader must report the
// shortfall rather than padding or returning a short buffer.
func TestReaderDeflatedDeclaredSizeLargerThanData(t *testing.T) {
	plain := compressibleBytes(10 * oneKB)
	declared := 2 * len(plain)

	entry := deflatedEntry(t, "long.bin", plain)
	entry.uncompressedSize = uint64(declared)
	reader, err := NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{entry}, false)))
	require.NoError(t, err)

	got, err := reader.ReadAllFileData("long.bin", oneMB)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Nil(t, got, "no data may accompany a read error")

	for _, r := range [][2]int{{0, declared}, {len(plain) - 1, 2}, {len(plain), 1}, {declared - 1, 1}} {
		part, err := reader.ReadFileData("long.bin", int64(r[0]), int64(r[1]))
		require.ErrorIs(t, err, io.ErrUnexpectedEOF, "read of %d at %d", r[1], r[0])
		assert.Nil(t, part)
	}

	// A read that stops well short of where the data runs out still succeeds.
	// One that reaches it may not: archive/zip reports the shortfall as soon
	// as the stream ends, discarding the final chunk.
	got, err = reader.ReadFileData("long.bin", 0, 100)
	require.NoError(t, err)
	assert.Equal(t, plain[:100], got)
}

func TestReaderDeflatedEmptyEntry(t *testing.T) {
	entry := deflatedEntry(t, "empty.bin", nil)
	require.NotEmpty(t, entry.data, "an empty DEFLATE stream still has a final block")

	reader, err := NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{entry}, false)))
	require.NoError(t, err)

	size, err := reader.ReadFileSize("empty.bin")
	require.NoError(t, err)
	require.Zero(t, size)

	got, err := reader.ReadAllFileData("empty.bin", oneMB)
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = reader.ReadFileData("empty.bin", 0, 0)
	require.NoError(t, err)
	assert.Empty(t, got)

	// Declaring zero bytes over a stream that holds some is a mismatch.
	entry = deflatedEntry(t, "notempty.bin", []byte("not empty"))
	entry.uncompressedSize = 0
	reader, err = NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{entry}, false)))
	require.NoError(t, err)
	_, err = reader.ReadAllFileData("notempty.bin", oneMB)
	require.ErrorIs(t, err, zip.ErrFormat)
	// An empty read at the declared end reaches the end, so it is checked too.
	_, err = reader.ReadFileData("notempty.bin", 0, 0)
	require.ErrorIs(t, err, zip.ErrFormat)
}

func TestReaderDeflatedCorruptData(t *testing.T) {
	plain := compressibleBytes(20 * oneKB)
	compressed := deflateRaw(t, plain)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"truncated stream", compressed[:len(compressed)/2]},
		{"not deflate", bytes.Repeat([]byte{0xFF}, 64)},
		{"no data", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := rawZipEntry{
				name: "corrupt.bin", data: tc.data,
				method: zip.Deflate, uncompressedSize: uint64(len(plain)),
			}
			reader, err := NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{entry}, false)))
			require.NoError(t, err)

			got, err := reader.ReadAllFileData("corrupt.bin", oneMB)
			require.Error(t, err)
			assert.Nil(t, got)

			size, err := reader.ReadFileSize("corrupt.bin")
			require.NoError(t, err)
			if size > 0 {
				got, err = reader.ReadFileData("corrupt.bin", 0, size)
				require.Error(t, err)
				assert.Nil(t, got)
			}
		})
	}
}

// TestManifestDeflatedSizeCap pins that WithTDFManifestMaxSize measures the
// manifest after inflation, and that neither an honest nor a lying declared
// size lets a small compressed entry inflate without bound.
func TestManifestDeflatedSizeCap(t *testing.T) {
	const maxSize = 64 * oneKB

	t.Run("declared size past the cap is refused before inflating", func(t *testing.T) {
		big := []byte(`{"pad":"` + strings.Repeat("a", oneMB) + `"}`)
		manifest := deflatedEntry(t, TDFManifestFileName, big)
		require.Less(t, len(manifest.data), maxSize, "compressed size alone would pass the cap")

		data := buildRawZip(t, []rawZipEntry{{name: TDFPayloadFileName, data: []byte("payload bytes")}, manifest}, false)
		src := &byteCountingSeeker{ReadSeeker: bytes.NewReader(data)}
		reader, err := NewTDFReader(src, WithTDFManifestMaxSize(maxSize))
		require.NoError(t, err)

		src.n = 0
		_, err = reader.Manifest()
		require.ErrorContains(t, err, "size too large")
		assert.Zero(t, src.n, "the cap must be applied before any entry data is read")

		// The same archive loads with the cap lifted.
		reader, err = NewTDFReader(bytes.NewReader(data))
		require.NoError(t, err)
		got, err := reader.Manifest()
		require.NoError(t, err)
		assert.Equal(t, string(big), got)
	})

	t.Run("declared size under the cap but data far larger", func(t *testing.T) {
		// A classic bomb: a few KiB inflating to megabytes, declared tiny.
		manifest := deflatedEntry(t, TDFManifestFileName, make([]byte, 4*oneMB))
		manifest.uncompressedSize = oneKB

		data := buildRawZip(t, []rawZipEntry{{name: TDFPayloadFileName, data: []byte("payload bytes")}, manifest}, false)
		reader, err := NewTDFReader(bytes.NewReader(data), WithTDFManifestMaxSize(maxSize))
		require.NoError(t, err)

		got, err := reader.Manifest()
		require.ErrorIs(t, err, zip.ErrFormat)
		assert.Empty(t, got)
	})

	t.Run("inflation stops at the declared size", func(t *testing.T) {
		// Incompressible data makes the compressed stream as long as the
		// inflated one, so the bytes pulled from the archive show how far
		// inflation went. Inflating the whole entry would read all of it.
		manifest := deflatedEntry(t, TDFManifestFileName, randomBytes(oneMB))
		manifest.uncompressedSize = oneKB
		require.Greater(t, len(manifest.data), oneMB/2)

		data := buildRawZip(t, []rawZipEntry{{name: TDFPayloadFileName, data: []byte("payload bytes")}, manifest}, false)
		src := &byteCountingSeeker{ReadSeeker: bytes.NewReader(data)}
		reader, err := NewTDFReader(src, WithTDFManifestMaxSize(maxSize))
		require.NoError(t, err)

		src.n = 0
		_, err = reader.Manifest()
		require.ErrorIs(t, err, zip.ErrFormat)
		assert.Less(t, src.n, int64(len(manifest.data)/4),
			"read %d of %d compressed bytes to check a %d byte manifest", src.n, len(manifest.data), oneKB)
	})
}

// TestReaderDeflatedPayloadRandomAccess drives a deflated entry the way the
// sdk's ReadAt and Seek do: backwards, overlapping, repeated and skipping
// ahead. The payload is larger than the DEFLATE window and the inflater's
// read buffer, so a backwards read genuinely has to restart.
func TestReaderDeflatedPayloadRandomAccess(t *testing.T) {
	plain := compressibleBytes(512 * oneKB)
	data := buildRawZip(t, []rawZipEntry{deflatedEntry(t, TDFPayloadFileName, plain)}, false)
	reader, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	check := func(off, n int) {
		t.Helper()
		got, err := reader.ReadFileData(TDFPayloadFileName, int64(off), int64(n))
		require.NoError(t, err, "read of %d at %d", n, off)
		require.Equal(t, plain[off:off+n], got, "read of %d at %d", n, off)
	}

	// Reverse segment order.
	const segment = 40000
	for off := (len(plain) - 1) / segment * segment; off >= 0; off -= segment {
		check(off, min(segment, len(plain)-off))
	}

	// The end, then the start, then the same read twice, then overlapping.
	check(len(plain)-10, 10)
	check(0, 10)
	check(0, 10)
	check(5, 100)
	check(50, 100)
	check(len(plain)/2, 1)
	check(len(plain)/2-1, 3)

	// Skip ahead past the read buffer, then back a little.
	check(300*oneKB, 10)
	check(400*oneKB, 10)
	check(399*oneKB, 2*oneKB)

	rng := rand.New(rand.NewPCG(1, 2))
	for range 200 {
		off := rng.IntN(len(plain))
		check(off, rng.IntN(len(plain)-off+1))
	}
}

// TestReaderDeflatedRepeatedSegmentReadsStayLinear pins the cost of the
// sdk's Read: each call goes through ReadAt, which fetches the whole segment
// holding the cursor, so a caller reading in small pieces asks for the same
// segment many times in a row. Each repeat lies behind the inflater's cursor;
// restarting from the start of the entry for it would make a sequential read
// quadratic in the payload size.
func TestReaderDeflatedRepeatedSegmentReadsStayLinear(t *testing.T) {
	plain := randomBytes(512 * oneKB)
	entry := deflatedEntry(t, TDFPayloadFileName, plain)
	src := &byteCountingSeeker{ReadSeeker: bytes.NewReader(buildRawZip(t, []rawZipEntry{entry}, false))}
	reader, err := NewReader(src)
	require.NoError(t, err)

	src.n = 0
	const segment, repeats = 32 * oneKB, 8
	for off := 0; off < len(plain); off += segment {
		for range repeats {
			got, err := reader.ReadFileData(TDFPayloadFileName, int64(off), segment)
			require.NoError(t, err)
			require.Equal(t, plain[off:off+segment], got)
		}
	}

	// One pass over the entry, plus slack for archive/zip reading the
	// central directory and local header.
	const slack = 64 * oneKB
	assert.LessOrEqual(t, src.n, int64(len(entry.data))+slack,
		"read %d archive bytes for one sequential pass over a %d byte entry", src.n, len(entry.data))
}

// TestReaderDeflatedConcurrentReads shares one Reader across goroutines, the
// way parallel ReadAt calls would. Run with -race.
func TestReaderDeflatedConcurrentReads(t *testing.T) {
	plain := compressibleBytes(200 * oneKB)
	stored := compressibleBytes(30 * oneKB)
	data := buildRawZip(t, []rawZipEntry{
		deflatedEntry(t, TDFPayloadFileName, plain),
		{name: TDFManifestFileName, data: stored},
	}, false)
	reader, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			rng := rand.New(rand.NewPCG(uint64(g), 3))
			for range 25 {
				name, want := TDFPayloadFileName, plain
				if rng.IntN(3) == 0 {
					name, want = TDFManifestFileName, stored
				}
				off := rng.IntN(len(want))
				n := rng.IntN(min(len(want)-off, 20*oneKB) + 1)
				// t.Errorf, unlike require, is safe off the test goroutine.
				got, err := reader.ReadFileData(name, int64(off), int64(n))
				if err != nil {
					t.Errorf("read of %d at %d in %s: %v", n, off, name, err)
					return
				}
				if !bytes.Equal(want[off:off+n], got) {
					t.Errorf("read of %d at %d in %s returned the wrong bytes", n, off, name)
					return
				}
			}
		})
	}
	wg.Wait()
}

// TestReaderDeflatedZip64 asserts both sizes of a deflated entry come from the
// ZIP64 extra field when the central directory defers them there, and that the
// two are kept apart.
func TestReaderDeflatedZip64(t *testing.T) {
	plain := compressibleBytes(30 * oneKB)

	for _, zip64EOCD := range []bool{false, true} {
		t.Run("zip64 EOCD "+strconv.FormatBool(zip64EOCD), func(t *testing.T) {
			entry := deflatedEntry(t, "zip64.bin", plain)
			entry.zip64 = true
			entry.extraPrefix = timestampExtraField()
			require.NotEqual(t, len(entry.data), len(plain))

			reader, err := NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{
				entry,
				{name: "after.bin", data: []byte("after")},
			}, zip64EOCD)))
			require.NoError(t, err)

			size, err := reader.ReadFileSize("zip64.bin")
			require.NoError(t, err)
			assert.Equal(t, int64(len(plain)), size)

			got, err := reader.ReadAllFileData("zip64.bin", oneMB)
			require.NoError(t, err)
			assert.Equal(t, plain, got)

			got, err = reader.ReadFileData("zip64.bin", 1000, 2000)
			require.NoError(t, err)
			assert.Equal(t, plain[1000:3000], got)
		})
	}
}

// TestParseZip64ExtraFieldUncompressedSizeOnly covers a deflated entry whose
// uncompressed size alone overflows 32 bits, the usual shape for a highly
// compressible entry: the extra field then carries only that value, and the
// compressed size and offset stay in the central directory.
func TestParseZip64ExtraFieldUncompressedSizeOnly(t *testing.T) {
	const big = uint64(5) << 30
	extra := binary.LittleEndian.AppendUint16(timestampExtraField(), zip64ExternalID)
	extra = binary.LittleEndian.AppendUint16(extra, 8)
	extra = binary.LittleEndian.AppendUint64(extra, big)

	h := CDFileHeader{UncompressedSize: zip64MagicVal, CompressedSize: 1234, LocalHeaderOffset: 56, ExtraFieldLength: uint16(len(extra))}
	offset, compressed, uncompressed, err := resolveEntryLocation(bytes.NewReader(extra), h)
	require.NoError(t, err)
	assert.Equal(t, big, uncompressed)
	assert.Equal(t, uint64(1234), compressed)
	assert.Equal(t, uint64(56), offset)
}

// TestReaderDeflatedDeclaredSizeBeyondInt64 covers declared uncompressed
// sizes that do not fit the int64 reads are bounded by. They are refused when
// the archive is opened.
func TestReaderDeflatedDeclaredSizeBeyondInt64(t *testing.T) {
	compressed := deflateRaw(t, []byte("payload bytes"))

	for _, declared := range []uint64{beyondInt64, math.MaxUint64} {
		t.Run(strconv.FormatUint(declared, 10), func(t *testing.T) {
			_, err := NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{{
				name: "0.payload", data: compressed, method: zip.Deflate,
				uncompressedSize: declared, zip64: true,
			}}, false)))
			require.ErrorIs(t, err, errZipFormat)
			require.ErrorContains(t, err, "uncompressed")
		})
	}
}

// TestReaderDeflatedHugeDeclaredSizeDoesNotAllocate declares a terabyte for
// a few bytes of DEFLATE data. Reads up to that size are in range, so only
// growing the buffer as data arrives, rather than allocating the declared size
// up front, keeps them from exhausting memory before archive/zip reports the
// shortfall.
func TestReaderDeflatedHugeDeclaredSizeDoesNotAllocate(t *testing.T) {
	entry := deflatedEntry(t, "0.payload", []byte("payload bytes"))
	entry.uncompressedSize = beyondEOF
	entry.zip64 = true
	reader, err := NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{entry}, false)))
	require.NoError(t, err)

	size, err := reader.ReadFileSize("0.payload")
	require.NoError(t, err)
	require.Equal(t, int64(beyondEOF), size)

	_, err = reader.ReadAllFileData("0.payload", math.MaxInt64)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	_, err = reader.ReadFileData("0.payload", 0, size)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	_, err = reader.ReadFileData("0.payload", size/2, size/2)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

// TestReaderDeflatedChecksumMismatch asserts the CRC-32 is verified once a
// deflated entry is read to the end, and only then: a partial read cannot see
// the whole entry, so it cannot check it.
func TestReaderDeflatedChecksumMismatch(t *testing.T) {
	plain := compressibleBytes(20 * oneKB)
	entry := deflatedEntry(t, TDFPayloadFileName, plain)
	entry.crc32 ^= 0xFFFFFFFF
	manifest := deflatedEntry(t, TDFManifestFileName, []byte(testManifest))
	manifest.crc32++

	reader, err := NewTDFReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{entry, manifest}, false)))
	require.NoError(t, err)

	_, err = reader.Manifest()
	require.ErrorIs(t, err, zip.ErrChecksum)

	got, err := reader.ReadPayload(0, 1000)
	require.NoError(t, err)
	assert.Equal(t, plain[:1000], got)

	for _, r := range [][2]int{{0, len(plain)}, {len(plain) - 10, 10}} {
		part, err := reader.ReadPayload(int64(r[0]), int64(r[1]))
		require.ErrorIs(t, err, zip.ErrChecksum, "read of %d at %d", r[1], r[0])
		assert.Nil(t, part)
	}

	// An empty read at the end is checked like any read that reaches it; one
	// short of the end needs no data and is not.
	_, err = reader.ReadPayload(int64(len(plain)), 0)
	require.ErrorIs(t, err, zip.ErrChecksum)
	got, err = reader.ReadPayload(500, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestReaderDeflatedArchiveZipWriter reads entries archive/zip itself wrote:
// the sizes and CRC-32 follow the data in a data descriptor, and the local
// header carries zeros.
func TestReaderDeflatedArchiveZipWriter(t *testing.T) {
	payload := compressibleBytes(100 * oneKB)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range []struct {
		name string
		data []byte
	}{{TDFPayloadFileName, payload}, {TDFManifestFileNameSpec, []byte(testManifest)}} {
		dst, err := w.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate})
		require.NoError(t, err)
		_, err = dst.Write(e.data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	reader, err := NewTDFReader(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	manifest, err := reader.Manifest()
	require.NoError(t, err)
	require.JSONEq(t, testManifest, manifest)

	got, err := reader.ReadPayload(int64(len(payload))-5000, 5000)
	require.NoError(t, err)
	assert.Equal(t, payload[len(payload)-5000:], got)
	got, err = reader.ReadPayload(0, int64(len(payload)))
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// TestReaderDeflatedDuplicateNamesMatchByOffset gives two deflated entries the
// same name. The reader keeps the later one, and has to read that one's data
// through archive/zip -- matching on the name alone would find the first.
func TestReaderDeflatedDuplicateNamesMatchByOffset(t *testing.T) {
	first := []byte("the first entry's data, which the reader must not return")
	second := []byte("the second entry's data, which it must")

	reader, err := NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{
		deflatedEntry(t, TDFPayloadFileName, first),
		deflatedEntry(t, TDFPayloadFileName, second),
	}, false)))
	require.NoError(t, err)

	got, err := reader.ReadAllFileData(TDFPayloadFileName, oneMB)
	require.NoError(t, err)
	assert.Equal(t, second, got)

	got, err = reader.ReadFileData(TDFPayloadFileName, 4, 6)
	require.NoError(t, err)
	assert.Equal(t, second[4:10], got)
}

// TestReaderArchiveZipOnlyForDeflatedEntries pins that archive/zip is reached
// only through a deflated entry, and only once one is read: archives written
// by OpenTDF, which are all STORED, keep this package's direct path.
func TestReaderArchiveZipOnlyForDeflatedEntries(t *testing.T) {
	stored := buildRawZip(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
		{name: TDFManifestFileName, data: []byte(testManifest)},
	}, false)
	reader, err := NewReader(bytes.NewReader(stored))
	require.NoError(t, err)
	for name, entry := range reader.fileEntries {
		assert.Nil(t, entry.deflated, "STORED entry %s must not reach archive/zip", name)
	}

	mixed := buildRawZip(t, []rawZipEntry{
		deflatedEntry(t, TDFPayloadFileName, []byte("payload bytes")),
		{name: TDFManifestFileName, data: []byte(testManifest)},
	}, false)
	reader, err = NewReader(bytes.NewReader(mixed))
	require.NoError(t, err)
	require.Nil(t, reader.fileEntries[TDFManifestFileName].deflated)
	payload := reader.fileEntries[TDFPayloadFileName].deflated
	require.NotNil(t, payload)

	_, err = reader.ReadAllFileData(TDFManifestFileName, oneMB)
	require.NoError(t, err)
	assert.Nil(t, payload.view.zr, "reading a STORED entry must not build the archive/zip reader")

	_, err = reader.ReadFileData(TDFPayloadFileName, 0, 7)
	require.NoError(t, err)
	assert.NotNil(t, payload.view.zr)
}

// TestReaderStoredEntryIgnoresDeclaredUncompressedSize pins that STORED
// entries keep their existing behaviour: the stored length is the entry's
// length whatever the uncompressed size field says.
func TestReaderStoredEntryIgnoresDeclaredUncompressedSize(t *testing.T) {
	payload := []byte("stored entry with a stray original size")
	reader, err := NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{{
		name: "stored.bin", data: payload, uncompressedSize: 5,
	}}, false)))
	require.NoError(t, err)

	size, err := reader.ReadFileSize("stored.bin")
	require.NoError(t, err)
	assert.Equal(t, int64(len(payload)), size)

	got, err := reader.ReadAllFileData("stored.bin", oneMB)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}
