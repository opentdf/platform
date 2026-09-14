// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawZipEntry describes one entry for buildRawZip. The builder deliberately
// bypasses the writers in this package: these fixtures cover archives our own
// writers never emit (differing compressed/uncompressed sizes, file comments,
// extra fields ahead of the ZIP64 one), which is exactly where the reader's
// conformance gaps live.
type rawZipEntry struct {
	name string
	// data is the stored (compressed) content.
	data []byte
	// uncompressedSize overrides the declared original size. Zero means
	// len(data), i.e. a normal STORED entry.
	uncompressedSize uint64
	// comment is the central directory file comment.
	comment string
	// extraPrefix is written into the extra-field area ahead of the ZIP64
	// field, standing in for a timestamp or NTFS field.
	extraPrefix []byte
	// zip64 emits the 0xFFFFFFFF sentinels plus a ZIP64 extended
	// information extra field for this entry.
	zip64 bool
	// zip64CompressedSize overrides the stored size declared in the ZIP64
	// extra field, letting a fixture lie about how much data it holds. Zero
	// means len(data), so a fixture cannot declare a stored size of zero --
	// a computed override that came out zero would silently revert to the
	// honest size, so callers that compute one must check it is nonzero.
	zip64CompressedSize uint64
	// zip64LocalHeaderOffset overrides the header offset declared in the
	// ZIP64 extra field. Zero means the entry's real offset, and carries the
	// same caveat as zip64CompressedSize.
	zip64LocalHeaderOffset uint64
}

func (e rawZipEntry) zip64Compressed() uint64 {
	if e.zip64CompressedSize != 0 {
		return e.zip64CompressedSize
	}
	return uint64(len(e.data))
}

func (e rawZipEntry) zip64Offset(actual uint64) uint64 {
	if e.zip64LocalHeaderOffset != 0 {
		return e.zip64LocalHeaderOffset
	}
	return actual
}

func (e rawZipEntry) uncompressed() uint64 {
	if e.uncompressedSize != 0 {
		return e.uncompressedSize
	}
	return uint64(len(e.data))
}

// clamp32 narrows a size for a 32-bit header field, substituting the ZIP64
// sentinel when it does not fit.
func clamp32(v uint64) uint32 {
	if v >= zip64MagicVal {
		return zip64MagicVal
	}
	return uint32(v)
}

// buildRawZip assembles an archive byte-for-byte from entries.
func buildRawZip(t testing.TB, entries []rawZipEntry, zip64EOCD bool) []byte {
	t.Helper()

	buf := &bytes.Buffer{}
	offsets := make([]uint64, len(entries))

	for i, e := range entries {
		offsets[i] = uint64(buf.Len())
		lfh := LocalFileHeader{
			Signature:        fileHeaderSignature,
			Version:          zipVersion,
			Crc32:            crc32.ChecksumIEEE(e.data),
			CompressedSize:   clamp32(uint64(len(e.data))),
			UncompressedSize: clamp32(e.uncompressed()),
			FilenameLength:   uint16(len(e.name)),
		}
		require.NoError(t, binary.Write(buf, binary.LittleEndian, lfh))
		buf.WriteString(e.name)
		buf.Write(e.data)
	}

	cdOffset := uint64(buf.Len())
	for i, e := range entries {
		extra := &bytes.Buffer{}
		extra.Write(e.extraPrefix)

		cdh := CDFileHeader{
			Signature:         centralDirectoryHeaderSignature,
			VersionCreated:    zipVersion,
			VersionNeeded:     zipVersion,
			Crc32:             crc32.ChecksumIEEE(e.data),
			CompressedSize:    clamp32(uint64(len(e.data))),
			UncompressedSize:  clamp32(e.uncompressed()),
			FilenameLength:    uint16(len(e.name)),
			FileCommentLength: uint16(len(e.comment)),
			LocalHeaderOffset: clamp32(offsets[i]),
		}

		if e.zip64 {
			cdh.CompressedSize = zip64MagicVal
			cdh.UncompressedSize = zip64MagicVal
			cdh.LocalHeaderOffset = zip64MagicVal
			require.NoError(t, binary.Write(extra, binary.LittleEndian, Zip64ExtendedInfoExtraField{
				Signature:             zip64ExternalID,
				Size:                  zip64ExtendedInfoExtraFieldSize - extraFieldHeaderSize,
				OriginalSize:          e.uncompressed(),
				CompressedSize:        e.zip64Compressed(),
				LocalFileHeaderOffset: e.zip64Offset(offsets[i]),
			}))
		}
		cdh.ExtraFieldLength = uint16(extra.Len())

		require.NoError(t, binary.Write(buf, binary.LittleEndian, cdh))
		buf.WriteString(e.name)
		buf.Write(extra.Bytes())
		buf.WriteString(e.comment)
	}
	cdSize := uint64(buf.Len()) - cdOffset

	eocd := EndOfCDRecord{
		Signature:               endOfCentralDirectorySignature,
		NumberOfCDRecordEntries: uint16(len(entries)),
		TotalCDRecordEntries:    uint16(len(entries)),
		SizeOfCentralDirectory:  clamp32(cdSize),
		CentralDirectoryOffset:  clamp32(cdOffset),
	}

	if zip64EOCD {
		zip64Start := uint64(buf.Len())
		require.NoError(t, binary.Write(buf, binary.LittleEndian, Zip64EndOfCDRecord{
			Signature:                          zip64EndOfCDSignature,
			RecordSize:                         zip64EndOfCDRecordSize - zip64RecordHeaderSize,
			VersionMadeBy:                      zipVersion,
			VersionToExtract:                   zipVersion,
			NumberOfCDRecordEntries:            uint64(len(entries)),
			TotalCDRecordEntries:               uint64(len(entries)),
			CentralDirectorySize:               cdSize,
			StartingDiskCentralDirectoryOffset: cdOffset,
		}))
		require.NoError(t, binary.Write(buf, binary.LittleEndian, Zip64EndOfCDRecordLocator{
			Signature:     zip64EndOfCDLocatorSignature,
			CDOffset:      zip64Start,
			NumberOfDisks: 1,
		}))

		eocd.NumberOfCDRecordEntries = zip64MagicVal16
		eocd.TotalCDRecordEntries = zip64MagicVal16
		eocd.SizeOfCentralDirectory = zip64MagicVal
		eocd.CentralDirectoryOffset = zip64MagicVal
	}

	require.NoError(t, binary.Write(buf, binary.LittleEndian, eocd))
	return buf.Bytes()
}

// timestampExtraField is a plausible non-ZIP64 extra field (tag 0x5455,
// "extended timestamp") used to push the ZIP64 field off the head of the
// extra-field area.
func timestampExtraField() []byte {
	return []byte{0x55, 0x54, 0x05, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04}
}

// TestReaderZip64ExtraFieldOrder asserts the reader follows APPNOTE 4.5.3's
// ZIP64 value order -- original size, compressed size, local header offset.
// Reading the compressed size first is invisible for STORED entries where
// the two match, so the fixture makes them differ.
func TestReaderZip64ExtraFieldOrder(t *testing.T) {
	payload := []byte("seventeen bytes!!")
	require.Len(t, payload, 17)

	data := buildRawZip(t, []rawZipEntry{{
		name:             "differing.bin",
		data:             payload,
		uncompressedSize: 99, // deliberately not len(payload)
		zip64:            true,
	}}, true)

	reader, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	size, err := reader.ReadFileSize("differing.bin")
	require.NoError(t, err)
	// 99 here would mean the reader took the original size for the
	// compressed one, i.e. read the two values in the wrong order.
	assert.Equal(t, int64(len(payload)), size)

	got, err := reader.ReadAllFileData("differing.bin", oneMB)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// TestReaderZip64ExtraFieldNotFirst asserts the ZIP64 extra field need not
// head the extra-field area.
func TestReaderZip64ExtraFieldNotFirst(t *testing.T) {
	payload := []byte("preceded by a timestamp field")

	data := buildRawZip(t, []rawZipEntry{{
		name:        "prefixed.bin",
		data:        payload,
		extraPrefix: timestampExtraField(),
		zip64:       true,
	}}, true)

	reader, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	got, err := reader.ReadAllFileData("prefixed.bin", oneMB)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// TestReaderPerEntryZip64WithoutZip64EOCD asserts a per-entry ZIP64 extra
// field is honored even when the archive's EOCD is not itself ZIP64.
func TestReaderPerEntryZip64WithoutZip64EOCD(t *testing.T) {
	payload := []byte("entry is zip64, archive is not")

	data := buildRawZip(t, []rawZipEntry{{
		name:  "lonely.bin",
		data:  payload,
		zip64: true,
	}}, false)

	reader, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	got, err := reader.ReadAllFileData("lonely.bin", oneMB)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// TestReaderCentralDirectoryFileComment asserts a comment on one central
// directory entry does not desync the entries that follow it.
func TestReaderCentralDirectoryFileComment(t *testing.T) {
	first := []byte("first entry contents")
	second := []byte("second entry contents")

	data := buildRawZip(t, []rawZipEntry{
		{name: "first.bin", data: first, comment: "a central directory file comment"},
		{name: "second.bin", data: second},
	}, false)

	reader, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	got, err := reader.ReadAllFileData("second.bin", oneMB)
	require.NoError(t, err)
	assert.Equal(t, second, got)
}

// TestReaderCentralDirectoryLengthOverflow asserts the three per-entry
// uint16 lengths (name, extra field, comment) are widened before being
// summed. Here they total 65646, which wraps to 110 if summed at 16 bits.
func TestReaderCentralDirectoryLengthOverflow(t *testing.T) {
	const longNameLen = 65000

	second := []byte("second entry contents")
	data := buildRawZip(t, []rawZipEntry{
		{
			name:        strings.Repeat("n", longNameLen),
			data:        []byte("first entry contents"),
			extraPrefix: bytes.Repeat([]byte{0}, 600),
		},
		{name: "second.bin", data: second},
	}, false)

	reader, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	got, err := reader.ReadAllFileData("second.bin", oneMB)
	require.NoError(t, err)
	assert.Equal(t, second, got)
}

// TestReaderZip64DetectedFromEntryCount asserts the entry count is its own
// ZIP64 trigger, independent of the size/offset sentinels, and that its
// sentinel is two bytes wide.
func TestReaderZip64DetectedFromEntryCount(t *testing.T) {
	payload := []byte("counted")
	data := buildRawZip(t, []rawZipEntry{{name: "counted.bin", data: payload}}, true)

	// Undo the size/offset sentinels the builder set, leaving only the
	// entry-count sentinel to signal ZIP64.
	eocdStart := len(data) - endOfCDRecordSize
	eocd := EndOfCDRecord{}
	require.NoError(t, binary.Read(bytes.NewReader(data[eocdStart:]), binary.LittleEndian, &eocd))
	require.Equal(t, uint32(zip64MagicVal), eocd.CentralDirectoryOffset)

	rewritten := &bytes.Buffer{}
	rewritten.Write(data[:eocdStart])
	eocd.SizeOfCentralDirectory = 0
	eocd.CentralDirectoryOffset = 0
	require.NoError(t, binary.Write(rewritten, binary.LittleEndian, eocd))

	reader, err := NewReader(bytes.NewReader(rewritten.Bytes()))
	require.NoError(t, err)

	got, err := reader.ReadAllFileData("counted.bin", oneMB)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// TestReaderMalformedExtraFieldRejected checks the walk refuses an extra
// field that claims to run past the end of the area rather than reading
// whatever follows it.
func TestReaderMalformedExtraFieldRejected(t *testing.T) {
	// Tag 0x0001, declared body length 0xFFFF, no body.
	_, err := parseZip64ExtraField([]byte{0x01, 0x00, 0xFF, 0xFF}, CDFileHeader{
		CompressedSize: zip64MagicVal,
	})
	require.ErrorIs(t, err, errZipFormat)
}

// beyondInt64 narrows to a negative int64; beyondEOF stays positive but is
// far larger than any fixture archive. The reader has to refuse both, and for
// different reasons -- the first corrupts a seek or an allocation outright,
// the second merely addresses bytes that are not there.
const (
	beyondInt64 = uint64(1) << 63
	beyondEOF   = uint64(1) << 40
)

// overwrite re-encodes v over the region of data starting at off, which must
// already hold a record of the same width.
func overwrite(t *testing.T, data []byte, off int, v any) []byte {
	t.Helper()

	buf := &bytes.Buffer{}
	require.NoError(t, binary.Write(buf, binary.LittleEndian, v))

	out := make([]byte, 0, len(data))
	out = append(out, data[:off]...)
	out = append(out, buf.Bytes()...)
	return append(out, data[off+buf.Len():]...)
}

// locatorOf decodes the ZIP64 end of central directory locator and returns it
// with its offset in data.
func locatorOf(t testing.TB, data []byte) (Zip64EndOfCDRecordLocator, int) {
	t.Helper()

	off := len(data) - endOfCDRecordSize - zip64EndOfCDRecordLocatorSize
	locator := Zip64EndOfCDRecordLocator{}
	require.NoError(t, binary.Read(bytes.NewReader(data[off:]), binary.LittleEndian, &locator))
	require.Equal(t, uint32(zip64EndOfCDLocatorSignature), locator.Signature)
	return locator, off
}

// TestReaderRejectsZip64ValuesBeyondArchive covers the ZIP64 extra field,
// whose sizes and offsets are raw uint64 read straight off disk and so are
// attacker-controlled in any TDF. The stored-size case pins the precondition
// that made a panic reachable -- 1<<63 narrowed to a negative length, which
// nothing downstream rejected before make([]byte, size) blew up. The panic
// itself is covered by the fuzz seed in fuzz_test.go.
//
// Each case names the check expected to reject it. Seven guards wrap
// errZipFormat, so asserting the sentinel alone would stay green if a
// different one happened to catch the fixture.
func TestReaderRejectsZip64ValuesBeyondArchive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry rawZipEntry
		field string
	}{
		{"stored size above MaxInt64", rawZipEntry{zip64CompressedSize: beyondInt64}, "file data"},
		{"stored size past EOF", rawZipEntry{zip64CompressedSize: beyondEOF}, "file data"},
		{"header offset above MaxInt64", rawZipEntry{zip64LocalHeaderOffset: beyondInt64}, "local file header"},
		{"header offset past EOF", rawZipEntry{zip64LocalHeaderOffset: beyondEOF}, "local file header"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := tc.entry
			entry.name = "0.payload"
			entry.data = []byte("payload bytes")
			entry.zip64 = true

			_, err := NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{entry}, false)))
			require.ErrorIs(t, err, errZipFormat)
			require.ErrorContains(t, err, tc.field)
		})
	}
}

// twoEntryFixture is the shape the entry-bound tests need: a second entry
// after the one under test, so the central directory sits well past the first
// entry's data and a forged size has somewhere to reach. With a single entry
// the bound and the honest data length coincide and the accepted case below
// would assert nothing.
func twoEntryFixture() (rawZipEntry, rawZipEntry) {
	return rawZipEntry{name: "0.payload", data: []byte("payload bytes"), zip64: true},
		rawZipEntry{name: "0.manifest.json", data: []byte(`{"m":1}`)}
}

// TestReaderEntryBoundaryIsCentralDirectory pins both the off-by-one and the
// limit it is measured against. All file data precedes the central directory,
// so an entry ending on the byte before it is in range and exactly one byte
// more is not -- even though that byte, and every byte of the central
// directory after it, is still inside the archive.
func TestReaderEntryBoundaryIsCentralDirectory(t *testing.T) {
	payload, manifest := twoEntryFixture()
	data := buildRawZip(t, []rawZipEntry{payload, manifest}, false)

	reader, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	cdStart := cdStartOf(t, data)
	dataStart := uint64(reader.fileEntries[payload.name].index)
	require.Less(t, cdStart, uint64(len(data)), "the bound has to be tighter than the archive")

	// Claim every byte from where the data starts up to the central
	// directory. The override changes only the declared size, so the layout --
	// and with it cdStart and the archive length -- is unchanged.
	payload.zip64CompressedSize = cdStart - dataStart
	require.NotZero(t, payload.zip64CompressedSize, "a zero override would revert to the honest size")
	exact := buildRawZip(t, []rawZipEntry{payload, manifest}, false)
	require.Len(t, exact, len(data))

	_, err = NewReader(bytes.NewReader(exact))
	require.NoError(t, err, "an entry ending on the byte before the central directory is in bounds")

	payload.zip64CompressedSize++
	_, err = NewReader(bytes.NewReader(buildRawZip(t, []rawZipEntry{payload, manifest}, false)))
	require.ErrorIs(t, err, errZipFormat, "one byte into the central directory is not")
	require.ErrorContains(t, err, "runs past the "+boundCDStart,
		"the rejection has to come from the central directory bound, not from EOF")
}

// TestReaderRejectsEntryOverrunningCentralDirectory covers the leak the
// boundary above only brushes: a forged ZIP64 stored size that stays inside
// the archive but swallows the central directory, which ReadAllFileData would
// otherwise hand back as file content.
func TestReaderRejectsEntryOverrunningCentralDirectory(t *testing.T) {
	payload, manifest := twoEntryFixture()
	data := buildRawZip(t, []rawZipEntry{payload, manifest}, false)

	reader, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	cdStart := cdStartOf(t, data)
	dataStart := uint64(reader.fileEntries[payload.name].index)

	// Reach to the last byte before the EOCD. Bounding against the archive
	// accepted this; bounding against the central directory does not.
	payload.zip64CompressedSize = uint64(len(data)) - endOfCDRecordSize - dataStart
	require.Greater(t, dataStart+payload.zip64CompressedSize, cdStart)

	forged := buildRawZip(t, []rawZipEntry{payload, manifest}, false)
	require.Len(t, forged, len(data))

	_, err = NewReader(bytes.NewReader(forged))
	require.ErrorIs(t, err, errZipFormat)
	require.ErrorContains(t, err, "runs past the "+boundCDStart,
		"a size that fits the archive but not the central directory must be refused by the tighter bound")
}

// TestWriterManifestEndsAtCentralDirectory pins why that bound is inclusive.
// Finalize places the central directory on the byte immediately after the
// manifest data, so the manifest entry of every archive this package writes
// ends exactly on the bound -- a strict comparison would reject all of them.
func TestWriterManifestEndsAtCentralDirectory(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode Zip64Mode
	}{
		{"auto", Zip64Auto},
		{"always", Zip64Always},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := writeOneSegmentArchive(t, []byte("payload bytes"), WithZip64Mode(tc.mode))

			reader, err := NewReader(bytes.NewReader(data))
			require.NoError(t, err)

			entry := reader.fileEntries[TDFManifestFileName]
			assert.Equal(t, int64(cdStartOf(t, data)), entry.index+entry.length)
		})
	}
}

// TestReadFileDataBoundsIndex asserts the read offset is bounded by the
// entry, not just the length. For a TDF the offset is accumulated from the
// segment sizes the manifest declares, so an unbounded one lets a manifest
// walk the read off the end of the payload and into the ZIP structures that
// follow it.
func TestReadFileDataBoundsIndex(t *testing.T) {
	payload, manifest := twoEntryFixture()
	data := buildRawZip(t, []rawZipEntry{payload, manifest}, false)

	reader, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	size, err := reader.ReadFileSize(payload.name)
	require.NoError(t, err)
	require.Equal(t, int64(len(payload.data)), size)

	// The whole entry is fine; anything that ends past it is not.
	got, err := reader.ReadFileData(payload.name, 0, size)
	require.NoError(t, err)
	assert.Equal(t, payload.data, got)

	// An in-bounds index has to actually offset the read. Dropping it would
	// hand every segment of a TDF the bytes of segment 0, and the surviving
	// bounds checks would not notice.
	require.Greater(t, len(payload.data), 9, "the fixture needs room for an interior read")
	got, err = reader.ReadFileData(payload.name, 4, 5)
	require.NoError(t, err)
	assert.Equal(t, payload.data[4:9], got)

	for _, tc := range []struct {
		name          string
		index, length int64
	}{
		{"last byte plus one", size - 1, 2},
		{"starts at the end", size, 1},
		{"starts past the end", size + 1, 1},
		{"negative index", -1, 1},
		{"negative length", 0, -1},
		{"length past the entry", 0, size + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := reader.ReadFileData(payload.name, tc.index, tc.length)
			require.ErrorIs(t, err, errZipFileSizeError)
		})
	}
}

// TestReaderRejectsZip64LocatorOffsetBeyondArchive covers the one 64-bit
// offset that is read before any entry: the locator's pointer to the ZIP64
// end of central directory record.
func TestReaderRejectsZip64LocatorOffsetBeyondArchive(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset uint64
	}{
		{"above MaxInt64", beyondInt64},
		{"past EOF", beyondEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := buildRawZip(t, []rawZipEntry{{name: "0.payload", data: []byte("payload bytes")}}, true)

			locator, off := locatorOf(t, data)
			locator.CDOffset = tc.offset

			_, err := NewReader(bytes.NewReader(overwrite(t, data, off, locator)))
			require.ErrorIs(t, err, errZipFormat)
			require.ErrorContains(t, err, "zip64 end of central directory record")
		})
	}
}

// zip64EOCDOf decodes the ZIP64 end of central directory record and returns it
// with its offset in data.
func zip64EOCDOf(t *testing.T, data []byte) (Zip64EndOfCDRecord, int) {
	t.Helper()

	locator, _ := locatorOf(t, data)
	record := Zip64EndOfCDRecord{}
	require.NoError(t, binary.Read(bytes.NewReader(data[locator.CDOffset:]), binary.LittleEndian, &record))
	require.Equal(t, uint32(zip64EndOfCDSignature), record.Signature)
	return record, int(locator.CDOffset)
}

// countingSeeker counts the seeks NewReader performs, so a test can assert
// that a check rejected an archive up front rather than walking it.
type countingSeeker struct {
	inner io.ReadSeeker
	seeks int
}

func (c *countingSeeker) Read(p []byte) (int, error) { return c.inner.Read(p) }

func (c *countingSeeker) Seek(offset int64, whence int) (int64, error) {
	c.seeks++
	return c.inner.Seek(offset, whence)
}

// TestReaderRejectsEntryCountBeyondArchive checks the ZIP64 entry count is
// bounded by the room the archive actually has: each central directory record
// is at least cdFileHeaderSize bytes, so a uint64 count is self-evidently a
// lie before the walk begins.
//
// The assertion is on the seek count, not the error. Removing the guard
// entirely still produces errZipFormat -- the second iteration lands on the
// ZIP64 end of central directory record and fails the signature check -- so
// only the short-circuit distinguishes the guard from its absence.
func TestReaderRejectsEntryCountBeyondArchive(t *testing.T) {
	data := buildRawZip(t, []rawZipEntry{{name: "0.payload", data: []byte("payload bytes")}}, true)

	record, off := zip64EOCDOf(t, data)
	record.NumberOfCDRecordEntries = math.MaxUint64
	record.TotalCDRecordEntries = math.MaxUint64

	// The EOCD, the locator, and the ZIP64 end of central directory record:
	// three seeks to establish the count, and none to walk it.
	const seeksBeforeTheWalk = 3

	counting := &countingSeeker{inner: bytes.NewReader(overwrite(t, data, off, record))}
	_, err := NewReader(counting)
	require.ErrorIs(t, err, errZipFormat)
	require.ErrorContains(t, err, "central directory entries declared")
	assert.LessOrEqual(t, counting.seeks, seeksBeforeTheWalk,
		"an impossible entry count must be refused before the central directory walk")
}

// TestReaderRejectsCentralDirectoryStartBeyondArchive covers the guard that
// places centralDirectoryStart inside the archive. That is the precondition
// the int64 safety of every subsequent offset check rests on, and it is the
// one bound no per-entry check can stand in for: the fixture declares zero
// entries, so the walk never runs.
func TestReaderRejectsCentralDirectoryStartBeyondArchive(t *testing.T) {
	data := buildRawZip(t, []rawZipEntry{{name: "0.payload", data: []byte("payload bytes")}}, true)

	record, off := zip64EOCDOf(t, data)
	record.StartingDiskCentralDirectoryOffset = beyondEOF
	record.NumberOfCDRecordEntries = 0
	record.TotalCDRecordEntries = 0

	_, err := NewReader(bytes.NewReader(overwrite(t, data, off, record)))
	require.ErrorIs(t, err, errZipFormat)
	require.ErrorContains(t, err, boundCDStart)
}

// cdHeaderOf decodes the central directory file header at off.
func cdHeaderOf(t *testing.T, data []byte, off int) CDFileHeader {
	t.Helper()

	cdh := CDFileHeader{}
	require.NoError(t, binary.Read(bytes.NewReader(data[off:]), binary.LittleEndian, &cdh))
	require.Equal(t, uint32(centralDirectoryHeaderSignature), cdh.Signature)
	return cdh
}

// TestReaderRejectsCentralDirectoryWalkBeyondArchive reaches the entry-offset
// check with a nonzero accumulated offset, which every other fixture leaves at
// zero. A forged comment length on the first record sends the walk to a second
// record that lies outside the archive.
func TestReaderRejectsCentralDirectoryWalkBeyondArchive(t *testing.T) {
	first, second := twoEntryFixture()
	data := buildRawZip(t, []rawZipEntry{first, second}, false)
	cdStart := int(cdStartOf(t, data))

	cdh := cdHeaderOf(t, data, cdStart)
	cdh.FileCommentLength = math.MaxUint16

	_, err := NewReader(bytes.NewReader(overwrite(t, data, cdStart, cdh)))
	require.ErrorIs(t, err, errZipFormat)
	require.ErrorContains(t, err, "central directory entry")
}

// TestReaderBoundsLocalHeaderByCentralDirectory pins which limit the local
// header offset is measured against. The forged offset is inside the archive
// but inside the central directory, so only the tighter bound rejects it --
// widening the limit to the archive length would let the seek land on central
// directory bytes and fail later, and differently.
func TestReaderBoundsLocalHeaderByCentralDirectory(t *testing.T) {
	payload, manifest := twoEntryFixture()
	data := buildRawZip(t, []rawZipEntry{payload, manifest}, false)

	cdStart := cdStartOf(t, data)
	require.Less(t, cdStart, uint64(len(data)), "the bound has to be tighter than the archive")

	// One byte into the central directory. The override changes only the
	// declared offset, so the layout is unchanged.
	payload.zip64LocalHeaderOffset = cdStart + 1
	forged := buildRawZip(t, []rawZipEntry{payload, manifest}, false)
	require.Len(t, forged, len(data))

	_, err := NewReader(bytes.NewReader(forged))
	require.ErrorIs(t, err, errZipFormat)
	require.ErrorContains(t, err, "local file header")
	require.ErrorContains(t, err, "runs past the "+boundCDStart)
}

// TestReaderRejectsLocalHeaderLengthsOverrunningCentralDirectory covers the
// bound on where an entry's data begins. The delta comes from the local
// header's own filename and extra-field lengths, which buildRawZip always
// writes honestly, so the header is rewritten in place instead.
func TestReaderRejectsLocalHeaderLengthsOverrunningCentralDirectory(t *testing.T) {
	payload, manifest := twoEntryFixture()
	data := buildRawZip(t, []rawZipEntry{payload, manifest}, false)

	// The first entry's local header sits at offset 0.
	lfh := LocalFileHeader{}
	require.NoError(t, binary.Read(bytes.NewReader(data), binary.LittleEndian, &lfh))
	require.Equal(t, uint32(fileHeaderSignature), lfh.Signature)
	lfh.ExtraFieldLength = math.MaxUint16

	_, err := NewReader(bytes.NewReader(overwrite(t, data, 0, lfh)))
	require.ErrorIs(t, err, errZipFormat)
	require.ErrorContains(t, err, "file data start")
}

// hostileSeeker reports a fixed, implausible position from every Seek while
// reading from a real archive underneath. It stands in for a caller-supplied
// io.ReadSeeker -- a range-backed or remote one -- that misreports its
// position, which is what the archive-length guard defends against.
type hostileSeeker struct {
	inner io.ReadSeeker
	pos   int64
}

func (h hostileSeeker) Read(p []byte) (int, error)     { return h.inner.Read(p) }
func (h hostileSeeker) Seek(int64, int) (int64, error) { return h.pos, nil }

// TestReaderRejectsImplausibleSeekPosition covers the guard on the archive
// length itself. Every other bound is derived from it, so a position that
// cannot be widened to a uint64 and back has to be refused before any of them
// is built.
func TestReaderRejectsImplausibleSeekPosition(t *testing.T) {
	data := buildRawZip(t, []rawZipEntry{{name: "0.payload", data: []byte("payload bytes")}}, false)

	for _, tc := range []struct {
		name string
		pos  int64
	}{
		{"negative position", -1},
		{"position at MaxInt64", math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewReader(hostileSeeker{inner: bytes.NewReader(data), pos: tc.pos})
			require.ErrorIs(t, err, errZipFormat)
			require.ErrorContains(t, err, "implausible end of central directory offset")
		})
	}
}

// eocdOf decodes the trailing end of central directory record.
func eocdOf(t testing.TB, data []byte) EndOfCDRecord {
	t.Helper()
	eocd := EndOfCDRecord{}
	require.NoError(t, binary.Read(bytes.NewReader(data[len(data)-endOfCDRecordSize:]), binary.LittleEndian, &eocd))
	require.Equal(t, uint32(endOfCentralDirectorySignature), eocd.Signature)
	return eocd
}

// cdStartOf returns where the central directory begins, following the ZIP64
// end of central directory record when the EOCD defers to it.
func cdStartOf(t testing.TB, data []byte) uint64 {
	t.Helper()

	eocd := eocdOf(t, data)
	if !eocdNeedsZip64(eocd) {
		return uint64(eocd.CentralDirectoryOffset)
	}

	locator, _ := locatorOf(t, data)
	record := Zip64EndOfCDRecord{}
	require.NoError(t, binary.Read(bytes.NewReader(data[locator.CDOffset:]), binary.LittleEndian, &record))
	require.Equal(t, uint32(zip64EndOfCDSignature), record.Signature)
	return record.StartingDiskCentralDirectoryOffset
}

// writeOneSegmentArchive drives the segment writer over a single payload.
func writeOneSegmentArchive(t *testing.T, payload []byte, opts ...Option) []byte {
	t.Helper()

	w := NewSegmentTDFWriter(1, opts...)
	defer w.Close()

	header, err := w.WriteSegment(t.Context(), 0, uint64(len(payload)), crc32.ChecksumIEEE(payload))
	require.NoError(t, err)

	fin, err := w.Finalize(t.Context(), []byte(`{"m":1}`))
	require.NoError(t, err)

	return buildZip(t, [][]byte{header, payload}, fin)
}

// TestWriterSwitchesToZip64AtInjectedThreshold asserts the writer switches
// to ZIP64 once an entry's size, compressed size, or offset exceeds the
// configured threshold. The production threshold is 2 GiB, which no unit
// test can reach without allocating a 2 GiB payload, so the threshold is
// lowered instead -- the same seam java-sdk uses.
func TestWriterSwitchesToZip64AtInjectedThreshold(t *testing.T) {
	const threshold = 1024
	payload := bytes.Repeat([]byte("z"), threshold+1)

	t.Run("above threshold uses zip64", func(t *testing.T) {
		data := writeOneSegmentArchive(t, payload, WithMaxNonZip64Value(threshold))

		eocd := eocdOf(t, data)
		assert.Equal(t, uint32(zip64MagicVal), eocd.CentralDirectoryOffset,
			"payload above the threshold should defer the EOCD to ZIP64")

		// The archive still has to be readable, by us and by a stock reader.
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		require.NoError(t, err)
		assert.Len(t, zr.File, 2)

		reader, err := NewReader(bytes.NewReader(data))
		require.NoError(t, err)
		got, err := reader.ReadAllFileData(TDFPayloadFileName, oneMB)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("below threshold stays zip32", func(t *testing.T) {
		data := writeOneSegmentArchive(t, payload) // default threshold, 2 GiB

		eocd := eocdOf(t, data)
		assert.NotEqual(t, uint32(zip64MagicVal), eocd.CentralDirectoryOffset,
			"a kilobyte payload should not need ZIP64")
	})
}

// TestEntryNeedsZip64AtTwoGiB pins the production switch point without
// materializing an archive of that size.
func TestEntryNeedsZip64AtTwoGiB(t *testing.T) {
	require.Equal(t, uint64(math.MaxInt32), uint64(maxNonZip64Value))

	cd := NewCentralDirectory()

	// Every field is a trigger on its own, offsets included -- the local
	// condition must not lean on the central directory offset check in
	// Finalize to catch a large offset.
	for _, tc := range []struct {
		name  string
		entry FileEntry
		want  bool
	}{
		{"just below", FileEntry{Size: maxNonZip64Value, CompressedSize: maxNonZip64Value}, false},
		{"size above", FileEntry{Size: maxNonZip64Value + 1}, true},
		{"compressed size above", FileEntry{CompressedSize: maxNonZip64Value + 1}, true},
		{"offset above", FileEntry{Offset: maxNonZip64Value + 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, cd.entryNeedsZip64(tc.entry))
		})
	}
}

// TestCentralDirectoryNarrowingGuard asserts a value that cannot fit the
// 32-bit field fails loudly instead of being silently truncated into a
// corrupt archive.
func TestCentralDirectoryNarrowingGuard(t *testing.T) {
	t.Run("central directory offset", func(t *testing.T) {
		cd := NewCentralDirectory()
		cd.AddFile(FileEntry{Name: "small", Size: 1, CompressedSize: 1})
		cd.Offset = uint64(math.MaxUint32) + 1

		_, err := cd.GenerateBytes(false)
		require.ErrorIs(t, err, ErrFieldOverflow)
	})

	t.Run("entry count", func(t *testing.T) {
		cd := NewCentralDirectory()
		cd.Entries = make([]FileEntry, zip64MagicVal16)

		_, err := cd.GenerateBytes(false)
		require.ErrorIs(t, err, ErrFieldOverflow)
	})

	t.Run("value that fits is accepted", func(t *testing.T) {
		require.NoError(t, checkFitsInCentralDirectory("size", zip64MagicVal-1))
		// The sentinel itself cannot be written as a literal value.
		require.ErrorIs(t, checkFitsInCentralDirectory("size", zip64MagicVal), ErrFieldOverflow)
	})
}
