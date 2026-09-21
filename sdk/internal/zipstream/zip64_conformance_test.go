// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"hash/crc32"
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
				CompressedSize:        uint64(len(e.data)),
				LocalFileHeaderOffset: offsets[i],
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

// eocdOf decodes the trailing end of central directory record.
func eocdOf(t *testing.T, data []byte) EndOfCDRecord {
	t.Helper()
	eocd := EndOfCDRecord{}
	require.NoError(t, binary.Read(bytes.NewReader(data[len(data)-endOfCDRecordSize:]), binary.LittleEndian, &eocd))
	require.Equal(t, uint32(endOfCentralDirectorySignature), eocd.Signature)
	return eocd
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
