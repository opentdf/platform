// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DSPX-5354: the reader used to take an entry's compressed size as its length
// and ignore both the uncompressed size and the central directory size, so it
// accepted archives that other TDF readers (web-sdk) reject.

// TestReaderRejectsStoredEntryWithDifferingSizes covers a STORED entry whose
// compressed and uncompressed sizes disagree. Stored data is its own content,
// so the two can only differ in a malformed archive, and a reader bounding the
// entry by the other field would see a different entry.
func TestReaderRejectsStoredEntryWithDifferingSizes(t *testing.T) {
	payload := []byte("sixty-four bytes of stored payload, give or take a few of them..")

	for _, tc := range []struct {
		name             string
		uncompressedSize uint64
		zip64            bool
	}{
		{"uncompressed size one larger", uint64(len(payload)) + 1, false},
		{"uncompressed size one smaller", uint64(len(payload)) - 1, false},
		// The sizes only reach the comparison after the ZIP64 extra field is
		// resolved; comparing the 32-bit sentinels would see two equal values.
		{"zip64 uncompressed size one larger", uint64(len(payload)) + 1, true},
		{"zip64 uncompressed size one smaller", uint64(len(payload)) - 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := buildRawZip(t, []rawZipEntry{
				{name: TDFPayloadFileName, data: payload, uncompressedSize: tc.uncompressedSize, zip64: tc.zip64},
				{name: TDFManifestFileName, data: []byte(`{"m":1}`)},
			}, tc.zip64)

			_, err := NewReader(bytes.NewReader(data))
			require.ErrorIs(t, err, errZipFormat)
			require.ErrorContains(t, err, "stored entry")
			require.ErrorContains(t, err, TDFPayloadFileName)
		})
	}
}

// zip64ExtraField encodes a ZIP64 extended information extra field carrying
// exactly the given values, in APPNOTE order.
func zip64ExtraField(t *testing.T, values ...uint64) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	require.NoError(t, binary.Write(buf, binary.LittleEndian, uint16(zip64ExternalID)))
	require.NoError(t, binary.Write(buf, binary.LittleEndian, uint16(8*len(values))))
	for _, v := range values {
		require.NoError(t, binary.Write(buf, binary.LittleEndian, v))
	}
	return buf.Bytes()
}

// TestReaderResolvesZip64SentinelsBeforeComparingSizes pins that each size is
// taken from wherever the entry declares it. APPNOTE lets an entry defer one
// size to the ZIP64 extra field and keep the other in its 32-bit field, so
// comparing the raw fields would set a sentinel against a real value.
func TestReaderResolvesZip64SentinelsBeforeComparingSizes(t *testing.T) {
	payload := []byte("one size deferred to the zip64 extra field")
	size := uint64(len(payload))

	for _, tc := range []struct {
		name string
		// extraValues are the ZIP64 field's values, in APPNOTE order, for an
		// entry at offset 0 whose header offset is also deferred.
		extraValues []uint64
		deferred    func(*CDFileHeader)
		wantErr     bool
	}{
		{
			name:        "only the compressed size deferred",
			extraValues: []uint64{size, 0},
			deferred:    func(h *CDFileHeader) { h.CompressedSize = zip64MagicVal },
		},
		{
			name:        "only the uncompressed size deferred",
			extraValues: []uint64{size, 0},
			deferred:    func(h *CDFileHeader) { h.UncompressedSize = zip64MagicVal },
		},
		{
			name:        "deferred uncompressed size disagrees",
			extraValues: []uint64{size + 1, 0},
			deferred:    func(h *CDFileHeader) { h.UncompressedSize = zip64MagicVal },
			wantErr:     true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := buildRawZip(t, []rawZipEntry{{
				name:        TDFPayloadFileName,
				data:        payload,
				extraPrefix: zip64ExtraField(t, tc.extraValues...),
			}}, false)

			cdStart := int(cdStartOf(t, data))
			cdh := cdHeaderOf(t, data, cdStart)
			tc.deferred(&cdh)
			cdh.LocalHeaderOffset = zip64MagicVal
			data = overwrite(t, data, cdStart, cdh)

			reader, err := NewReader(bytes.NewReader(data))
			if tc.wantErr {
				require.ErrorIs(t, err, errZipFormat)
				require.ErrorContains(t, err, "stored entry")
				return
			}
			require.NoError(t, err)
			got, err := reader.ReadAllFileData(TDFPayloadFileName, oneMB)
			require.NoError(t, err)
			assert.Equal(t, payload, got)
		})
	}
}

// TestReaderIgnoresLocalHeaderSizes pins which copy of the sizes is compared.
// Streaming writers -- this package, web-sdk, archive/zip -- set bit 3, write
// zero sizes in the local header, and append a data descriptor. Only the
// central directory carries the sizes, so checking the local header's would
// reject every one of their archives.
func TestReaderIgnoresLocalHeaderSizes(t *testing.T) {
	payload := []byte("sizes live in the central directory")
	data := buildRawZip(t, []rawZipEntry{{name: TDFPayloadFileName, data: payload}}, false)

	// The entry's local header sits at offset 0.
	lfh := LocalFileHeader{}
	require.NoError(t, binary.Read(bytes.NewReader(data), binary.LittleEndian, &lfh))
	require.Equal(t, uint32(fileHeaderSignature), lfh.Signature)
	lfh.GeneralPurposeBitFlag |= dataDescriptorBitFlag
	lfh.CompressedSize = 0
	lfh.UncompressedSize = 0

	reader, err := NewReader(bytes.NewReader(overwrite(t, data, 0, lfh)))
	require.NoError(t, err)
	got, err := reader.ReadAllFileData(TDFPayloadFileName, oneMB)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// TestReaderRejectsCentralDirectorySizeMismatch covers the declared central
// directory size, which the reader used to ignore. It has to fit between the
// start of the central directory and the record after it, and the records
// walked from that start have to fill it exactly.
func TestReaderRejectsCentralDirectorySizeMismatch(t *testing.T) {
	payload, manifest := twoEntryFixture()
	entries := []rawZipEntry{payload, manifest}

	for _, zip64 := range []bool{false, true} {
		honest := buildRawZip(t, entries, zip64)
		_, err := NewReader(bytes.NewReader(honest))
		require.NoError(t, err, "the unmodified fixture has to parse")

		// setSize rewrites the declared size wherever this archive keeps it.
		setSize := func(t *testing.T, size uint64) []byte {
			if !zip64 {
				eocd := eocdOf(t, honest)
				eocd.SizeOfCentralDirectory = uint32(size)
				return overwrite(t, honest, len(honest)-endOfCDRecordSize, eocd)
			}
			record, off := zip64EOCDOf(t, honest)
			record.CentralDirectorySize = size
			return overwrite(t, honest, off, record)
		}

		trailer := "end of central directory record"
		var cdSize uint64
		if zip64 {
			trailer = "zip64 end of central directory record"
			record, _ := zip64EOCDOf(t, honest)
			cdSize = record.CentralDirectorySize
		} else {
			cdSize = uint64(eocdOf(t, honest).SizeOfCentralDirectory)
		}

		for _, tc := range []struct {
			name    string
			size    uint64
			wantErr string
		}{
			// The DSPX-5354 repro: far past the end of the file.
			{"size 0xfffffff0", 0xfffffff0, "runs past the " + trailer},
			{"one byte too large", cdSize + 1, "runs past the " + trailer},
			{"one byte too small", cdSize - 1, "central directory declares"},
			// Too small to hold even the declared number of records.
			{"zero", 0, "central directory entries declared"},
		} {
			name := tc.name
			if zip64 {
				name = "zip64 " + name
			}
			t.Run(name, func(t *testing.T) {
				_, err := NewReader(bytes.NewReader(setSize(t, tc.size)))
				require.ErrorIs(t, err, errZipFormat)
				require.ErrorContains(t, err, tc.wantErr)
			})
		}
	}
}
