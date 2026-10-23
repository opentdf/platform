package sdk

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/opentdf/platform/sdk/internal/zipstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// probeEntry is one entry for buildProbeZip.
type probeEntry struct {
	name string
	// data is written verbatim as the entry's bytes.
	data []byte
	// method is the compression method declared in both headers.
	method uint16
	// crcOf is what the declared CRC-32 covers. Nil means data.
	crcOf []byte
	// uncompressedSize is the declared uncompressed size. Zero means len(data).
	uncompressedSize uint32
}

// buildProbeZip assembles an archive byte for byte, with the declared sizes in
// both the local header and the central directory and no ZIP64 records. It
// follows gen.py in the xtest validity corpus (DSPX-5349), so these tests and
// the cross-SDK cases describe the same archives. A nonzero cdSize replaces
// the central directory size declared in the end of central directory record.
func buildProbeZip(t *testing.T, entries []probeEntry, cdSize uint32) []byte {
	t.Helper()

	const zipVersion = 20
	body := &bytes.Buffer{}
	cd := &bytes.Buffer{}
	for _, e := range entries {
		crcOf := e.crcOf
		if crcOf == nil {
			crcOf = e.data
		}
		usize := e.uncompressedSize
		if usize == 0 {
			usize = uint32(len(e.data))
		}
		offset := uint32(body.Len())

		require.NoError(t, binary.Write(body, binary.LittleEndian, zipstream.LocalFileHeader{
			Signature:         0x04034b50,
			Version:           zipVersion,
			CompressionMethod: e.method,
			Crc32:             crc32.ChecksumIEEE(crcOf),
			CompressedSize:    uint32(len(e.data)),
			UncompressedSize:  usize,
			FilenameLength:    uint16(len(e.name)),
		}))
		body.WriteString(e.name)
		body.Write(e.data)

		require.NoError(t, binary.Write(cd, binary.LittleEndian, zipstream.CDFileHeader{
			Signature:         0x02014b50,
			VersionCreated:    zipVersion,
			VersionNeeded:     zipVersion,
			CompressionMethod: e.method,
			Crc32:             crc32.ChecksumIEEE(crcOf),
			CompressedSize:    uint32(len(e.data)),
			UncompressedSize:  usize,
			FilenameLength:    uint16(len(e.name)),
			LocalHeaderOffset: offset,
		}))
		cd.WriteString(e.name)
	}

	if cdSize == 0 {
		cdSize = uint32(cd.Len())
	}
	cdOffset := uint32(body.Len())
	body.Write(cd.Bytes())
	require.NoError(t, binary.Write(body, binary.LittleEndian, zipstream.EndOfCDRecord{
		Signature:               0x06054b50,
		NumberOfCDRecordEntries: uint16(len(entries)),
		TotalCDRecordEntries:    uint16(len(entries)),
		SizeOfCentralDirectory:  cdSize,
		CentralDirectoryOffset:  cdOffset,
	}))
	return body.Bytes()
}

// zipProfileCase is an archive with a schema-valid manifest that IsValidTdf
// and LoadTDF must refuse at the ZIP layer.
type zipProfileCase struct {
	name    string
	archive []byte
	// check asserts which reader check refused the archive.
	check func(t *testing.T, err error)
}

func errorContains(substr string) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		t.Helper()
		require.ErrorContains(t, err, substr)
	}
}

func zipProfileFixtures(t *testing.T) (probeEntry, probeEntry) {
	t.Helper()
	return probeEntry{name: zipstream.TDFPayloadFileName, data: make([]byte, 64)},
		probeEntry{name: zipstream.TDFManifestFileName, data: []byte(minimalManifestJSON)}
}

// zipProfileCases are the DSPX-5354 repros: archives web-sdk's isValidTdf
// rejects that IsValidTdf accepted.
func zipProfileCases(t *testing.T) []zipProfileCase {
	t.Helper()
	payload, manifest := zipProfileFixtures(t)

	mismatched := payload
	mismatched.uncompressedSize = uint32(len(payload.data)) + 1

	return []zipProfileCase{
		{
			name:    "0.payload compressed size differs from uncompressed size",
			archive: buildProbeZip(t, []probeEntry{mismatched, manifest}, 0),
			check:   errorContains("stored entry"),
		},
		{
			name:    "EOCD central directory size 0xfffffff0",
			archive: buildProbeZip(t, []probeEntry{manifest}, 0xfffffff0),
			check:   errorContains("runs past the end of central directory record"),
		},
	}
}

// TestZipProfileControls pins that buildProbeZip's honest archives open, so
// each repro below fails for the one field it changes.
func TestZipProfileControls(t *testing.T) {
	payload, manifest := zipProfileFixtures(t)

	for _, tc := range []struct {
		name    string
		entries []probeEntry
	}{
		{"manifest only", []probeEntry{manifest}},
		{"payload and manifest", []probeEntry{payload, manifest}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := buildProbeZip(t, tc.entries, 0)

			valid, err := IsValidTdf(bytes.NewReader(archive))
			require.NoError(t, err)
			assert.True(t, valid)

			_, err = newLoadTestSDK().LoadTDF(bytes.NewReader(archive), WithIgnoreAllowlist(true))
			require.NoError(t, err)
		})
	}
}

// TestIsValidTdf_RejectsZipProfileViolations covers DSPX-5354 through both
// public entry points. LoadTDF opens the archive with the same reader as
// IsValidTdf, so it has to refuse the same archives.
func TestIsValidTdf_RejectsZipProfileViolations(t *testing.T) {
	for _, tc := range zipProfileCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := IsValidTdf(bytes.NewReader(tc.archive))
			require.Error(t, err)
			assert.False(t, valid)
			tc.check(t, err)

			_, err = newLoadTestSDK().LoadTDF(bytes.NewReader(tc.archive), WithIgnoreAllowlist(true))
			require.Error(t, err)
			tc.check(t, err)
		})
	}
}
