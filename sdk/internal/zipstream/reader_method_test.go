// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// deflate compresses data as a raw DEFLATE stream, the form ZIP method 8 holds.
func deflate(tb testing.TB, data []byte) []byte {
	tb.Helper()

	buf := &bytes.Buffer{}
	w, err := flate.NewWriter(buf, flate.BestCompression)
	require.NoError(tb, err)
	_, err = w.Write(data)
	require.NoError(tb, err)
	require.NoError(tb, w.Close())
	return buf.Bytes()
}

// TestReaderRejectsNonStoredEntries covers DSPX-5354's TDF profile check. The
// reader returns entry bytes verbatim, so it used to hand back a deflated
// payload as ciphertext and a deflated manifest as JSON. Every entry has to be
// STORED, and anything else is refused when the archive is opened.
func TestReaderRejectsNonStoredEntries(t *testing.T) {
	plain := make([]byte, 64)
	deflated := deflate(t, plain)

	for _, tc := range []struct {
		name  string
		entry rawZipEntry
	}{
		{
			name:  "deflated",
			entry: rawZipEntry{data: deflated, method: zip.Deflate, uncompressedSize: uint64(len(plain))},
		},
		// Declaring method 8 over bytes that are not compressed is refused on
		// the declaration alone; the reader does not guess.
		{"deflate declared on stored bytes", rawZipEntry{data: plain, method: zip.Deflate}},
		{"bzip2", rawZipEntry{data: plain, method: 12}},
		{"lzma", rawZipEntry{data: plain, method: 14}},
		{"zstd", rawZipEntry{data: plain, method: 93}},
		{"aes", rawZipEntry{data: plain, method: 99}},
	} {
		for _, name := range []string{TDFPayloadFileName, TDFManifestFileName} {
			t.Run(tc.name+" "+name, func(t *testing.T) {
				entry := tc.entry
				entry.name = name
				entries := []rawZipEntry{entry, {name: TDFManifestFileName, data: []byte(`{"m":1}`)}}
				if name == TDFManifestFileName {
					entries = []rawZipEntry{{name: TDFPayloadFileName, data: plain}, entry}
				}

				_, err := NewReader(bytes.NewReader(buildRawZip(t, entries, false)))
				require.ErrorIs(t, err, zip.ErrAlgorithm)
				require.ErrorContains(t, err, strconv.Quote(name))
				require.ErrorContains(t, err, "compression method "+strconv.Itoa(int(entry.method)))
			})
		}
	}
}
