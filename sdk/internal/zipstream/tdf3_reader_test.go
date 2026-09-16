package zipstream

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rawZip(t *testing.T, members [][2]string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, m := range members {
		// TDF members are Stored; zipstream.Reader returns raw bytes at an offset.
		f, err := w.CreateHeader(&zip.FileHeader{Name: m[0], Method: zip.Store})
		require.NoError(t, err)
		_, err = f.Write([]byte(m[1]))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return bytes.NewReader(buf.Bytes())
}

func manifestJSON(url string) string {
	return `{"payload":{"type":"reference","url":"` + url + `","protocol":"zip","isEncrypted":true}}`
}

func TestTDFReader_SpecNames(t *testing.T) {
	r, err := NewTDFReader(rawZip(t, [][2]string{{"manifest.json", manifestJSON("0.payload")}, {"0.payload", "PAY"}}))
	require.NoError(t, err)
	assert.Equal(t, "manifest.json", r.ManifestFileName())
	assert.Equal(t, "0.payload", r.PayloadFileName())
	got, err := r.ReadPayload(0, 3)
	require.NoError(t, err)
	assert.Equal(t, "PAY", string(got))
}

func TestTDFReader_LegacyManifestName(t *testing.T) {
	r, err := NewTDFReader(rawZip(t, [][2]string{{"0.manifest.json", manifestJSON("0.payload")}, {"0.payload", "OLD"}}))
	require.NoError(t, err)
	assert.Equal(t, "0.manifest.json", r.ManifestFileName())
	m, err := r.Manifest()
	require.NoError(t, err)
	assert.Contains(t, m, `"url":"0.payload"`)
	size, err := r.PayloadSize()
	require.NoError(t, err)
	assert.Equal(t, int64(3), size)
}

func TestTDFReader_PrefersSpecManifestWhenBothPresent(t *testing.T) {
	r, err := NewTDFReader(rawZip(t, [][2]string{
		{"0.manifest.json", manifestJSON("b")},
		{"manifest.json", manifestJSON("a")},
		{"a", "A"}, {"b", "B"},
	}))
	require.NoError(t, err)
	got, err := r.ReadPayload(0, 1)
	require.NoError(t, err)
	assert.Equal(t, "A", string(got))
}

func TestTDFReader_PayloadFromURL(t *testing.T) {
	r, err := NewTDFReader(rawZip(t, [][2]string{{"manifest.json", manifestJSON("data.bin")}, {"data.bin", "XYZ"}}))
	require.NoError(t, err)
	assert.Equal(t, "data.bin", r.PayloadFileName())
	got, err := r.ReadPayload(1, 2)
	require.NoError(t, err)
	assert.Equal(t, "YZ", string(got))
}

func TestTDFReader_FallbackWhenURLEmpty(t *testing.T) {
	r, err := NewTDFReader(rawZip(t, [][2]string{{"manifest.json", manifestJSON("")}, {"0.payload", "FB"}}))
	require.NoError(t, err)
	assert.Equal(t, "0.payload", r.PayloadFileName())
}

func TestTDFReader_URLNamesMissingEntry(t *testing.T) {
	_, err := NewTDFReader(rawZip(t, [][2]string{{"manifest.json", manifestJSON("missing.bin")}, {"0.payload", "x"}}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing.bin")
}

func TestTDFReader_UnsafeURL(t *testing.T) {
	// manifestJSON splices bad directly into a JSON string literal, so a
	// single backslash (`a\b`) is consumed by the JSON decoder as the \b
	// (backspace) escape rather than surviving as a literal backslash; a
	// literal backslash after decoding requires doubling it here (`a\\b`).
	// isSafeEntryName rejects both: the decoded control character and the
	// decoded literal backslash.
	for _, bad := range []string{"../x", "/abs", `a\b`, `a\\b`, "x/../y"} {
		// The safety check fires before any lookup, so no payload member is needed.
		_, err := NewTDFReader(rawZip(t, [][2]string{{"manifest.json", manifestJSON(bad)}}))
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), "unsafe", bad)
	}
}

func TestTDFReader_MissingManifest(t *testing.T) {
	_, err := NewTDFReader(rawZip(t, [][2]string{{"0.payload", "x"}}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manifest.json")
}
