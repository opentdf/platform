package sdk

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func namedManifestZip(t testing.TB, name, manifest string) []byte {
	t.Helper()

	buf := &bytes.Buffer{}
	w := zip.NewWriter(buf)
	for _, f := range []struct{ name, body string }{
		{"0.payload", "payload"},
		{name, manifest},
	} {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Store})
		require.NoError(t, err)
		_, err = fw.Write([]byte(f.body))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

type manifestReadSeeker struct {
	*bytes.Reader
	dataOffset int64
	dataLength int64
	dataReads  int
}

func (r *manifestReadSeeker) Read(p []byte) (int, error) {
	pos, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	n, err := r.Reader.Read(p)
	readStart := max(pos, r.dataOffset)
	readEnd := min(pos+int64(n), r.dataOffset+r.dataLength)
	if readStart < readEnd {
		r.dataReads += int(readEnd - readStart)
	}
	return n, err
}

func manifestDataOffset(t *testing.T, data []byte, name string) int64 {
	t.Helper()

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	for _, file := range reader.File {
		if file.Name == name {
			offset, err := file.DataOffset()
			require.NoError(t, err)
			return offset
		}
	}
	t.Fatalf("manifest entry %q not found", name)
	return 0
}

// IsValidTdf uses a 10 MiB detection bound even though LoadTDF's manifest
// limit remains opt-in for callers that need larger TDFs.
func TestIsValidTdf_DefaultManifestSizeCap(t *testing.T) {
	manifest := `{"payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":true},` +
		`"encryptionInformation":{},"pad":"` + strings.Repeat("a", defaultIsValidTDFManifestMaxSize) + `"}`

	valid, err := IsValidTdf(bytes.NewReader(namedManifestZip(t, "0.manifest.json", manifest)))
	assert.False(t, valid)
	require.ErrorIs(t, err, ErrTDFManifestTooLarge)
}

func TestIsValidTdf_WithMaxManifestSize_RejectsManifestBeforeReading(t *testing.T) {
	manifest := minimalManifestJSON + strings.Repeat(" ", 64)
	for _, name := range []string{"manifest.json", "0.manifest.json"} {
		t.Run(name, func(t *testing.T) {
			data := namedManifestZip(t, name, manifest)
			tracked := &manifestReadSeeker{
				Reader:     bytes.NewReader(data),
				dataOffset: manifestDataOffset(t, data, name),
				dataLength: int64(len(manifest)),
			}

			valid, err := IsValidTdf(tracked, WithMaxManifestSize(int64(len(manifest)-1)))
			assert.False(t, valid)
			require.ErrorIs(t, err, ErrTDFManifestTooLarge)
			assert.Zero(t, tracked.dataReads, "manifest size must be checked before reading entry data")
		})
	}
}

func TestIsValidTdf_WithMaxManifestSize_SpecNameDoesNotFallBack(t *testing.T) {
	validManifest := minimalManifestJSON
	oversizedManifest := validManifest + strings.Repeat(" ", 64)
	buf := &bytes.Buffer{}
	w := zip.NewWriter(buf)
	for _, f := range []struct{ name, body string }{
		{"0.payload", "payload"},
		{"0.manifest.json", validManifest},
		{"manifest.json", oversizedManifest},
	} {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Store})
		require.NoError(t, err)
		_, err = fw.Write([]byte(f.body))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	data := buf.Bytes()

	valid, err := IsValidTdf(bytes.NewReader(data), WithMaxManifestSize(int64(len(oversizedManifest)-1)))
	assert.False(t, valid)
	require.ErrorIs(t, err, ErrTDFManifestTooLarge)
}

func TestIsValidTdf_WithMaxManifestSize_AcceptsManifestOverDefault(t *testing.T) {
	manifest := minimalManifestJSON + strings.Repeat(" ", defaultIsValidTDFManifestMaxSize)
	valid, err := IsValidTdf(
		bytes.NewReader(namedManifestZip(t, "manifest.json", manifest)),
		WithMaxManifestSize(int64(len(manifest))),
	)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestIsValidTdf_OrdinaryZIP(t *testing.T) {
	buf := &bytes.Buffer{}
	w := zip.NewWriter(buf)
	file, err := w.Create("ordinary.txt")
	require.NoError(t, err)
	_, err = file.Write([]byte("not a TDF"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	valid, err := IsValidTdf(bytes.NewReader(buf.Bytes()))
	assert.False(t, valid)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrTDFManifestTooLarge)
}

func TestIsValidTdf_WithMaxManifestSize_MalformedManifest(t *testing.T) {
	valid, err := IsValidTdf(
		bytes.NewReader(namedManifestZip(t, "manifest.json", "{")),
		WithMaxManifestSize(1024),
	)
	assert.False(t, valid)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrTDFManifestTooLarge)
}

func TestIsValidTdf_WithSchemaValidationSkip(t *testing.T) {
	valid, err := IsValidTdf(
		bytes.NewReader(namedManifestZip(t, "manifest.json", "{")),
		WithSchemaValidation(Skip),
	)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestIsValidTdf_WithMaxManifestSize_RejectsNonPositiveSize(t *testing.T) {
	for _, size := range []int64{0, -1} {
		valid, err := IsValidTdf(bytes.NewReader(nil), WithMaxManifestSize(size))
		assert.False(t, valid)
		require.ErrorContains(t, err, "greater than 0")
	}
}
