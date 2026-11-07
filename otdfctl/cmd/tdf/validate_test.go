package tdf

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validTDF was written by the Go SDK (CreateTDF, one RSA-wrapped key access
// object). Its private key was discarded; only its structure matters here.
const validTDF = "testdata/valid.tdf"

func writeTemp(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input")
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

func TestValidateFileAcceptsATDF(t *testing.T) {
	result, err := validateFile(validTDF)
	require.NoError(t, err)
	assert.Equal(t, validateResult{Valid: true}, result)
}

func TestValidateFileRejectsNonTDFs(t *testing.T) {
	tdf, err := os.ReadFile(validTDF)
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		content []byte
	}{
		{name: "text", content: []byte(strings.Repeat("this is not a TDF\n", 8))},
		// Shorter than a ZIP end-of-central-directory record, so the SDK's first
		// seek fails. That is a property of the file, not an I/O fault.
		{name: "shorter than a zip trailer", content: []byte("PK")},
		{name: "empty", content: nil},
		{name: "truncated TDF", content: tdf[:len(tdf)-10]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := validateFile(writeTemp(t, tc.content))
			require.NoError(t, err, "an invalid TDF is a result, not a failure to check")
			assert.False(t, result.Valid)
			assert.NotEmpty(t, result.Reason)
		})
	}
}

func TestValidateFileFailsWhenItCannotCheck(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		_, err := validateFile(filepath.Join(t.TempDir(), "missing.tdf"))
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
	t.Run("directory", func(t *testing.T) {
		_, err := validateFile(t.TempDir())
		require.ErrorContains(t, err, "not a regular file")
	})
}

// failingReader seeks like a regular file but every read fails, the way a file
// on a failing disk or a dropped network mount does.
type failingReader struct {
	*bytes.Reader
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: "valid.tdf", Err: syscall.EIO}
}

func TestValidateReaderReportsReadFailures(t *testing.T) {
	tdf, err := os.ReadFile(validTDF)
	require.NoError(t, err)

	_, err = validateReader(failingReader{bytes.NewReader(tdf)})
	require.ErrorIs(t, err, syscall.EIO, "a read failure must not be reported as an invalid TDF")
}

func TestWriteValidateResultIsOneLine(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result validateResult
		want   string
	}{
		{name: "valid", result: validateResult{Valid: true}, want: `{"valid":true}` + "\n"},
		{
			name:   "invalid",
			result: validateResult{Reason: `manifest: <payload> & "type" missing`},
			// Not HTML-escaped, so the reason reads the same as the SDK error.
			want: `{"valid":false,"reason":"manifest: <payload> & \"type\" missing"}` + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, writeValidateResult(&buf, tc.result))
			assert.Equal(t, tc.want, buf.String())
		})
	}
}
