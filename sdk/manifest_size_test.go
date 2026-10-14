package sdk

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// IsValidTdf applies no manifest size cap: a schema-valid manifest past the
// former 10 MB default is accepted (DSPX-4502).
func TestIsValidTdf_NoDefaultManifestSizeCap(t *testing.T) {
	m := `{"payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":true},` +
		`"encryptionInformation":{},"pad":"` + strings.Repeat("a", 11*1024*1024) + `"}`

	buf := &bytes.Buffer{}
	w := zip.NewWriter(buf)
	for _, f := range []struct{ name, body string }{{"0.payload", "payload"}, {"0.manifest.json", m}} {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Store})
		require.NoError(t, err)
		_, err = fw.Write([]byte(f.body))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	valid, err := IsValidTdf(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	assert.True(t, valid)
}
