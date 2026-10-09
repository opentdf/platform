package sdk

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// minimalManifestJSON satisfies the lax schema.
const minimalManifestJSON = `{"payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":true},` +
	`"encryptionInformation":{}}`

func zipWithManifest(t testing.TB, manifest string) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	w := zip.NewWriter(buf)
	for _, f := range []struct{ name, body string }{
		{"0.payload", "not really ciphertext"},
		{"0.manifest.json", manifest},
	} {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Store})
		require.NoError(t, err)
		_, err = io.WriteString(fw, f.body)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// newLoadTestSDK returns an SDK that can run LoadTDF without a platform.
func newLoadTestSDK() *SDK {
	s := newSDK()
	s.wellknownConfiguration = newMockWellKnownService(createWellKnown(nil), nil)
	s.conn = &ConnectRPCConnection{Client: http.DefaultClient}
	return s
}
