package handlers

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/opentdf/platform/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecryptReturnsTypedAssertionErrors checks that the SDK's typed failure,
// with its reason, reaches the caller unchanged, so the CLI prints it.
func TestDecryptReturnsTypedAssertionErrors(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for name, body := range map[string]string{
		"0.payload":       "not really ciphertext",
		"0.manifest.json": `{"payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":true},"encryptionInformation":{},"assertions":[{"id":"classification","ID":"system-metadata"}]}`,
	} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		require.NoError(t, err)
		_, err = w.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())

	var out bytes.Buffer
	h := Handler{sdk: &sdk.SDK{}}
	err := h.Decrypt(t.Context(), &out, bytes.NewReader(archive.Bytes()), DecryptOptions{IgnoreAllowlist: true})

	var failure sdk.ErrAssertionFailure
	require.ErrorAs(t, err, &failure)
	assert.Equal(t, sdk.AssertionReasonAmbiguousMember, failure.Reason)
	assert.Equal(t, "classification", failure.ID)
	require.ErrorIs(t, err, sdk.ErrTampered)
	assert.Contains(t, err.Error(), "reason=ambiguous-member")
	assert.Contains(t, err.Error(), "id: classification")
	assert.Empty(t, out.Bytes())
}
