package handlers

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// zipPrefix is the signature sdk.GetTdfType looks for. It is enough to route
// input down the Standard branch, which is where the option plumbing lives; the
// cases below all fail before anything reaches the SDK, so no platform
// connection and no real TDF is needed.
var zipPrefix = []byte{0x50, 0x4B, 0x03, 0x04}

func TestDecryptRejectsNonTDFInput(t *testing.T) {
	var out bytes.Buffer

	err := Handler{}.Decrypt(t.Context(), &out, bytes.NewReader([]byte("not a tdf at all")), DecryptOptions{})

	require.EqualError(t, err, "invalid TDF")
	assert.Empty(t, out.Bytes(), "a rejected input must not produce output")
}

// GetTdfType cannot read four bytes from an empty input, so it reports Invalid
// rather than a read error. Worth pinning: an empty spool is a plausible way to
// get here, and "invalid TDF" is the message the user sees for it.
func TestDecryptRejectsEmptyInput(t *testing.T) {
	var out bytes.Buffer

	err := Handler{}.Decrypt(t.Context(), &out, bytes.NewReader(nil), DecryptOptions{})

	require.EqualError(t, err, "invalid TDF")
	assert.Empty(t, out.Bytes())
}

func TestDecryptAssertionVerificationKeyErrors(t *testing.T) {
	dir := t.TempDir()

	malformed := filepath.Join(dir, "malformed.json")
	require.NoError(t, os.WriteFile(malformed, []byte("{not json"), 0o600))

	badKey := filepath.Join(dir, "bad-key.json")
	require.NoError(t, os.WriteFile(badKey,
		[]byte(`{"keys":{"assertion1":{"alg":"RS256","key":"not a pem block"}}}`), 0o600))

	for _, tc := range []struct {
		name    string
		file    string
		wantMsg string
	}{
		{
			name:    "missing file",
			file:    filepath.Join(dir, "does-not-exist.json"),
			wantMsg: "unable to read assertions verification keys file",
		},
		{
			name:    "malformed json",
			file:    malformed,
			wantMsg: "unable to unmarshal assertion verification keys json",
		},
		{
			name:    "unusable key",
			file:    badKey,
			wantMsg: "error with assertion signing key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer

			err := Handler{}.Decrypt(t.Context(), &out, bytes.NewReader(zipPrefix), DecryptOptions{
				AssertionVerificationKeysFile: tc.file,
			})

			require.ErrorContains(t, err, tc.wantMsg)
			assert.Empty(t, out.Bytes(), "an option failure must not produce output")
		})
	}
}

func TestInspectTDFRejectsNonTDFInput(t *testing.T) {
	result, errs := Handler{}.InspectTDF(bytes.NewReader([]byte("not a tdf at all")))

	require.Len(t, errs, 1)
	require.ErrorIs(t, errs[0], ErrTDFInspectFailNotValidTDF)
	assert.Nil(t, result.ZTDFManifest)
}
