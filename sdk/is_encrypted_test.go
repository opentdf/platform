package sdk

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DSPX-5102: cleartext-flagged TDFs are unsupported, so both manifest schemas
// reject payload.isEncrypted=false. The field is optional and defaults to
// true, so omitting it stays valid.

// cleartextManifestJSON is minimalManifestJSON declaring a cleartext payload.
var cleartextManifestJSON = strings.Replace(minimalManifestJSON, `"isEncrypted":true`, `"isEncrypted":false`, 1)

var schemaIntensities = []SchemaValidationIntensity{Lax, Strict}

func TestIsEncryptedFalseRejected(t *testing.T) {
	valid, err := IsValidTdf(bytes.NewReader(zipWithManifest(t, cleartextManifestJSON)))
	assert.False(t, valid)
	require.ErrorIs(t, err, ErrInvalidPerSchema)

	data := zipWithManifest(t, cleartextManifestJSON)
	s := newLoadTestSDK()
	for _, intensity := range schemaIntensities {
		r, err := s.LoadTDF(bytes.NewReader(data), WithSchemaValidation(intensity), WithIgnoreAllowlist(true))
		require.ErrorIs(t, err, ErrInvalidPerSchema)
		assert.Contains(t, err.Error(), "isEncrypted")
		assert.Nil(t, r)
	}

	// Without schema validation (the LoadTDF default) the flag is not
	// consulted: the reader always treats the payload as ciphertext, so a
	// false flag cannot downgrade it to a cleartext read.
	r, err := s.LoadTDF(bytes.NewReader(data), WithIgnoreAllowlist(true))
	require.NoError(t, err)
	_, err = r.WriteTo(io.Discard)
	require.Error(t, err)
}

func TestIsEncryptedTrueOrMissingAccepted(t *testing.T) {
	missing := strings.Replace(minimalManifestJSON, `,"isEncrypted":true`, ``, 1)
	require.NotEqual(t, minimalManifestJSON, missing, "fixture must contain isEncrypted:true")

	s := newLoadTestSDK()
	for name, manifest := range map[string]string{"true": minimalManifestJSON, "missing": missing} {
		t.Run(name, func(t *testing.T) {
			data := zipWithManifest(t, manifest)

			valid, err := IsValidTdf(bytes.NewReader(data))
			require.NoError(t, err)
			assert.True(t, valid)

			for _, intensity := range schemaIntensities {
				r, err := s.LoadTDF(bytes.NewReader(data), WithSchemaValidation(intensity), WithIgnoreAllowlist(true))
				require.NoError(t, err)
				assert.NotNil(t, r)
			}
		})
	}
}

// Every SDK writer funnels through chunkedWriter.buildManifest; CreateTDF is
// the public entry point. The written manifest must declare isEncrypted:true
// and pass both schemas.
func TestWritersAlwaysEmitIsEncryptedTrue(t *testing.T) {
	buf := &bytes.Buffer{}
	_, err := newLoadTestSDK().CreateTDF(buf, bytes.NewReader([]byte("hello")), func(c *TDFConfig) error {
		c.kasInfoList = []KASInfo{{URL: "https://kas.example.com", PublicKey: mockRSAPublicKey1, Default: true}}
		return nil
	})
	require.NoError(t, err)

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	f, err := zr.Open("0.manifest.json")
	require.NoError(t, err)
	defer f.Close()
	raw, err := io.ReadAll(f)
	require.NoError(t, err)

	var parsed struct {
		Payload struct {
			IsEncrypted *bool `json:"isEncrypted"`
		} `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(raw, &parsed))
	require.NotNil(t, parsed.Payload.IsEncrypted, "writer must emit isEncrypted")
	assert.True(t, *parsed.Payload.IsEncrypted)

	for _, intensity := range schemaIntensities {
		valid, err := isValidManifest(string(raw), intensity)
		require.NoError(t, err)
		assert.True(t, valid)
	}
}
