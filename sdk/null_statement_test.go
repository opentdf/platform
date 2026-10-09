package sdk

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression fixtures for DSPX-5102 / opentdf/platform#4202: a JSON null
// statement must not panic the caller.

// nullStatementManifestJSON carries a case-variant duplicate of "statement"
// whose value is null. encoding/json matches keys case-insensitively, so it
// runs Statement.UnmarshalJSON with "null", which used to dereference nil.
const nullStatementManifestJSON = `{"payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":true},"encryptionInformation":{},` +
	`"assertions":[{"id":"a","type":"other","scope":"tdo","appliesToState":"encrypted","statement":{"value":"ok"},"Statement":null}]}`

// The null-statement manifest is schema-valid, so IsValidTdf accepts it, and
// LoadTDF defers key access to the first read. What matters is that nothing
// panics: LoadTDF used to dereference nil while decoding the manifest, and
// the first read of this keyless TDF must fail cleanly.
func TestNullStatementManifestDoesNotPanic(t *testing.T) {
	data := zipWithManifest(t, nullStatementManifestJSON)

	require.NotPanics(t, func() { _, _ = IsValidTdf(bytes.NewReader(data)) })

	s := newLoadTestSDK()
	for _, intensity := range []SchemaValidationIntensity{Skip, Lax, Strict} {
		var (
			r   *Reader
			err error
		)
		require.NotPanics(t, func() {
			r, err = s.LoadTDF(bytes.NewReader(data), WithSchemaValidation(intensity), WithIgnoreAllowlist(true))
		})
		require.NoError(t, err)
		require.Len(t, r.manifest.Assertions, 1)
		assert.Equal(t, "ok", r.manifest.Assertions[0].Statement.Value)

		require.NotPanics(t, func() { _, err = r.WriteTo(io.Discard) })
		require.Error(t, err)
	}
}

func TestStatementUnmarshalJSONNull(t *testing.T) {
	t.Run("literal null is a no-op", func(t *testing.T) {
		s := Statement{Format: "f", Schema: "s", Value: "v"}
		require.NoError(t, s.UnmarshalJSON([]byte("null")))
		require.NoError(t, s.UnmarshalJSON([]byte(" null\n")))
		assert.Equal(t, Statement{Format: "f", Schema: "s", Value: "v"}, s)
	})

	t.Run("case-variant null key keeps the earlier statement", func(t *testing.T) {
		var a Assertion
		require.NotPanics(t, func() {
			require.NoError(t, json.Unmarshal([]byte(`{"statement":{"value":"ok"},"Statement":null}`), &a))
		})
		assert.Equal(t, "ok", a.Statement.Value)
	})

	t.Run("manifest", func(t *testing.T) {
		var m Manifest
		require.NotPanics(t, func() {
			require.NoError(t, json.Unmarshal([]byte(nullStatementManifestJSON), &m))
		})
		require.Len(t, m.Assertions, 1)
		assert.Equal(t, "ok", m.Assertions[0].Statement.Value)
	})
}
