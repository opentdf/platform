package sdk

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DSPX-5102 / opentdf/platform#4202: the case-variant key "Statement" matches
// case-insensitively, so null reaches Statement.UnmarshalJSON.
const nullStatementManifestJSON = `{"payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":true},"encryptionInformation":{},` +
	`"assertions":[{"id":"a","type":"other","scope":"tdo","appliesToState":"encrypted","statement":{"value":"ok"},"Statement":null}]}`

// exactNullStatementManifestJSON reaches Statement.UnmarshalJSON with null
// through the exact member name, which spec Section 3 allows.
const exactNullStatementManifestJSON = `{"payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":true},"encryptionInformation":{},` +
	`"assertions":[{"id":"a","type":"other","scope":"tdo","appliesToState":"encrypted","statement":null}]}`

func TestNullStatementManifestDoesNotPanic(t *testing.T) {
	s := newLoadTestSDK()

	t.Run("case variant is rejected while parsing", func(t *testing.T) {
		data := zipWithManifest(t, nullStatementManifestJSON)
		var err error
		require.NotPanics(t, func() { _, err = IsValidTdf(bytes.NewReader(data)) })
		requireAssertionFailure(t, err, "a", AssertionReasonAmbiguousMember)

		for _, intensity := range []SchemaValidationIntensity{Skip, Lax, Strict} {
			require.NotPanics(t, func() {
				_, err = s.LoadTDF(bytes.NewReader(data), WithSchemaValidation(intensity), WithIgnoreAllowlist(true))
			})
			requireAssertionFailure(t, err, "a", AssertionReasonAmbiguousMember)
		}
	})

	t.Run("exact null statement loads", func(t *testing.T) {
		data := zipWithManifest(t, exactNullStatementManifestJSON)
		var err error
		require.NotPanics(t, func() { _, err = IsValidTdf(bytes.NewReader(data)) })
		require.ErrorIs(t, err, ErrInvalidPerSchema, "the schema, not Section 3, rejects a null statement")

		var r *Reader
		require.NotPanics(t, func() {
			r, err = s.LoadTDF(bytes.NewReader(data), WithSchemaValidation(Skip), WithIgnoreAllowlist(true))
		})
		require.NoError(t, err)
		require.Len(t, r.manifest.Assertions, 1)
		assert.Equal(t, Statement{}, r.manifest.Assertions[0].Statement)

		require.NotPanics(t, func() { _, err = r.WriteTo(io.Discard) })
		require.Error(t, err)
	})
}

func TestStatementUnmarshalJSONNull(t *testing.T) {
	t.Run("literal null is a no-op", func(t *testing.T) {
		s := Statement{Format: "f", Schema: "s", Value: "v"}
		require.NoError(t, s.UnmarshalJSON([]byte("null")))
		require.NoError(t, s.UnmarshalJSON([]byte(" null\n")))
		assert.Equal(t, Statement{Format: "f", Schema: "s", Value: "v"}, s)
	})

	t.Run("null as the only statement leaves it zero", func(t *testing.T) {
		var a Assertion
		require.NotPanics(t, func() {
			require.NoError(t, json.Unmarshal([]byte(`{"id":"a","statement":null}`), &a))
		})
		assert.Equal(t, Statement{}, a.Statement)
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
			err := json.Unmarshal([]byte(nullStatementManifestJSON), &m)
			requireAssertionFailure(t, err, "a", AssertionReasonAmbiguousMember)
		})
		require.NotPanics(t, func() {
			require.NoError(t, json.Unmarshal([]byte(exactNullStatementManifestJSON), &m))
		})
		require.Len(t, m.Assertions, 1)
		assert.Equal(t, Statement{}, m.Assertions[0].Statement)
	})
}

// Null-as-unset is only safe because the hash covers the statement, so
// tampering with a signed one fails verification.
func TestNullStatementChangesAssertionHash(t *testing.T) {
	signed := Assertion{
		ID:             "a",
		Type:           "other",
		Scope:          "tdo",
		AppliesToState: "encrypted",
		Statement:      Statement{Format: "f", Schema: "s", Value: "v"},
	}
	signedHash, err := signed.GetHash()
	require.NoError(t, err)

	var tampered Assertion
	require.NoError(t, json.Unmarshal([]byte(
		`{"id":"a","type":"other","scope":"tdo","appliesToState":"encrypted","statement":null}`), &tampered))
	tamperedHash, err := tampered.GetHash()
	require.NoError(t, err)

	assert.NotEqual(t, signedHash, tamperedHash)
}
