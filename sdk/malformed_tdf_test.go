package sdk

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression fixtures for DSPX-5102 / opentdf/platform#4202: untrusted files
// handed to IsValidTdf or LoadTDF must be rejected with an error, never panic
// the caller.

// minimalManifestJSON is a manifest that satisfies the lax schema; isEncrypted
// is left as a parameter so tests can flip it.
func minimalManifestJSON(isEncrypted bool) string {
	enc := "true"
	if !isEncrypted {
		enc = "false"
	}
	return `{"payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":` + enc +
		`},"encryptionInformation":{}}`
}

// nullStatementManifestJSON carries a case-variant duplicate of "statement"
// whose value is null. encoding/json matches keys case-insensitively, so it
// runs Statement.UnmarshalJSON with "null", which used to dereference nil.
const nullStatementManifestJSON = `{"payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":true},"encryptionInformation":{},` +
	`"assertions":[{"id":"a","type":"other","scope":"tdo","appliesToState":"encrypted","statement":{"value":"ok"},"Statement":null}]}`

// zipWithManifest stores manifest and a small payload in a well-formed zip.
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

// malformedZip64ManifestTDF builds the archive from #4202: a single
// 0.manifest.json entry whose central directory compressed size is the ZIP64
// sentinel 0xFFFFFFFF, with a ZIP64 extra field declaring a stored size of
// 0xFFFFFFFFFFFFFFFF. Narrowed to int64 that is -1, which used to reach
// make([]byte, -1).
func malformedZip64ManifestTDF(t testing.TB) []byte {
	t.Helper()
	const (
		name             = "0.manifest.json"
		zipVersion       = 45
		zip64Sentinel    = 0xFFFFFFFF
		zip64ExtraTag    = 0x0001
		uint64Size       = 8
		extraHeaderBytes = 4
	)
	data := []byte(minimalManifestJSON(true))
	le := binary.LittleEndian
	buf := &bytes.Buffer{}
	write := func(v any) { require.NoError(t, binary.Write(buf, le, v)) }

	// Local file header.
	write(uint32(0x04034b50))
	write(uint16(zipVersion))       // version needed
	write(uint16(0))                // flags
	write(uint16(0))                // method: stored
	write(uint16(0))                // mod time
	write(uint16(0))                // mod date
	write(crc32.ChecksumIEEE(data)) // crc32
	write(uint32(len(data)))        // compressed size
	write(uint32(len(data)))        // uncompressed size
	write(uint16(len(name)))        // filename length
	write(uint16(0))                // extra length
	buf.WriteString(name)
	buf.Write(data)

	// Central directory header.
	cdOffset := buf.Len()
	write(uint32(0x02014b50))
	write(uint16(zipVersion))                    // version made by
	write(uint16(zipVersion))                    // version needed
	write(uint16(0))                             // flags
	write(uint16(0))                             // method
	write(uint16(0))                             // mod time
	write(uint16(0))                             // mod date
	write(crc32.ChecksumIEEE(data))              // crc32
	write(uint32(zip64Sentinel))                 // compressed size: see ZIP64 extra
	write(uint32(len(data)))                     // uncompressed size
	write(uint16(len(name)))                     // filename length
	write(uint16(extraHeaderBytes + uint64Size)) // extra length
	write(uint16(0))                             // comment length
	write(uint16(0))                             // disk number start
	write(uint16(0))                             // internal attrs
	write(uint32(0))                             // external attrs
	write(uint32(0))                             // local header offset
	buf.WriteString(name)
	write(uint16(zip64ExtraTag))
	write(uint16(uint64Size))
	write(uint64(math.MaxUint64)) // compressed size
	cdSize := buf.Len() - cdOffset

	// End of central directory record.
	write(uint32(0x06054b50))
	write(uint16(0)) // disk
	write(uint16(0)) // cd disk
	write(uint16(1)) // entries on disk
	write(uint16(1)) // entries total
	write(uint32(cdSize))
	write(uint32(cdOffset))
	write(uint16(0)) // comment length
	return buf.Bytes()
}

func TestIsValidTdf_MalformedZip64LengthRejected(t *testing.T) {
	data := malformedZip64ManifestTDF(t)
	var (
		valid bool
		err   error
	)
	require.NotPanics(t, func() { valid, err = IsValidTdf(bytes.NewReader(data)) })
	assert.False(t, valid)
	require.Error(t, err)
}

func TestLoadTDF_MalformedZip64LengthRejected(t *testing.T) {
	s := newLoadTestSDK()
	data := malformedZip64ManifestTDF(t)

	for _, intensity := range []SchemaValidationIntensity{Skip, Lax, Strict} {
		var (
			r   *Reader
			err error
		)
		require.NotPanics(t, func() {
			r, err = s.LoadTDF(bytes.NewReader(data), WithSchemaValidation(intensity), WithIgnoreAllowlist(true))
		})
		require.Error(t, err)
		assert.Nil(t, r)
	}
}

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

func TestIsEncryptedFalseRejected(t *testing.T) {
	t.Run("IsValidTdf", func(t *testing.T) {
		valid, err := IsValidTdf(bytes.NewReader(zipWithManifest(t, minimalManifestJSON(false))))
		assert.False(t, valid)
		require.ErrorIs(t, err, ErrInvalidPerSchema)

		valid, err = IsValidTdf(bytes.NewReader(zipWithManifest(t, minimalManifestJSON(true))))
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("lax schema", func(t *testing.T) {
		valid, err := isValidManifest(minimalManifestJSON(false), Lax)
		assert.False(t, valid)
		require.ErrorIs(t, err, ErrInvalidPerSchema)
		assert.Contains(t, err.Error(), "isEncrypted")

		valid, err = isValidManifest(minimalManifestJSON(true), Lax)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("strict schema", func(t *testing.T) {
		good := writtenManifest(t)
		valid, err := isValidManifest(good, Strict)
		require.NoError(t, err)
		require.True(t, valid)

		bad := strings.Replace(good, `"isEncrypted":true`, `"isEncrypted":false`, 1)
		require.NotEqual(t, good, bad, "fixture must contain isEncrypted:true")
		valid, err = isValidManifest(bad, Strict)
		assert.False(t, valid)
		require.ErrorIs(t, err, ErrInvalidPerSchema)
		assert.Contains(t, err.Error(), "isEncrypted")
	})

	t.Run("LoadTDF with schema validation", func(t *testing.T) {
		s := newLoadTestSDK()
		data := zipWithManifest(t, minimalManifestJSON(false))
		for _, intensity := range []SchemaValidationIntensity{Lax, Strict} {
			r, err := s.LoadTDF(bytes.NewReader(data), WithSchemaValidation(intensity), WithIgnoreAllowlist(true))
			require.ErrorIs(t, err, ErrInvalidPerSchema)
			assert.Nil(t, r)
		}
	})

	// Without schema validation (the LoadTDF default) the flag is not
	// consulted: the reader always treats the payload as ciphertext, so a
	// false flag cannot downgrade it to a cleartext read.
	t.Run("LoadTDF default skips schema validation", func(t *testing.T) {
		s := newLoadTestSDK()
		data := zipWithManifest(t, minimalManifestJSON(false))
		r, err := s.LoadTDF(bytes.NewReader(data), WithIgnoreAllowlist(true))
		require.NoError(t, err)
		_, err = r.WriteTo(io.Discard)
		require.Error(t, err)
	})
}

// newLoadTestSDK returns an SDK that can run LoadTDF without a platform.
func newLoadTestSDK() *SDK {
	s := newSDK()
	s.wellknownConfiguration = newMockWellKnownService(createWellKnown(nil), nil)
	s.conn = &ConnectRPCConnection{Client: http.DefaultClient}
	return s
}

// writtenManifest creates a TDF with the SDK writer and returns its manifest
// JSON as stored in the archive.
func writtenManifest(t *testing.T) string {
	t.Helper()
	s := newLoadTestSDK()
	buf := &bytes.Buffer{}
	obj, err := s.CreateTDF(buf, bytes.NewReader([]byte("hello")), func(c *TDFConfig) error {
		c.kasInfoList = []KASInfo{{URL: "https://kas.example.com", PublicKey: mockRSAPublicKey1, Default: true}}
		return nil
	})
	require.NoError(t, err)
	require.True(t, obj.manifest.IsEncrypted)

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	f, err := zr.Open("0.manifest.json")
	require.NoError(t, err)
	defer f.Close()
	m, err := io.ReadAll(f)
	require.NoError(t, err)
	return string(m)
}

// Every SDK writer funnels through chunkedWriter.buildManifest; CreateTDF is
// the public entry point. Cleartext-flagged TDFs are unsupported, so the
// written manifest must declare isEncrypted:true and pass both schemas.
func TestWritersAlwaysEmitIsEncryptedTrue(t *testing.T) {
	m := writtenManifest(t)

	var parsed struct {
		Payload map[string]json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal([]byte(m), &parsed))
	assert.JSONEq(t, "true", string(parsed.Payload["isEncrypted"]))

	for _, intensity := range []SchemaValidationIntensity{Lax, Strict} {
		valid, err := isValidManifest(m, intensity)
		require.NoError(t, err)
		assert.True(t, valid)
	}
}
