package sdk

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// manifestTemplate is a minimal but structurally complete manifest. The two
// verbs take extra keys for the payload object and for the manifest root
// respectively, each of which must begin with a comma.
const manifestTemplate = `{
  "payload": {
    "type": "reference",
    "url": "0.payload",
    "protocol": "zip",
    "mimeType": "application/octet-stream",
    "isEncrypted": true%s
  },
  "encryptionInformation": {
    "type": "split",
    "policy": "eyJ1dWlkIjogIjEifQ==",
    "keyAccess": [],
    "method": {
      "algorithm": "AES-256-GCM",
      "iv": "",
      "isStreamable": true
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "cm9vdHNpZw=="
      },
      "segmentHashAlg": "GMAC",
      "segmentSizeDefault": 2097152,
      "encryptedSegmentSizeDefault": 2097180,
      "segments": []
    }
  }%s
}`

func testManifestJSON(payloadExtra, rootExtra string) string {
	return fmt.Sprintf(manifestTemplate, payloadExtra, rootExtra)
}

// assertManifestBodyDecoded checks the fields a manifest carries besides the
// spec version. Manifest has a custom UnmarshalJSON, so every case asserts the
// rest of the document still decodes -- a decoder that got the version right
// while quietly dropping the payload or the integrity information would
// otherwise look like a pass.
func assertManifestBodyDecoded(t *testing.T, m Manifest) {
	t.Helper()

	assert.Equal(t, "reference", m.Type)
	assert.Equal(t, "0.payload", m.URL)
	assert.Equal(t, "zip", m.Protocol)
	assert.Equal(t, "application/octet-stream", m.MimeType)
	assert.True(t, m.IsEncrypted)

	assert.Equal(t, "split", m.KeyAccessType)
	assert.Equal(t, "eyJ1dWlkIjogIjEifQ==", m.Policy)
	assert.Equal(t, "AES-256-GCM", m.Method.Algorithm)
	assert.Equal(t, "GMAC", m.SegmentHashAlgorithm)
	assert.Equal(t, int64(2097152), m.DefaultSegmentSize)
	assert.Equal(t, "cm9vdHNpZw==", m.Signature)
}

// TestManifest_UnmarshalJSON_SpecVersion covers reading tdf_spec_version, a
// deprecated name for the spec version that entered some specification drafts
// and some older OpenTDF documentation in error. schemaVersion is the canonical
// name and always wins; tdf_spec_version is read only so that files written
// against the deprecated name stay usable. Both placements it occurs in are
// read -- the root, which the spec prose documents and web-sdk writes, then
// payload, which revisions of the JSON schema declared in error.
func TestManifest_UnmarshalJSON_SpecVersion(t *testing.T) {
	tests := []struct {
		name         string
		payloadExtra string
		rootExtra    string
		want         string
	}{
		{
			name:      "schemaVersion at root",
			rootExtra: `,"schemaVersion":"4.3.0"`,
			want:      "4.3.0",
		},
		{
			// Where the spec prose documents it, and where web-sdk writes it.
			name:      "deprecated tdf_spec_version at root",
			rootExtra: `,"tdf_spec_version":"4.3.0"`,
			want:      "4.3.0",
		},
		{
			// Where revisions of the JSON schema declared it in error.
			name:         "deprecated tdf_spec_version under payload",
			payloadExtra: `,"tdf_spec_version":"4.3.0"`,
			want:         "4.3.0",
		},
		{
			name:         "schemaVersion wins over payload tdf_spec_version",
			payloadExtra: `,"tdf_spec_version":"4.2.0"`,
			rootExtra:    `,"schemaVersion":"4.3.0"`,
			want:         "4.3.0",
		},
		{
			name:      "schemaVersion wins over root tdf_spec_version",
			rootExtra: `,"schemaVersion":"4.3.0","tdf_spec_version":"4.2.0"`,
			want:      "4.3.0",
		},
		{
			// The root is the placement with the better provenance, so it decides
			// when the two copies disagree.
			name:         "root tdf_spec_version wins over the payload copy",
			payloadExtra: `,"tdf_spec_version":"4.2.0"`,
			rootExtra:    `,"tdf_spec_version":"4.3.0"`,
			want:         "4.3.0",
		},
		{
			// A null root copy is not a value, so the payload copy still applies.
			name:         "null root tdf_spec_version falls through to payload",
			payloadExtra: `,"tdf_spec_version":"4.3.0"`,
			rootExtra:    `,"tdf_spec_version":null`,
			want:         "4.3.0",
		},
		{
			// An empty schemaVersion is not a value, so the fallback still applies.
			name:         "empty schemaVersion falls back to tdf_spec_version",
			payloadExtra: `,"tdf_spec_version":"4.3.0"`,
			rootExtra:    `,"schemaVersion":""`,
			want:         "4.3.0",
		},
		{
			name: "no version at all",
			want: "",
		},
		{
			// The lax schema permits a null tdf_spec_version, so decoding has to
			// tolerate it rather than failing the whole manifest.
			name:         "null tdf_spec_version is ignored",
			payloadExtra: `,"tdf_spec_version":null`,
			want:         "",
		},
		{
			// Off-spec types are schema validation's problem to report, not the
			// decoder's to choke on.
			name:         "numeric tdf_spec_version is ignored",
			payloadExtra: `,"tdf_spec_version":430`,
			want:         "",
		},
		{
			name:         "object tdf_spec_version is ignored",
			payloadExtra: `,"tdf_spec_version":{"major":4}`,
			want:         "",
		},
		{
			// The decoder gates its off-spec pass on a substring scan for the
			// literal key, so a key spelled with JSON escapes is not found. The
			// fallback declines to fire rather than misreading anything, which
			// is the same "no version" this returned before the name was read
			// at all. Pinned because it is a deliberate limit, not an accident.
			name: "escaped tdf_spec_version key is not read",
			// The escape is "v": a decoder reading this sees the key
			// tdf_spec_version, but the raw bytes do not contain it.
			payloadExtra: `,"tdf_spec_\u0076ersion":"4.3.0"`,
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m Manifest
			require.NoError(t, json.Unmarshal([]byte(testManifestJSON(tt.payloadExtra, tt.rootExtra)), &m))
			assert.Equal(t, tt.want, m.TDFVersion)
			assertManifestBodyDecoded(t, m)
		})
	}
}

// TestManifest_Marshal_EmitsSchemaVersionOnly guards the writer side: manifests
// this SDK produces name the field schemaVersion and never the off-spec
// tdf_spec_version, at the root or under payload.
func TestManifest_Marshal_EmitsSchemaVersionOnly(t *testing.T) {
	var m Manifest
	require.NoError(t, json.Unmarshal([]byte(testManifestJSON("", "")), &m))
	m.TDFVersion = TDFSpecVersion

	data, err := json.Marshal(m)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))

	assert.Equal(t, TDFSpecVersion, got["schemaVersion"])
	assert.NotContains(t, got, "tdf_spec_version")

	payload, ok := got["payload"].(map[string]any)
	require.True(t, ok, "payload should be an object")
	assert.NotContains(t, payload, "tdf_spec_version")
}

// TestManifest_RoundTripNormalizesSpecVersion shows that reading a manifest
// written with the off-spec name and writing it back out normalizes it to
// schemaVersion, so the error is not propagated by anything that re-emits a
// manifest it read.
func TestManifest_RoundTripNormalizesSpecVersion(t *testing.T) {
	var m Manifest
	require.NoError(t, json.Unmarshal([]byte(testManifestJSON(`,"tdf_spec_version":"4.3.0"`, "")), &m))
	require.Equal(t, "4.3.0", m.TDFVersion)

	data, err := json.Marshal(m)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, "4.3.0", got["schemaVersion"])
	assert.NotContains(t, got, "tdf_spec_version")

	payload, ok := got["payload"].(map[string]any)
	require.True(t, ok, "payload should be an object")
	assert.NotContains(t, payload, "tdf_spec_version")
}
