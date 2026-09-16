// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

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

// TestManifest_UnmarshalJSON_SpecVersion mirrors the stable SDK's test of the
// same name. tdf_spec_version is an off-spec name for the spec version that
// leaked into some specification drafts and some older OpenTDF documentation;
// schemaVersion is correct and always wins. Only the payload copy is read,
// matching where the bundled schemas declare it.
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
			name:         "off-spec tdf_spec_version under payload",
			payloadExtra: `,"tdf_spec_version":"4.3.0"`,
			want:         "4.3.0",
		},
		{
			name:      "off-spec tdf_spec_version at root is ignored",
			rootExtra: `,"tdf_spec_version":"4.3.0"`,
			want:      "",
		},
		{
			name:         "schemaVersion wins over payload tdf_spec_version",
			payloadExtra: `,"tdf_spec_version":"4.2.0"`,
			rootExtra:    `,"schemaVersion":"4.3.0"`,
			want:         "4.3.0",
		},
		{
			name:         "payload tdf_spec_version is read past a root copy",
			payloadExtra: `,"tdf_spec_version":"4.3.0"`,
			rootExtra:    `,"tdf_spec_version":"4.2.0"`,
			want:         "4.3.0",
		},
		{
			name: "no version at all",
			want: "",
		},
		{
			name:         "null tdf_spec_version is ignored",
			payloadExtra: `,"tdf_spec_version":null`,
			want:         "",
		},
		{
			name:         "numeric tdf_spec_version is ignored",
			payloadExtra: `,"tdf_spec_version":430`,
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

			// The custom decoder must not drop anything else.
			assert.Equal(t, "reference", m.Type)
			assert.Equal(t, "0.payload", m.URL)
			assert.Equal(t, "split", m.KeyAccessType)
			assert.Equal(t, "GMAC", m.SegmentHashAlgorithm)
			assert.Equal(t, "cm9vdHNpZw==", m.Signature)
		})
	}
}

// TestManifest_Marshal_EmitsSchemaVersionOnly guards the writer side: manifests
// this package produces name the field schemaVersion and never the off-spec
// tdf_spec_version, at the root or under payload.
func TestManifest_Marshal_EmitsSchemaVersionOnly(t *testing.T) {
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
