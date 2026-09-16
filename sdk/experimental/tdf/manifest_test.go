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
// schemaVersion is correct and always wins.
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
			name:      "off-spec tdf_spec_version at root",
			rootExtra: `,"tdf_spec_version":"4.3.0"`,
			want:      "4.3.0",
		},
		{
			name:         "off-spec tdf_spec_version under payload",
			payloadExtra: `,"tdf_spec_version":"4.3.0"`,
			want:         "4.3.0",
		},
		{
			name:      "schemaVersion wins over root tdf_spec_version",
			rootExtra: `,"schemaVersion":"4.3.0","tdf_spec_version":"4.2.0"`,
			want:      "4.3.0",
		},
		{
			name:         "root tdf_spec_version wins over payload tdf_spec_version",
			payloadExtra: `,"tdf_spec_version":"4.2.0"`,
			rootExtra:    `,"tdf_spec_version":"4.3.0"`,
			want:         "4.3.0",
		},
		{
			name: "no version at all",
			want: "",
		},
		{
			name:      "null tdf_spec_version is ignored",
			rootExtra: `,"tdf_spec_version":null`,
			want:      "",
		},
		{
			name:      "numeric tdf_spec_version is ignored",
			rootExtra: `,"tdf_spec_version":430`,
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m Manifest
			require.NoError(t, json.Unmarshal([]byte(testManifestJSON(tt.payloadExtra, tt.rootExtra)), &m))
			assert.Equal(t, tt.want, m.TDFVersion)

			// The custom decoder must not drop anything else.
			assert.Equal(t, "reference", m.Payload.Type)
			assert.Equal(t, "0.payload", m.Payload.URL)
			assert.Equal(t, "split", m.EncryptionInformation.KeyAccessType)
			assert.Equal(t, "GMAC", m.EncryptionInformation.IntegrityInformation.SegmentHashAlgorithm)
			assert.Equal(t, "cm9vdHNpZw==", m.EncryptionInformation.IntegrityInformation.RootSignature.Signature)
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
