package sdk

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DSPX-5353: IsValidTdf must reject manifest bytes that LoadTDF cannot parse.
// gojsonschema's string loader reads only the first JSON value, so trailing
// data used to pass validation while LoadTDF's json.Unmarshal rejected it.
func TestIsValidTdf_ManifestTrailingData(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		valid    bool
	}{
		{name: "minimal manifest", manifest: minimalManifestJSON, valid: true},
		{name: "trailing whitespace", manifest: minimalManifestJSON + " \r\n\t", valid: true},
		{name: "trailing garbage", manifest: minimalManifestJSON + " garbage"},
		{name: "two concatenated objects", manifest: minimalManifestJSON + "{}"},
		{name: "extra closing brace", manifest: minimalManifestJSON + "}"},
		{name: "leading UTF-8 BOM", manifest: "\xef\xbb\xbf" + minimalManifestJSON},
	}

	s := newLoadTestSDK()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := zipWithManifest(t, tc.manifest)

			valid, err := IsValidTdf(bytes.NewReader(data))
			assert.Equal(t, tc.valid, valid)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.NotErrorIs(t, err, ErrInvalidPerSchema)
			}

			// LoadTDF must agree at every validation intensity.
			for _, intensity := range []SchemaValidationIntensity{Skip, Lax, Strict} {
				r, err := s.LoadTDF(bytes.NewReader(data), WithSchemaValidation(intensity), WithIgnoreAllowlist(true))
				if tc.valid {
					require.NoError(t, err, "intensity %d", intensity)
					require.NotNil(t, r)
				} else {
					require.Error(t, err, "intensity %d", intensity)
					require.Nil(t, r)
				}
			}
		})
	}
}
