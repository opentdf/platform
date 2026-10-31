package sdk

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/internal/zipstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DSPX-4388: a TDF the SDK writes must pass its own manifest schemas, whatever
// key access type the KAS key gives it. The schemas once left mlkem-wrapped out
// of the key access type enum, so IsValidTdf rejected every ML-KEM TDF that
// CreateTDF produced.
func TestCreateTDFKeyAccessTypesPassSchemaValidation(t *testing.T) {
	for _, tc := range []struct {
		keyType ocrypto.KeyType
		kaoType string
	}{
		{ocrypto.RSA2048Key, kWrapped},
		{ocrypto.EC256Key, kECWrapped},
		{ocrypto.HybridXWingKey, kHybridWrapped},
		{ocrypto.HybridSecp256r1MLKEM768Key, kHybridWrapped},
		{ocrypto.MLKEM768Key, kMLKEMWrapped},
		{ocrypto.MLKEM1024Key, kMLKEMWrapped},
	} {
		t.Run(string(tc.keyType), func(t *testing.T) {
			kasKey, err := ocrypto.NewKeyPair(tc.keyType)
			require.NoError(t, err)
			kasPublicKey, err := kasKey.PublicKeyInPemFormat()
			require.NoError(t, err)

			s := newLoadTestSDK()
			tdf := &bytes.Buffer{}
			_, err = s.CreateTDF(tdf, strings.NewReader("hello, world"),
				WithKasInformation(KASInfo{
					URL:       "https://kas.example.com",
					KID:       "k1",
					Algorithm: string(tc.keyType),
					PublicKey: kasPublicKey,
				}),
				WithAutoconfigure(false),
			)
			require.NoError(t, err)

			tdfReader, err := zipstream.NewTDFReader(bytes.NewReader(tdf.Bytes()))
			require.NoError(t, err)
			manifest, err := tdfReader.Manifest()
			require.NoError(t, err)
			var m Manifest
			require.NoError(t, json.Unmarshal([]byte(manifest), &m))
			require.Len(t, m.KeyAccessObjs, 1)
			assert.Equal(t, tc.kaoType, m.KeyAccessObjs[0].KeyType)

			valid, err := IsValidTdf(bytes.NewReader(tdf.Bytes()))
			require.NoError(t, err)
			assert.True(t, valid)

			for _, intensity := range []SchemaValidationIntensity{Lax, Strict} {
				valid, err = isValidManifest(manifest, intensity)
				require.NoError(t, err, "at %v", intensity)
				assert.True(t, valid, "at %v", intensity)

				_, err = s.LoadTDF(bytes.NewReader(tdf.Bytes()),
					WithSchemaValidation(intensity), WithIgnoreAllowlist(true))
				require.NoError(t, err, "at %v", intensity)
			}
		})
	}
}
