package sdk

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hexToBytes(h string) []byte {
	hexes := strings.Fields(strings.ToLower(h))
	b := make([]byte, len(hexes))
	for i := range hexes {
		hex.Decode(b[i:], []byte(hexes[i]))
	}
	return b
}

func TestParseHeader(t *testing.T) {
	testcases := []struct {
		name     string
		expected NanoTDFHeader
		golden   string
	}{
		{
			name: "plain",
			expected: NanoTDFHeader{
				kasURL: ResourceLocator{
					urlProtocolHTTPS,
					"kas.eternos.xyz",
				},
				bindCfg: bindingConfig{
					true,
					0,
					ocrypto.ECCModeSecp256r1,
				},
				sigCfg: signatureConfig{},
				EphemeralKey: hexToBytes(`
					03 40 77 00 C2 D1 C8 CB 35 59 35 2C DA AD 07 5C 0A 1B 33 14
					C7 B3 05 54 5F 37 85 DA 49 9E 90 FD E0
				`),
				EncryptedPolicyBody: hexToBytes(`
					5F 14 E7 49 CD 6A C0 2D 7E 39 1E E6 51 AD E3 75 E2 87 E2 C3
					7C 69 1F 76 11 5A CE 53 A3 F8 49 AC 9F B7 6B 0F 1C FB 7B E0
					0B 61 CA 57 FE 35 58 14 1C FF 69 A7 E3 06 32 E7 86 5A 6B C1
					C0 E9 B4 43 71 F0 E0 C4 8D FA 5E CA 04 35 6D 60 BC 51 D0 25
					1E B6 66 71 73 29 A6 A2 9E 8A 85 12 09 02 B9 84
				`),
				PolicyBinding: hexToBytes(`
					10 3F 76 CC 1C 66 08 32 E0 B0 7C AF 91 1F C1 50 6D 95 57 F9
					44 37 54 A7 77 D4 EF E0 6F 1A D9 D2 01 E2 EF 1A C0 11 2B 37
					72 4C 5F 4F A4 0A D7 01 CF 40 6C 2E D5 9D B5 72 03 B3 8C A4
					F1 74 60 54
				`),
			},
			golden: "embedded",
		},
	}

	for _, testcase := range testcases {
		content, err := os.Open("testdata/" + testcase.golden + ".ntdf")
		if err != nil {
			t.Fatalf("Error loading golden file: %s", err)
		}
		actual, headerSize, err := NewNanoTDFHeaderFromReader(content)
		require.NoError(t, err)
		assert.Equal(t, 0xa2, headerSize)
		assert.Equal(t, testcase.expected, actual)
	}
}
