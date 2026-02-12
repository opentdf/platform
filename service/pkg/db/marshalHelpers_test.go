package db

import (
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reverseAlgMap mirrors the SDK's getKasKeyAlg mapping: ocrypto.KeyType string → policy.Algorithm.
// If FormatAlg produces a string that isn't in this map, the SDK would return ALGORITHM_UNSPECIFIED.
var reverseAlgMap = map[string]policy.Algorithm{
	string(ocrypto.RSA2048Key): policy.Algorithm_ALGORITHM_RSA_2048,
	string(ocrypto.RSA4096Key): policy.Algorithm_ALGORITHM_RSA_4096,
	string(ocrypto.EC256Key):   policy.Algorithm_ALGORITHM_EC_P256,
	string(ocrypto.EC384Key):   policy.Algorithm_ALGORITHM_EC_P384,
	string(ocrypto.EC521Key):   policy.Algorithm_ALGORITHM_EC_P521,
}

func TestFormatAlg_RoundTrip(t *testing.T) {
	// Every supported algorithm must survive a round-trip:
	//   enum → FormatAlg(enum) → reverseAlgMap[result] → must equal original enum
	// This proves FormatAlg produces strings the SDK's getKasKeyAlg can parse.
	supportedAlgs := []struct {
		name string
		alg  policy.Algorithm
	}{
		{"RSA-2048", policy.Algorithm_ALGORITHM_RSA_2048},
		{"RSA-4096", policy.Algorithm_ALGORITHM_RSA_4096},
		{"EC-P256", policy.Algorithm_ALGORITHM_EC_P256},
		{"EC-P384", policy.Algorithm_ALGORITHM_EC_P384},
		{"EC-P521", policy.Algorithm_ALGORITHM_EC_P521},
	}

	for _, tc := range supportedAlgs {
		t.Run(tc.name, func(t *testing.T) {
			formatted, err := FormatAlg(tc.alg)
			require.NoError(t, err, "FormatAlg should not error for %s", tc.name)

			roundTripped, ok := reverseAlgMap[formatted]
			require.True(t, ok, "FormatAlg returned %q which is not a known ocrypto.KeyType string", formatted)
			assert.Equal(t, tc.alg, roundTripped, "round-trip mismatch: FormatAlg(%s) = %q maps back to %s, not %s",
				tc.name, formatted, roundTripped, tc.alg)
		})
	}
}

func TestFormatAlg_Unsupported(t *testing.T) {
	unsupported := []struct {
		name string
		alg  policy.Algorithm
	}{
		{"Unspecified", policy.Algorithm_ALGORITHM_UNSPECIFIED},
		{"Invalid", policy.Algorithm(99)},
	}

	for _, tc := range unsupported {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FormatAlg(tc.alg)
			require.Error(t, err)
		})
	}
}
