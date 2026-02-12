package db

import (
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFormatAlg_MatchesOcryptoKeyTypes verifies that FormatAlg produces strings
// that match the canonical ocrypto.KeyType constants. A mismatch here means the
// SDK's getKasKeyAlg will fail to recognize the algorithm string from the
// well-known config, returning ALGORITHM_UNSPECIFIED.
func TestFormatAlg_MatchesOcryptoKeyTypes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		alg      policy.Algorithm
		expected string
	}{
		{"RSA-2048", policy.Algorithm_ALGORITHM_RSA_2048, string(ocrypto.RSA2048Key)},
		{"RSA-4096", policy.Algorithm_ALGORITHM_RSA_4096, string(ocrypto.RSA4096Key)},
		{"EC-P256", policy.Algorithm_ALGORITHM_EC_P256, string(ocrypto.EC256Key)},
		{"EC-P384", policy.Algorithm_ALGORITHM_EC_P384, string(ocrypto.EC384Key)},
		{"EC-P521", policy.Algorithm_ALGORITHM_EC_P521, string(ocrypto.EC521Key)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := FormatAlg(tc.alg)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result,
				"FormatAlg output must match ocrypto.KeyType so the SDK can parse it back")
		})
	}
}

func TestFormatAlg_Unspecified(t *testing.T) {
	_, err := FormatAlg(policy.Algorithm_ALGORITHM_UNSPECIFIED)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}
