package cli

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/require"
)

func TestKeyAlgToEnum_RoundTrip(t *testing.T) {
	tests := []struct {
		alg  string
		enum policy.Algorithm
	}{
		{"rsa:2048", policy.Algorithm_ALGORITHM_RSA_2048},
		{"rsa:4096", policy.Algorithm_ALGORITHM_RSA_4096},
		{"ec:secp256r1", policy.Algorithm_ALGORITHM_EC_P256},
		{"ec:secp384r1", policy.Algorithm_ALGORITHM_EC_P384},
		{"ec:secp521r1", policy.Algorithm_ALGORITHM_EC_P521},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			got, err := KeyAlgToEnum(tt.alg)
			require.NoError(t, err)
			require.Equal(t, tt.enum, got)

			back, err := KeyEnumToAlg(got)
			require.NoError(t, err)
			require.Equal(t, tt.alg, back)
		})
	}
}

func TestKeyAlgToEnum_Invalid(t *testing.T) {
	_, err := KeyAlgToEnum("not-a-real-alg")
	require.Error(t, err)
}

func TestKeyEnumToAlg_Invalid(t *testing.T) {
	_, err := KeyEnumToAlg(policy.Algorithm_ALGORITHM_UNSPECIFIED)
	require.Error(t, err)
}
