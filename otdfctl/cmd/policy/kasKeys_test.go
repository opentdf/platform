package policy

import (
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair_Hybrid(t *testing.T) {
	tests := []struct {
		name    string
		alg     policy.Algorithm
		keyType ocrypto.KeyType
	}{
		{"X-Wing", policy.Algorithm_ALGORITHM_HPQT_XWING, ocrypto.HybridXWingKey},
		{"P256-MLKEM768", policy.Algorithm_ALGORITHM_HPQT_SECP256R1_MLKEM768, ocrypto.HybridSecp256r1MLKEM768Key},
		{"P384-MLKEM1024", policy.Algorithm_ALGORITHM_HPQT_SECP384R1_MLKEM1024, ocrypto.HybridSecp384r1MLKEM1024Key},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := generateKeyPair(tt.alg)
			require.NoError(t, err)
			require.Equal(t, tt.keyType, kp.GetKeyType())

			pubPem, err := kp.PublicKeyInPemFormat()
			require.NoError(t, err)
			require.NotEmpty(t, pubPem)

			privPem, err := kp.PrivateKeyInPemFormat()
			require.NoError(t, err)
			require.NotEmpty(t, privPem)
		})
	}
}

func TestGenerateKeyPair_Unsupported(t *testing.T) {
	_, err := generateKeyPair(policy.Algorithm_ALGORITHM_UNSPECIFIED)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported algorithm")
}
