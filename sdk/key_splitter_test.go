package sdk

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A PEM is required to get past the earlier nil/empty checks; these
// tests never wrap anything, so its contents only need to parse as a
// PEM block, not match the advertised algorithm.
const splitterTestPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjhRuJUUiBTLBmYuIJ6vGz1L8k+d3
0j9RGVOM3G8mUJDPuOwLZLwJqDGmvHkyTa8k3lWK8v5nOSGN3nOJ8t2gEg==
-----END PUBLIC KEY-----`

func TestDefaultKeySplitterRejectsUnmappableAlgorithm(t *testing.T) {
	// An algorithm the SDK has no wrapping scheme for yields the empty
	// string, which createKeyAccess reads as a request for RSA. The
	// resulting KAO claims keyType "wrapped" with no ephemeral public
	// key, so the TDF is built successfully and then cannot be decrypted
	// by anything. Fail at creation time instead.
	splitter := DefaultKeySplitter()
	res, err := splitter.Split(context.Background(), SplitRequest{
		DEK: []byte("0123456789abcdef"),
		DefaultKAS: []*policy.SimpleKasKey{{
			KasUri: "https://kas.example.com",
			PublicKey: &policy.SimpleKasPublicKey{
				Algorithm: policy.Algorithm(9999),
				Kid:       "k1",
				Pem:       splitterTestPEM,
			},
		}},
	})

	require.ErrorIs(t, err, ErrSplitterUnsupportedAlgorithm)
	assert.Nil(t, res)
	// The KAS URL is in the message so an operator can tell which of
	// several KASes is misconfigured.
	assert.Contains(t, err.Error(), "https://kas.example.com")
}

func TestDefaultKeySplitterAllowsUnspecifiedAlgorithm(t *testing.T) {
	// ALGORITHM_UNSPECIFIED is not a claim the SDK can reject: KASInfo
	// leaves Algorithm optional and a bare URL plus PEM has always meant
	// RSA. Only a KAS naming an algorithm this SDK cannot map is an
	// error. Policy-supplied keys take the strict path in
	// fillTemplateFromPlan instead.
	splitter := DefaultKeySplitter()
	res, err := splitter.Split(context.Background(), SplitRequest{
		DEK: []byte("0123456789abcdef"),
		DefaultKAS: []*policy.SimpleKasKey{{
			KasUri: "https://kas.example.com",
			PublicKey: &policy.SimpleKasPublicKey{
				Algorithm: policy.Algorithm_ALGORITHM_UNSPECIFIED,
				Kid:       "k1",
				Pem:       splitterTestPEM,
			},
		}},
	})

	require.NoError(t, err)
	require.Len(t, res.Splits, 1)
	require.Len(t, res.Splits[0].Keys, 1)
	assert.Empty(t, res.Splits[0].Keys[0].Algorithm)
}

func TestDefaultKeySplitterAcceptsKnownAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  policy.Algorithm
		want string
	}{
		{"rsa 2048", policy.Algorithm_ALGORITHM_RSA_2048, "rsa:2048"},
		{"ec p256", policy.Algorithm_ALGORITHM_EC_P256, "ec:secp256r1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			splitter := DefaultKeySplitter()
			dek := []byte("0123456789abcdef")
			res, err := splitter.Split(context.Background(), SplitRequest{
				DEK: dek,
				DefaultKAS: []*policy.SimpleKasKey{{
					KasUri: "https://kas.example.com",
					PublicKey: &policy.SimpleKasPublicKey{
						Algorithm: tc.alg,
						Kid:       "k1",
						Pem:       splitterTestPEM,
					},
				}},
			})

			require.NoError(t, err)
			require.Len(t, res.Splits, 1)
			assert.Equal(t, dek, res.Splits[0].Data)
			require.Len(t, res.Splits[0].Keys, 1)
			assert.Equal(t, "https://kas.example.com", res.Splits[0].Keys[0].URL)
			assert.Equal(t, tc.want, res.Splits[0].Keys[0].Algorithm)
		})
	}
}
