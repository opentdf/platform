package sdk

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateWrapKeyWithEC_AllCurves reproduces issue #3070:
// EC wrap/unwrap fails for P-384/P-521 because UncompressECPubKey
// hardcodes elliptic.P256() instead of using the actual curve parameter.
//
// This test exercises the SDK's generateWrapKeyWithEC function and
// verifies the KAS-side unwrap (compress ephemeral key + decrypt)
// produces the original symmetric key.
func TestGenerateWrapKeyWithEC_AllCurves(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode ocrypto.ECCMode
	}{
		{"P-256", ocrypto.ECCModeSecp256r1},
		{"P-384", ocrypto.ECCModeSecp384r1},
		{"P-521", ocrypto.ECCModeSecp521r1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			symKey := []byte("this-is-a-test-symmetric-key!!")

			// Generate KAS key pair for this curve
			kasKeyPair, err := ocrypto.NewECKeyPair(tc.mode)
			require.NoError(t, err)

			kasPublicPEM, err := kasKeyPair.PublicKeyInPemFormat()
			require.NoError(t, err)

			kasPrivatePEM, err := kasKeyPair.PrivateKeyInPemFormat()
			require.NoError(t, err)

			// SDK side: wrap the symmetric key
			wrapInfo, err := generateWrapKeyWithEC(tc.mode, kasPublicPEM, symKey)
			require.NoError(t, err)
			require.NotEmpty(t, wrapInfo.publicKey, "ephemeral public key should be set")
			require.NotEmpty(t, wrapInfo.wrappedKey, "wrapped key should be set")

			// KAS side: unwrap using the same flow as FakeKas/rewrap.go
			// 1. Get EC key size and mode from ephemeral PEM
			keySize, err := ocrypto.GetECKeySize([]byte(wrapInfo.publicKey))
			require.NoError(t, err)

			mode, err := ocrypto.ECSizeToMode(keySize)
			require.NoError(t, err)

			// 2. Parse ephemeral PEM and compress
			block, _ := pem.Decode([]byte(wrapInfo.publicKey))
			require.NotNil(t, block, "failed to decode ephemeral PEM")

			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			require.NoError(t, err)

			ecPub, ok := pub.(*ecdsa.PublicKey)
			require.True(t, ok, "ephemeral key should be *ecdsa.PublicKey")

			compressedKey, err := ocrypto.CompressedECPublicKey(mode, *ecPub)
			require.NoError(t, err)

			// 3. Decrypt with compressed ephemeral key
			kasPrivKey, err := ocrypto.ECPrivateKeyFromPem([]byte(kasPrivatePEM))
			require.NoError(t, err)

			decryptor, err := ocrypto.NewSaltedECDecryptor(kasPrivKey, tdfSalt(), nil)
			require.NoError(t, err)

			wrappedKeyBytes, err := ocrypto.Base64Decode([]byte(wrapInfo.wrappedKey))
			require.NoError(t, err)

			unwrappedKey, err := decryptor.DecryptWithEphemeralKey(wrappedKeyBytes, compressedKey)
			require.NoError(t, err, "DecryptWithEphemeralKey should succeed for %s", tc.name)
			assert.Equal(t, symKey, unwrappedKey, "unwrapped key should match original")
		})
	}
}
