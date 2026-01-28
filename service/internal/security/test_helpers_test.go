package security

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/require"
)

type testKeyMaterial struct {
	rsaKid        string
	rsaPrivatePEM string
	rsaPublicPEM  string

	ecKid        string
	ecPrivatePEM string
	ecPublicPEM  string
}

func writeTempFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func newStandardCryptoForTest(t *testing.T, includeRSA, includeEC bool) (*StandardCrypto, testKeyMaterial) {
	t.Helper()

	dir := t.TempDir()
	var keys []KeyPairInfo
	var material testKeyMaterial

	if includeRSA {
		rsaPair, err := generateRSAKeyAndPEM()
		require.NoError(t, err)
		rsaPrivatePEM, err := rsaPair.PrivateKeyInPemFormat()
		require.NoError(t, err)
		rsaPublicPEM, err := rsaPair.PublicKeyInPemFormat()
		require.NoError(t, err)

		material.rsaKid = "rsa-test-key"
		material.rsaPrivatePEM = rsaPrivatePEM
		material.rsaPublicPEM = rsaPublicPEM

		privatePath := writeTempFile(t, dir, "rsa-private.pem", rsaPrivatePEM)
		publicPath := writeTempFile(t, dir, "rsa-public.pem", rsaPublicPEM)
		keys = append(keys, KeyPairInfo{
			Algorithm:   AlgorithmRSA2048,
			KID:         material.rsaKid,
			Private:     privatePath,
			Certificate: publicPath,
		})
	}

	if includeEC {
		ecPair, err := generateECKeyAndPEM(ocrypto.ECCModeSecp256r1)
		require.NoError(t, err)
		ecPrivatePEM, err := ecPair.PrivateKeyInPemFormat()
		require.NoError(t, err)
		ecPublicPEM, err := ecPair.PublicKeyInPemFormat()
		require.NoError(t, err)

		material.ecKid = "ec-test-key"
		material.ecPrivatePEM = ecPrivatePEM
		material.ecPublicPEM = ecPublicPEM

		privatePath := writeTempFile(t, dir, "ec-private.pem", ecPrivatePEM)
		publicPath := writeTempFile(t, dir, "ec-public.pem", ecPublicPEM)
		keys = append(keys, KeyPairInfo{
			Algorithm:   AlgorithmECP256R1,
			KID:         material.ecKid,
			Private:     privatePath,
			Certificate: publicPath,
		})
	}

	crypto, err := NewStandardCrypto(StandardConfig{Keys: keys})
	require.NoError(t, err)

	return crypto, material
}

func exportProtectedKey(t *testing.T, key ocrypto.ProtectedKey) []byte {
	t.Helper()
	raw, err := (&noOpEncapsulator{}).Encapsulate(key)
	require.NoError(t, err)
	return raw
}
