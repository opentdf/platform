package ocrypto

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsPEMOrDERPrivateKey(t *testing.T) {
	privateKeyFiles := []string{
		"sample-rsa-2048-01-private.pem",
		"sample-ec-secp256r1-01-private.pem",
	}

	for _, filename := range privateKeyFiles {
		t.Run("pem-private-"+filename, func(t *testing.T) {
			pemData := readTestData(t, filename)
			require.True(t, IsPEMOrDERPrivateKey(pemData))
		})
	}

	t.Run("pem-public", func(t *testing.T) {
		pemData := readTestData(t, "sample-rsa-2048-01-public.pem")
		require.False(t, IsPEMOrDERPrivateKey(pemData))
	})

	t.Run("der-private", func(t *testing.T) {
		pemData := readTestData(t, "sample-rsa-2048-01-private.pem")
		block, _ := pem.Decode(pemData)
		require.NotNil(t, block)
		require.True(t, IsPEMOrDERPrivateKey(block.Bytes))
	})

	t.Run("random-bytes", func(t *testing.T) {
		require.False(t, IsPEMOrDERPrivateKey([]byte("not a key")))
	})
}

func readTestData(t *testing.T, filename string) []byte {
	t.Helper()
	path := filepath.Join("testdata", filename)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
