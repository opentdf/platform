package ocrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHybridWrapDEKRejectsNonHybridKeyType(t *testing.T) {
	rsaKeyPair, err := NewRSAKeyPair(RSA2048Size)
	require.NoError(t, err)
	rsaPublicPEM, err := rsaKeyPair.PublicKeyInPemFormat()
	require.NoError(t, err)

	wrapped, err := HybridWrapDEK(RSA2048Key, rsaPublicPEM, []byte("test-dek"))
	require.Error(t, err)
	require.Nil(t, wrapped)
	assert.Contains(t, err.Error(), "unsupported hybrid key type")
}
