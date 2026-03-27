package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCryptoProvider(t *testing.T) {
	t.Run("hsm removed", func(t *testing.T) {
		provider, err := NewCryptoProvider(Config{Type: "hsm"})
		require.ErrorIs(t, err, ErrHSMNotFound)
		assert.Nil(t, provider)
	})

	t.Run("standard", func(t *testing.T) {
		provider, err := NewCryptoProvider(Config{Type: "standard"})
		require.NoError(t, err)
		require.NotNil(t, provider)
	})

	t.Run("unknown type falls back to standard", func(t *testing.T) {
		provider, err := NewCryptoProvider(Config{Type: "unknown"})
		require.NoError(t, err)
		require.NotNil(t, provider)
	})
}
