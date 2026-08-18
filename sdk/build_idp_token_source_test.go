package sdk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildIDPTokenSource_DPoPWithoutCredentialsErrors verifies that explicitly
// configuring a DPoP option without any credentials fails loudly rather than
// silently returning an uncredentialed (and therefore un-DPoP-bound) client.
func TestBuildIDPTokenSource_DPoPWithoutCredentialsErrors(t *testing.T) {
	c := &config{}
	WithDPoPAlgorithm(ES256)(c)

	ts, key, err := buildIDPTokenSource(c)
	require.Error(t, err, "expected an error when DPoP is configured without credentials")
	assert.Contains(t, err.Error(), "no client credentials")
	assert.Nil(t, ts, "token source should be nil on error")
	assert.Nil(t, key, "dpop key should be nil on error")
}

// TestBuildIDPTokenSource_NoDPoPNoCredentialsIsUncredentialed verifies the
// legitimate uncredentialed case (e.g. consuming the well-known configuration)
// still returns a nil token source without error when no DPoP option is set.
func TestBuildIDPTokenSource_NoDPoPNoCredentialsIsUncredentialed(t *testing.T) {
	c := &config{}

	ts, key, err := buildIDPTokenSource(c)
	require.NoError(t, err)
	assert.Nil(t, ts, "uncredentialed client should have a nil token source")
	assert.Nil(t, key, "uncredentialed client should have a nil dpop key")
}
