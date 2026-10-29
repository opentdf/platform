package profiles

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewOtdfctlProfileStoreValidatesEndpointBeforeCreatingProfiler(t *testing.T) {
	_, err := NewOtdfctlProfileStore(ProfileDriverUnknown, &ProfileConfig{
		Name: "test",
	}, false)

	require.EqualError(t, err, "endpoint is required")
}
