package tracing

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_InitTracer_CompatibleResourceSchemas_Succeeds(t *testing.T) {
	shutdown, err := InitTracer(context.Background(), Config{
		Enabled: true,
		Provider: ProviderConfig{
			Name: ProviderFile,
			File: &FileConfig{Path: t.TempDir() + "/traces.json"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	shutdown()
}
