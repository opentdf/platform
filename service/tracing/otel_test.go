package tracing

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_InitTracer_CompatibleResourceSchemas_Succeeds(t *testing.T) {
	// The file exporter keeps the test hermetic while exercising the same enabled
	// tracing path used by OTLP, including creation and merging of OTel resources.
	shutdown, err := InitTracer(context.Background(), Config{
		Enabled: true,
		Provider: ProviderConfig{
			Name: ProviderFile,
			File: &FileConfig{Path: filepath.Join(t.TempDir(), "traces.json")},
		},
	})
	// InitTracer returns an error here when the SDK default resource schema and
	// the semantic-conventions schema selected by the module graph do not match.
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	shutdown()
}
