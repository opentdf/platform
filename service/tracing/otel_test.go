package tracing

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_InitTracer_CompatibleResourceSchemas_Succeeds(t *testing.T) {
	// resource.Default uses the schema from go.opentelemetry.io/otel/sdk, while
	// InitTracer's base resource uses the versioned go.opentelemetry.io/otel/semconv
	// import. If they drift, such as SDK schema 1.41.0 with semconv schema 1.26.0,
	// InitTracer returns "conflicting Schema URL" and require.NoError fails.
	// The file exporter avoids needing a collector; all exporters use this merge.
	shutdown, err := InitTracer(context.Background(), Config{
		Enabled: true,
		Provider: ProviderConfig{
			Name: ProviderFile,
			File: &FileConfig{Path: filepath.Join(t.TempDir(), "traces.json")},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	shutdown()
}
