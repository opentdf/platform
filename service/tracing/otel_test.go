package tracing

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

func Test_InitTracer_CompatibleResourceSchemas_Succeeds(t *testing.T) {
	// resource.Default uses the schema from go.opentelemetry.io/otel/sdk, while
	// InitTracer's base resource uses the versioned go.opentelemetry.io/otel/semconv
	// import. If they drift, such as SDK schema 1.41.0 with semconv schema 1.26.0,
	// InitTracer returns "conflicting Schema URL" and require.NoError fails.
	// The file exporter avoids needing a collector; all exporters use this merge.
	shutdown, err := InitTracer(t.Context(), Config{
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

func Test_InitTracer_ShutdownFlushesAfterContextCancellation(t *testing.T) {
	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	path := filepath.Join(t.TempDir(), "traces.json")
	shutdown, err := InitTracer(ctx, Config{
		Enabled: true,
		Provider: ProviderConfig{
			Name: ProviderFile,
			File: &FileConfig{Path: path},
		},
	})
	require.NoError(t, err)
	t.Cleanup(shutdown)

	_, span := otel.Tracer(ServiceName).Start(ctx, "pending-at-shutdown")
	span.End()
	cancel()
	shutdown()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), `"Name":"pending-at-shutdown"`)
}
