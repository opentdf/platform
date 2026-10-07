package tracing

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

func Test_InitTracer_CompatibleResourceSchemas_Succeeds(t *testing.T) {
	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
	})

	shutdown, err := InitTracer(context.Background(), Config{
		Enabled: true,
		Provider: ProviderConfig{
			Name: ProviderFile,
			File: &FileConfig{Path: filepath.Join(t.TempDir(), "traces.json")},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	t.Cleanup(shutdown)
}
