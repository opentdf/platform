package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func Test_InitTracer_OTLPExportsTracesAndMetrics_Succeeds(t *testing.T) {
	previousTracerProvider := otel.GetTracerProvider()
	previousMeterProvider := otel.GetMeterProvider()
	previousPropagator := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(previousTracerProvider)
		otel.SetMeterProvider(previousMeterProvider)
		otel.SetTextMapPropagator(previousPropagator)
	})

	var (
		mu    sync.Mutex
		paths []string
	)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)

	shutdown, err := InitTracer(t.Context(), Config{
		Enabled: true,
		Provider: ProviderConfig{
			Name: "OTLP",
			OTLP: &OTLPConfig{
				Endpoint: strings.TrimPrefix(collector.URL, "http://"),
				Insecure: true,
				Protocol: "http",
			},
		},
	})
	require.NoError(t, err)

	_, span := otel.Tracer(ServiceName).Start(t.Context(), "test-span")
	span.End()
	counter, err := otel.Meter(ServiceName).Int64Counter("test.counter")
	require.NoError(t, err)
	counter.Add(t.Context(), 1)
	shutdown()

	mu.Lock()
	defer mu.Unlock()
	require.Contains(t, paths, "/v1/traces")
	require.Contains(t, paths, "/v1/metrics")
}
