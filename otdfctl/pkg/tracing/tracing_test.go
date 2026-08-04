package tracing

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestInitDisabledWhenEndpointUnset(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

	shutdown, enabled := Init(context.Background())
	if enabled {
		t.Fatal("expected tracing to be disabled when OTEL_EXPORTER_OTLP_ENDPOINT is unset")
	}
	if shutdown == nil {
		t.Fatal("shutdown must be a non-nil no-op even when disabled")
	}
	shutdown() // must not panic
}

func TestExtractParentFromEnv(t *testing.T) {
	// A valid W3C traceparent for trace 0af7651916cd43dd8448eb211c80319c.
	const traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	t.Setenv("TRACEPARENT", traceparent)

	// Enable a provider so the global propagator is the W3C TraceContext.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	shutdown, enabled := Init(context.Background())
	if !enabled {
		t.Fatal("expected tracing enabled")
	}
	defer shutdown()

	ctx := ExtractParentFromEnv(context.Background())
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		t.Fatal("expected a valid remote span context from TRACEPARENT")
	}
	if got := sc.TraceID().String(); got != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("trace id = %s, want 0af7651916cd43dd8448eb211c80319c", got)
	}
}

func TestExtractParentFromEnvNoParent(t *testing.T) {
	t.Setenv("TRACEPARENT", "")
	ctx := ExtractParentFromEnv(context.Background())
	if trace.SpanContextFromContext(ctx).IsValid() {
		t.Error("expected no valid span context when TRACEPARENT is unset")
	}
}

func TestExporterOptionsScheme(t *testing.T) {
	// Bare host:port and http:// default to insecure; https:// stays secure.
	// We can't inspect the opaque options directly, so just assert the call
	// returns the expected count and does not panic for each scheme.
	for _, ep := range []string{"localhost:4317", "http://localhost:4317", "https://collector:4317"} {
		if got := exporterOptions(ep); len(got) == 0 {
			t.Errorf("exporterOptions(%q) returned no options", ep)
		}
	}
}
