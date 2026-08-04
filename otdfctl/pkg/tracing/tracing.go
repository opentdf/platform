// Package tracing wires optional OpenTelemetry tracing into otdfctl.
//
// It is a strict no-op unless OTEL_EXPORTER_OTLP_ENDPOINT is set, so normal CLI
// usage pays no startup cost and never fails when no collector is configured.
// When enabled, it exports spans over OTLP/gRPC and continues any trace passed
// in via the standard TRACEPARENT environment variable, so a CLI invocation
// joins the trace of whatever launched it (e.g. the xtest pytest harness).
package tracing

import (
	"context"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const (
	serviceName = "otdfctl"

	// shutdownTimeout bounds how long we wait to flush buffered spans on exit.
	shutdownTimeout = 5 * time.Second
)

// Init configures a global OTLP tracer provider and propagator when
// OTEL_EXPORTER_OTLP_ENDPOINT is set. It returns a shutdown function that
// flushes buffered spans (a no-op when tracing is disabled) and a bool
// reporting whether tracing was enabled.
func Init(ctx context.Context) (func(), bool) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		return func() {}, false
	}

	exporter, err := otlptracegrpc.New(ctx, exporterOptions(endpoint)...)
	if err != nil {
		// Tracing is best-effort: never block the CLI because a collector is
		// unreachable or misconfigured.
		return func() {}, false
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(attribute.String("service.name", serviceName)),
	)
	if err != nil {
		res = resource.NewSchemaless(attribute.String("service.name", serviceName))
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = tp.Shutdown(shutdownCtx)
	}
	return shutdown, true
}

// ExtractParentFromEnv returns a context carrying the remote span context
// described by the TRACEPARENT/TRACESTATE environment variables, so spans
// started from it become children of the caller's trace. If TRACEPARENT is
// unset the input context is returned unchanged.
func ExtractParentFromEnv(ctx context.Context) context.Context {
	carrier := propagation.MapCarrier{}
	if tp := os.Getenv("TRACEPARENT"); tp != "" {
		carrier["traceparent"] = tp
	}
	if ts := os.Getenv("TRACESTATE"); ts != "" {
		carrier["tracestate"] = ts
	}
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}

// exporterOptions derives the OTLP/gRPC dial options from the endpoint,
// honoring an optional http:// or https:// scheme to choose (in)secure
// transport. A bare host:port defaults to insecure for local development.
func exporterOptions(endpoint string) []otlptracegrpc.Option {
	insecure := true
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		insecure = false
		endpoint = strings.TrimPrefix(endpoint, "https://")
	case strings.HasPrefix(endpoint, "http://"):
		endpoint = strings.TrimPrefix(endpoint, "http://")
	}
	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(endpoint)}
	if insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	return opts
}
