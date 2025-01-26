package tracing

import (
	"context"
	"log"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/metadata"
)

const ServiceName = "opentdf-service"

type Config struct {
	Enabled bool   `json:"enabled"`
	Folder  string `json:"folder"`
}

func InitTracer(cfg Config) func() {
	if !cfg.Enabled {
		tp := noop.NewTracerProvider()
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return func() {}
	}

	ctx := context.Background()
	exporter, err := otlptrace.New(ctx, otlptracegrpc.NewClient(
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint("localhost:4317"),
	))
	if err != nil {
		log.Fatal(err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(ServiceName),
		)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return func() {
		if err := tp.Shutdown(ctx); err != nil {
			log.Fatal(err)
		}
	}
}

// InjectTraceContext injects trace context into outgoing context
func InjectTraceContext(ctx context.Context) context.Context {
	md := metadata.New(nil)
	if existingMD, ok := metadata.FromOutgoingContext(ctx); ok {
		md = existingMD.Copy()
	}
	propagation.TraceContext{}.Inject(ctx, &metadataCarrier{md})
	return metadata.NewOutgoingContext(ctx, md)
}

type metadataCarrier struct {
	md metadata.MD
}

func (mc *metadataCarrier) Get(key string) string {
	if values := mc.md.Get(strings.ToLower(key)); len(values) > 0 {
		return values[0]
	}
	return ""
}

func (mc *metadataCarrier) Set(key, value string) {
	mc.md.Set(strings.ToLower(key), value)
}

func (mc *metadataCarrier) Keys() []string {
	keys := make([]string, 0, len(mc.md))
	for k := range mc.md {
		keys = append(keys, k)
	}
	return keys
}
