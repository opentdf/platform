package tracing

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/metadata"
	"gopkg.in/natefinch/lumberjack.v2"
)

const ServiceName = "opentdf-service"

// Create a thread-safe writer wrapper
type syncWriter struct {
	mu     sync.Mutex
	writer *lumberjack.Logger
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(p)
}

type Config struct {
	Enabled        bool   `json:"enabled"`
	Folder         string `json:"folder"`
	ExportToJaeger bool   `yaml:"exportToJaeger"`
}

func InitTracer(ctx context.Context, cfg Config) (func(), error) {
	if !cfg.Enabled {
		tp := noop.NewTracerProvider()
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return func() {}, nil
	}

	// Create a directory for the traces
	td := cfg.Folder
	if td == "" {
		td = "traces"
	}
	if err := os.MkdirAll(td, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create traces directory: %w", err)
	}

	lumberjackLogger := &lumberjack.Logger{
		Filename:   td + "/traces.log",
		MaxSize:    20,   //nolint:mnd  // maximum size in megabytes
		MaxBackups: 10,   //nolint:mnd // number of backups
		MaxAge:     30,   //nolint:mnd    // days
		Compress:   true, // compress the rotated files
	}

	safeWriter := &syncWriter{
		writer: lumberjackLogger,
	}

	var exporter sdktrace.SpanExporter
	var err error

	if cfg.ExportToJaeger {
		exporter, err = otlptrace.New(ctx, otlptracegrpc.NewClient(
			otlptracegrpc.WithInsecure(),
			otlptracegrpc.WithEndpoint("localhost:4317"),
		))
	} else {
		exporter, err = stdouttrace.New(
			stdouttrace.WithWriter(safeWriter),
		)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create exporter: %w", err)
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
			log.Printf("Error shutting down tracer provider: %v", err)
		}
	}, nil
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
