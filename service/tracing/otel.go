package tracing

import (
	"context"
	"log"
	"os"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"gopkg.in/natefinch/lumberjack.v2"
)

const ServiceName = "github.com/opentdf/platform/service"

// Create a thread-safe writer wrapper
type syncWriter struct {
	mu     sync.Mutex
	writer *lumberjack.Logger
}

type Config struct {
	Enabled bool   `json:"enabled"`
	Folder  string `json:"folder"`
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(p)
}

func InitTracer(cfg Config) func() {
	if !cfg.Enabled {
		return func() {}
	}

	// Create a directory for the traces
	td := cfg.Folder
	if td == "" {
		td = "traces"
	}
	if err := os.MkdirAll(td, os.ModePerm); err != nil {
		log.Fatal(err)
	}

	lumberjackLogger := &lumberjack.Logger{
		Filename:   td + "/traces.log",
		MaxSize:    20,   //nolint:mnd  // maximum size in megabytes
		MaxBackups: 10,   //nolint:mnd // number of backups
		MaxAge:     30,   //nolint:mnd    // days
		Compress:   true, // compress the rotated files
	}

	// Wrap the logger with our thread-safe writer
	safeWriter := &syncWriter{
		writer: lumberjackLogger,
	}

	exporter, err := stdouttrace.New(
		stdouttrace.WithWriter(safeWriter),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Create a tracer provider with the exporter
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(ServiceName),
		)),
	)

	otel.SetTracerProvider(tp)

	return func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Fatal(err)
		}
		lumberjackLogger.Close()
	}
}
