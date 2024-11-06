package tracing

import (
	"context"
	"log"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"gopkg.in/natefinch/lumberjack.v2"
)

const ServiceName = "opentdf-service"

func InitTracer() func() {
	// Ensure the traces folder exists
	if err := os.MkdirAll("traces", os.ModePerm); err != nil {
		log.Fatal(err)
	}

	// Create a lumberjack logger for file rotation
	lumberjackLogger := &lumberjack.Logger{
		Filename:   "traces/traces.log",
		MaxSize:    10,   //nolint:mnd  // maximum size in megabytes
		MaxBackups: 10,   //nolint:mnd // number of backups
		MaxAge:     30,   //nolint:mnd    // days
		Compress:   true, // compress the rotated files
	}

	// Create a stdout exporter that writes to the lumberjack logger
	exporter, err := stdouttrace.New(
		stdouttrace.WithWriter(lumberjackLogger),
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
