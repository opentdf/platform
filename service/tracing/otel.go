package tracing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/metadata"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	ServiceName           = "opentdf-platform"
	ProviderOTLP          = "otlp"
	ProviderFile          = "file"
	DefaultFileMaxSize    = 20
	DefaultFileMaxBackups = 10
	DefaultFileMaxAge     = 30
	ShutdownTimeout       = 5 * time.Second // Added constant for shutdown timeout
)

// --- Configuration Structs ---

type Config struct {
	Enabled  bool           `json:"enabled" yaml:"enabled"`
	Provider ProviderConfig `json:"provider" yaml:"provider"`
}

type ProviderConfig struct {
	Name string      `json:"name" yaml:"name"`
	OTLP *OTLPConfig `json:"otlp,omitempty" yaml:"otlp,omitempty"`
	File *FileConfig `json:"file,omitempty" yaml:"file,omitempty"`
}

type OTLPConfig struct {
	Endpoint string            `json:"endpoint" yaml:"endpoint"`
	Insecure bool              `json:"insecure" yaml:"insecure"`
	Protocol string            `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Headers  map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
}

type FileConfig struct {
	Path        string `json:"path" yaml:"path"`
	PrettyPrint bool   `json:"prettyPrint,omitempty" yaml:"prettyPrint,omitempty"`
	MaxSize     int    `json:"maxSize,omitempty" yaml:"maxSize,omitempty"`
	MaxBackups  int    `json:"maxBackups,omitempty" yaml:"maxBackups,omitempty"`
	MaxAge      int    `json:"maxAge,omitempty" yaml:"maxAge,omitempty"`
	Compress    bool   `json:"compress,omitempty" yaml:"compress,omitempty"`
}

// --- Helper for file writing ---
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func newSyncWriter(w io.Writer) *syncWriter {
	return &syncWriter{w: w}
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func InitTracer(ctx context.Context, cfg Config) (func(), error) {
	logger := slog.Default()

	if !cfg.Enabled {
		logger.Info("tracing disabled.")
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.TraceContext{})
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
			logger.ErrorContext(ctx, "otel SDK Error", slog.Any("error", err))
		}))
		return func() {}, nil
	}

	logger.InfoContext(ctx, "initializing tracing", slog.String("provider", cfg.Provider.Name))

	var exporter sdktrace.SpanExporter
	var err error
	var writerCloser io.Closer

	switch strings.ToLower(cfg.Provider.Name) {
	case ProviderOTLP:
		if cfg.Provider.OTLP == nil {
			return nil, errors.New("OTLP provider selected but config missing")
		}
		exporter, err = createOTLPExporter(ctx, cfg.Provider.OTLP)
		if err != nil {
			return nil, fmt.Errorf("create OTLP exporter failed: %w", err)
		}
	case ProviderFile:
		if cfg.Provider.File == nil {
			return nil, errors.New("file provider selected but config missing")
		}
		exporter, writerCloser, err = createFileExporter(cfg.Provider.File)
		if err != nil {
			return nil, fmt.Errorf("create file exporter failed: %w", err)
		}
	case "":
		return nil, errors.New("tracing provider name missing")
	default:
		return nil, fmt.Errorf("unsupported tracing provider: '%s'", cfg.Provider.Name)
	}

	// 3. Create Resource: Combine attributes from explicit config, defaults, and environment.
	baseRes := resource.NewWithAttributes(
		semconv.SchemaURL, // Required by NewWithAttributes
		semconv.ServiceNameKey.String(ServiceName),
		// Add other static resource attributes here if needed
	)

	defaultRes := resource.Default() // Attributes detected by the SDK (host, OS, process, etc.)
	if defaultRes == nil {
		logger.Warn("resource.Default() returned nil. Using only explicitly defined resource attributes.")
		defaultRes = resource.Empty()
	}

	envRes, err := resource.New(ctx, resource.WithFromEnv()) // Attributes from OTEL_RESOURCE_ATTRIBUTES
	if err != nil {
		logger.WarnContext(ctx, "failed to create resource from env vars (OTEL_RESOURCE_ATTRIBUTES)", slog.Any("error", err))
		envRes = resource.Empty()
	}

	// Merge resources. Later resources overwrite earlier ones on key conflict.
	// Precedence: Environment > Explicit > Default
	res, err := resource.Merge(defaultRes, baseRes)
	if err != nil {
		_ = exporter.Shutdown(ctx)
		if writerCloser != nil {
			_ = writerCloser.Close()
		}
		return nil, fmt.Errorf("failed to merge default and base resources: %w", err)
	}
	res, err = resource.Merge(res, envRes)
	if err != nil {
		_ = exporter.Shutdown(ctx)
		if writerCloser != nil {
			_ = writerCloser.Close()
		}
		return nil, fmt.Errorf("failed to merge environment resource: %w", err)
	}

	logger.InfoContext(ctx, "initialized resource with attributes", slog.String("attributes", res.Encoded(attribute.DefaultEncoder())))

	// 4. Create Tracer Provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()), // Optional: Configure sampling
	)

	// 5. Set Global Provider and Propagator
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	logger.Info("tracing successfully initialized.")

	// 6. Return Shutdown Function
	return func() {
		logger.InfoContext(ctx, "shutting down tracing...")
		// Use a separate context for shutdown, typically context.Background() or a context with a timeout
		shutdownCtx, cancel := context.WithTimeout(ctx, ShutdownTimeout) // Example timeout
		defer cancel()

		if err := tp.Shutdown(shutdownCtx); err != nil {
			logger.ErrorContext(ctx, "error shutting down tracer provider", slog.Any("error", err))
		}
		if writerCloser != nil {
			if err := writerCloser.Close(); err != nil {
				logger.ErrorContext(ctx, "error closing trace file writer", slog.Any("error", err))
			}
		}
		logger.InfoContext(ctx, "tracing shutdown complete.")
	}, nil
}

// --- Exporter Creation Helpers ---

func createOTLPExporter(ctx context.Context, cfg *OTLPConfig) (sdktrace.SpanExporter, error) {
	logger := slog.Default()

	if cfg.Endpoint == "" {
		return nil, errors.New("OTLP endpoint is required")
	}

	protocol := strings.ToLower(cfg.Protocol)
	if protocol == "" {
		protocol = "grpc" // Default to gRPC
	}
	logger.InfoContext(ctx,
		"configuring OTLP exporter",
		slog.String("protocol", protocol),
		slog.String("endpoint", cfg.Endpoint),
		slog.Bool("insecure", cfg.Insecure),
	)

	switch protocol {
	case "grpc":
		grpcOpts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(cfg.Endpoint)}
		if cfg.Insecure {
			grpcOpts = append(grpcOpts, otlptracegrpc.WithInsecure())
		} // Else: Uses default secure credentials
		if len(cfg.Headers) > 0 {
			logger.InfoContext(ctx, "adding OTLP headers", slog.Int("count", len(cfg.Headers)))
			grpcOpts = append(grpcOpts, otlptracegrpc.WithHeaders(cfg.Headers))
		}
		// Add WithDialOption if needing custom grpc.DialOptions
		client := otlptracegrpc.NewClient(grpcOpts...)
		return otlptrace.New(ctx, client)

	case "http/protobuf", "http":
		httpOpts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(cfg.Endpoint)}
		if cfg.Insecure {
			httpOpts = append(httpOpts, otlptracehttp.WithInsecure())
		} // Else: Uses default secure credentials (HTTPS)
		if len(cfg.Headers) > 0 {
			logger.InfoContext(ctx,
				"adding OTLP headers",
				slog.Int("count", len(cfg.Headers)),
			)
			httpOpts = append(httpOpts, otlptracehttp.WithHeaders(cfg.Headers))
		}
		// Add WithTLSClientConfig, WithTimeout, etc. if needed
		client := otlptracehttp.NewClient(httpOpts...)
		return otlptrace.New(ctx, client)

	default:
		return nil, fmt.Errorf("unsupported OTLP protocol: '%s'", cfg.Protocol)
	}
}

func createFileExporter(cfg *FileConfig) (sdktrace.SpanExporter, io.Closer, error) {
	logger := slog.Default()

	if cfg.Path == "" {
		return nil, nil, errors.New("file path is required for file exporter")
	}

	dir := getDir(cfg.Path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, nil, fmt.Errorf("failed to create dir %s for trace file: %w", dir, err)
	}

	// Configure lumberjack rotation with defaults
	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = DefaultFileMaxSize
	}
	maxBackups := cfg.MaxBackups
	if maxBackups <= 0 {
		maxBackups = DefaultFileMaxBackups
	}
	maxAge := cfg.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultFileMaxAge
	}

	lumberjackLogger := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    maxSize,
		MaxBackups: maxBackups,
		MaxAge:     maxAge,
		Compress:   cfg.Compress,
		LocalTime:  true,
	}
	safeWriter := newSyncWriter(lumberjackLogger)

	opts := []stdouttrace.Option{
		stdouttrace.WithWriter(safeWriter),
		stdouttrace.WithoutTimestamps(), // Rely on logger/collector for timestamps
	}
	if cfg.PrettyPrint {
		opts = append(opts, stdouttrace.WithPrettyPrint())
	}

	exporter, err := stdouttrace.New(opts...)
	if err != nil {
		_ = lumberjackLogger.Close()
		return nil, nil, fmt.Errorf("failed create stdouttrace exporter for file: %w", err)
	}

	logger.Info("configuring file trace exporter",
		slog.String("path", cfg.Path),
		slog.Bool("prettyPrint", cfg.PrettyPrint),
		slog.Int("maxSizeMB", maxSize),
		slog.Int("maxBackups", maxBackups),
		slog.Int("maxAgeDays", maxAge),
		slog.Bool("compress", cfg.Compress),
	)

	return exporter, lumberjackLogger, nil // Return lumberjack for closing on shutdown
}

// --- gRPC Context Propagation ---

func InjectTraceContext(ctx context.Context) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	} else {
		md = md.Copy()
	}
	otel.GetTextMapPropagator().Inject(ctx, &metadataCarrier{md})
	return metadata.NewOutgoingContext(ctx, md)
}

type metadataCarrier struct {
	md metadata.MD
}

func (mc *metadataCarrier) Get(key string) string {
	values := mc.md.Get(strings.ToLower(key))
	if len(values) > 0 {
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

// --- Utility Functions ---

func getDir(filePath string) string {
	// Handle potential edge cases like "/" or "filename"
	lastSlash := strings.LastIndex(filePath, "/")
	if lastSlash == -1 {
		return "." // Current directory
	}
	if lastSlash == 0 {
		return "/" // Root directory
	}
	return filePath[:lastSlash]
}
