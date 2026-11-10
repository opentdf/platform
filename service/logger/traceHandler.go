package logger

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// OpenTelemetry-convention log attributes for trace context: 32- and
// 16-character lowercase hex respectively.
const (
	traceIDKey = "trace_id"
	spanIDKey  = "span_id"
)

// traceContextAttrs returns the trace and span IDs of the OpenTelemetry span
// active on the context, letting backends link a span to the logs it produced.
// Records emitted outside a traced request gain nothing.
func traceContextAttrs(ctx context.Context) []slog.Attr {
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return nil
	}

	return []slog.Attr{
		slog.String(traceIDKey, spanCtx.TraceID().String()),
		slog.String(spanIDKey, spanCtx.SpanID().String()),
	}
}
