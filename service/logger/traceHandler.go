package logger

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// OpenTelemetry-convention log attributes for trace context: 32- and
// 16-character lowercase hex respectively.
const (
	TraceIDKey = "trace_id"
	SpanIDKey  = "span_id"
)

// TraceHandler annotates records with the trace and span IDs of the
// OpenTelemetry span active on the record's context, letting backends link a
// span to the logs it produced. Records emitted outside a traced request are
// left untouched.
type TraceHandler struct {
	handler slog.Handler
}

// NewTraceHandler wraps handler so emitted records carry the active span's
// trace and span IDs.
func NewTraceHandler(handler slog.Handler) *TraceHandler {
	return &TraceHandler{handler: handler}
}

// Handle adds the active span's trace and span IDs to the record, if any.
func (h *TraceHandler) Handle(ctx context.Context, r slog.Record) error {
	if spanCtx := trace.SpanContextFromContext(ctx); spanCtx.IsValid() {
		r.AddAttrs(
			slog.String(TraceIDKey, spanCtx.TraceID().String()),
			slog.String(SpanIDKey, spanCtx.SpanID().String()),
		)
	}

	return h.handler.Handle(ctx, r)
}

func (h *TraceHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *TraceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TraceHandler{handler: h.handler.WithAttrs(attrs)}
}

func (h *TraceHandler) WithGroup(name string) slog.Handler {
	return &TraceHandler{handler: h.handler.WithGroup(name)}
}
