package logger

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/logger/audit"
	"go.opentelemetry.io/otel/trace"
)

// ContextHandler is a custom slog.Handler that adds context attributes to log records from values set to the
// context by the RPC interceptor. It is used to enrich log records with request-specific metadata such as
// request ID, user agent, request IP, and actor ID.
type ContextHandler struct {
	handler slog.Handler
}

// Handle overrides the default Handle method to add context values set by RPC interceptor.
func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	contextData := audit.GetAuditDataFromContext(ctx)

	// Only add context attributes if RequestID is present, indicating this is part of a request
	if contextData.RequestID != uuid.Nil {
		r.AddAttrs(
			slog.String(string(sdkAudit.RequestIDContextKey), contextData.RequestID.String()),
			slog.String(string(sdkAudit.UserAgentContextKey), contextData.UserAgent),
			slog.String(string(sdkAudit.RequestIPContextKey), contextData.RequestIP),
			slog.String(string(sdkAudit.ActorIDContextKey), contextData.ActorID),
		)
	}

	// Correlate logs with distributed traces: stamp trace_id/span_id from the
	// active span so a log line links back to its Jaeger trace. Independent of
	// RequestID so logs emitted outside the audit path still correlate.
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}

	return h.handler.Handle(ctx, r)
}

func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{handler: h.handler.WithAttrs(attrs)}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{handler: h.handler.WithGroup(name)}
}
