package logger

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/logger/audit"
)

// contextAttrsFunc derives log attributes from a record's context. It returns
// nil when the context carries nothing to add.
type contextAttrsFunc func(context.Context) []slog.Attr

// contextAttrsHandler is a slog.Handler that enriches each record with
// attributes derived from its context, then delegates to the wrapped handler.
type contextAttrsHandler struct {
	handler slog.Handler
	sources []contextAttrsFunc
}

// newContextAttrsHandler wraps handler so each record gains the attributes
// produced by sources, in order. With no sources, handler is returned as-is.
func newContextAttrsHandler(handler slog.Handler, sources ...contextAttrsFunc) slog.Handler {
	if len(sources) == 0 {
		return handler
	}

	return &contextAttrsHandler{handler: handler, sources: sources}
}

func (h *contextAttrsHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, source := range h.sources {
		if attrs := source(ctx); len(attrs) > 0 {
			r.AddAttrs(attrs...)
		}
	}

	return h.handler.Handle(ctx, r)
}

func (h *contextAttrsHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *contextAttrsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextAttrsHandler{handler: h.handler.WithAttrs(attrs), sources: h.sources}
}

func (h *contextAttrsHandler) WithGroup(name string) slog.Handler {
	return &contextAttrsHandler{handler: h.handler.WithGroup(name), sources: h.sources}
}

// requestContextAttrs returns the request metadata set on the context by the
// RPC interceptor: request ID, user agent, request IP, and actor ID.
func requestContextAttrs(ctx context.Context) []slog.Attr {
	contextData := audit.GetAuditDataFromContext(ctx)

	// Only add context attributes if RequestID is present, indicating this is part of a request
	if contextData.RequestID == uuid.Nil {
		return nil
	}

	return []slog.Attr{
		slog.String(string(sdkAudit.RequestIDContextKey), contextData.RequestID.String()),
		slog.String(string(sdkAudit.UserAgentContextKey), contextData.UserAgent),
		slog.String(string(sdkAudit.RequestIPContextKey), contextData.RequestIP),
		slog.String(string(sdkAudit.ActorIDContextKey), contextData.ActorID),
	}
}
