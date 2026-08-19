package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

const (
	testTraceIDHex = "4bf92f3577b34da6a3ce929d0e0e4736"
	testSpanIDHex  = "00f067aa0ba902b7"
	testLogMsg     = "test message"
)

// tracedContext returns a context carrying a valid, non-recording span context.
func tracedContext(t *testing.T) context.Context {
	t.Helper()

	traceID, err := trace.TraceIDFromHex(testTraceIDHex)
	require.NoError(t, err)
	spanID, err := trace.SpanIDFromHex(testSpanIDHex)
	require.NoError(t, err)

	spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	require.True(t, spanCtx.IsValid())

	return trace.ContextWithSpanContext(context.Background(), spanCtx)
}

// logJSON emits a record through handler and returns the decoded output.
func logJSON(ctx context.Context, t *testing.T, buf *bytes.Buffer, handler slog.Handler) map[string]any {
	t.Helper()

	slog.New(handler).InfoContext(ctx, testLogMsg)

	var out map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	return out
}

func Test_TraceHandler_AddsTraceAndSpanID(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := newContextAttrsHandler(slog.NewJSONHandler(buf, nil), traceContextAttrs)

	out := logJSON(tracedContext(t), t, buf, handler)

	// 32- and 16-character lowercase hex, per the OpenTelemetry convention.
	assert.Equal(t, testTraceIDHex, out[traceIDKey])
	assert.Equal(t, testSpanIDHex, out[spanIDKey])
}

func Test_TraceHandler_NoSpanOnContext(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := newContextAttrsHandler(slog.NewJSONHandler(buf, nil), traceContextAttrs)

	out := logJSON(context.Background(), t, buf, handler)

	assert.NotContains(t, out, traceIDKey)
	assert.NotContains(t, out, spanIDKey)
}

// An invalid (all-zero) span context must not leak placeholder IDs into logs.
func Test_TraceHandler_InvalidSpanContext(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := newContextAttrsHandler(slog.NewJSONHandler(buf, nil), traceContextAttrs)
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{}))

	out := logJSON(ctx, t, buf, handler)

	assert.NotContains(t, out, traceIDKey)
	assert.NotContains(t, out, spanIDKey)
}

func Test_TraceHandler_PreservesWrappedHandlerAttrs(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := newContextAttrsHandler(slog.NewJSONHandler(buf, nil), traceContextAttrs).
		WithAttrs([]slog.Attr{slog.String("service", "kas")})

	out := logJSON(tracedContext(t), t, buf, handler)

	assert.Equal(t, "kas", out["service"])
	assert.Equal(t, testTraceIDHex, out[traceIDKey])
	assert.Equal(t, testSpanIDHex, out[spanIDKey])
}

func Test_TraceHandler_EnabledDelegates(t *testing.T) {
	inner := slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})
	handler := newContextAttrsHandler(inner, traceContextAttrs)

	assert.False(t, handler.Enabled(context.Background(), slog.LevelInfo))
	assert.True(t, handler.Enabled(context.Background(), slog.LevelError))
}

// Sources are applied in order, so a logger with both trace and request
// correlation emits the trace IDs ahead of the request metadata.
func Test_ContextAttrsHandler_AppliesSourcesInOrder(t *testing.T) {
	buf := &bytes.Buffer{}
	first := func(context.Context) []slog.Attr { return []slog.Attr{slog.Int("order", 1)} }
	second := func(context.Context) []slog.Attr { return []slog.Attr{slog.Int("order", 2)} }

	handler := newContextAttrsHandler(slog.NewJSONHandler(buf, nil), first, second)
	logJSON(context.Background(), t, buf, handler)

	assert.Regexp(t, `"order":1.*"order":2`, buf.String())
}

func Test_ContextAttrsHandler_NoSourcesIsPassthrough(t *testing.T) {
	inner := slog.NewJSONHandler(&bytes.Buffer{}, nil)

	assert.Same(t, inner, newContextAttrsHandler(inner))
}

func Test_Config_TraceCorrelationEnabled(t *testing.T) {
	enabled := true
	disabled := false

	assert.True(t, Config{}.traceCorrelationEnabled(), "unset should default to enabled")
	assert.True(t, Config{TraceCorrelation: &enabled}.traceCorrelationEnabled())
	assert.False(t, Config{TraceCorrelation: &disabled}.traceCorrelationEnabled())
}

func Test_ContextAttrSources_TraceCorrelationDisabled(t *testing.T) {
	buf := &bytes.Buffer{}
	inner := slog.NewJSONHandler(buf, nil)
	disabled := false

	sources := contextAttrSources(Config{TraceCorrelation: &disabled})
	assert.Empty(t, sources, "no sources means the wrapped handler is used directly")

	handler := newContextAttrsHandler(inner, sources...)
	out := logJSON(tracedContext(t), t, buf, handler)
	assert.NotContains(t, out, traceIDKey)
	assert.NotContains(t, out, spanIDKey)
}
