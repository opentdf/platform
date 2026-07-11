package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

// newHandler wires a ContextHandler around a JSON handler writing to buf.
func newHandler(buf *bytes.Buffer) slog.Handler {
	return &ContextHandler{handler: slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})}
}

func logAndParse(t *testing.T, ctx context.Context) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	l := slog.New(newHandler(&buf))
	l.InfoContext(ctx, "test message")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse log line %q: %v", buf.String(), err)
	}
	return got
}

func TestContextHandler_InjectsTraceAndSpanID(t *testing.T) {
	traceID, err := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := trace.SpanIDFromHex("0102030405060708")
	if err != nil {
		t.Fatal(err)
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	got := logAndParse(t, ctx)
	if got["trace_id"] != traceID.String() {
		t.Errorf("trace_id = %v, want %s", got["trace_id"], traceID.String())
	}
	if got["span_id"] != spanID.String() {
		t.Errorf("span_id = %v, want %s", got["span_id"], spanID.String())
	}
}

func TestContextHandler_NoSpanNoTraceFields(t *testing.T) {
	got := logAndParse(t, context.Background())
	if _, ok := got["trace_id"]; ok {
		t.Errorf("trace_id should be absent without an active span, got %v", got["trace_id"])
	}
	if _, ok := got["span_id"]; ok {
		t.Errorf("span_id should be absent without an active span, got %v", got["span_id"])
	}
}
