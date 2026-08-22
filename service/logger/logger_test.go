package logger

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
)

// captureStdout swaps os.Stdout for a pipe and returns the lines written by fn.
func captureStdout(t *testing.T, fn func()) []string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	defer func() {
		os.Stdout = orig
	}()

	fn()
	require.NoError(t, w.Close())

	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	require.NoError(t, scanner.Err())

	return lines
}

func decodeLine(t *testing.T, line string) map[string]any {
	t.Helper()

	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &out))
	return out
}

// emitAuditEvent drives an immediate audit event through the request metadata
// interceptor.
func emitAuditEvent(ctx context.Context, t *testing.T, lg *Logger) {
	t.Helper()

	next := audit.ContextServerInterceptor(lg.Audit)(
		func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			audit.LogAuditEvent(ctx, audit.VerbRewrap, &audit.EventObject{})
			return nil, nil //nolint:nilnil // the interceptor ignores the response in this test
		},
	)

	_, err := next(ctx, connect.NewRequest(&struct{}{}))
	require.NoError(t, err)
}

func Test_NewLogger_CorrelatesMainAndAuditLogs(t *testing.T) {
	ctx := tracedContext(t)

	lines := captureStdout(t, func() {
		lg, err := NewLogger(Config{Level: "info", Output: "stdout", Type: "json"})
		require.NoError(t, err)

		lg.InfoContext(ctx, "handled request")
		emitAuditEvent(ctx, t, lg)
	})
	require.Len(t, lines, 2, "expected one application log and one audit log")

	appLog := decodeLine(t, lines[0])
	assert.Equal(t, "handled request", appLog["msg"])
	assert.Equal(t, testTraceIDHex, appLog[traceIDKey])
	assert.Equal(t, testSpanIDHex, appLog[spanIDKey])

	auditLog := decodeLine(t, lines[1])
	assert.Equal(t, "AUDIT", auditLog["level"])
	assert.Equal(t, testTraceIDHex, auditLog[traceIDKey])
	assert.Equal(t, testSpanIDHex, auditLog[spanIDKey])
}

func Test_NewLogger_TraceCorrelationDisabled(t *testing.T) {
	ctx := tracedContext(t)
	disabled := false

	lines := captureStdout(t, func() {
		lg, err := NewLogger(Config{Level: "info", Output: "stdout", Type: "json", TraceCorrelation: &disabled})
		require.NoError(t, err)

		lg.InfoContext(ctx, "handled request")
		emitAuditEvent(ctx, t, lg)
	})
	require.Len(t, lines, 2)

	for _, line := range lines {
		entry := decodeLine(t, line)
		assert.NotContains(t, entry, traceIDKey)
		assert.NotContains(t, entry, spanIDKey)
	}
}

// The main logger carries request metadata alongside the trace IDs; audit
// records carry only the trace IDs, since the metadata is already in the payload.
func Test_NewLogger_RequestMetadataOnlyOnMainLogger(t *testing.T) {
	ctx := tracedContext(t)

	lines := captureStdout(t, func() {
		lg, err := NewLogger(Config{Level: "info", Output: "stdout", Type: "json"})
		require.NoError(t, err)

		next := audit.ContextServerInterceptor(lg.Audit)(
			func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
				lg.InfoContext(ctx, "handled request")
				audit.LogAuditEvent(ctx, audit.VerbRewrap, &audit.EventObject{})
				return nil, nil //nolint:nilnil // the interceptor ignores the response in this test
			},
		)
		_, err = next(ctx, connect.NewRequest(&struct{}{}))
		require.NoError(t, err)
	})
	require.Len(t, lines, 2)

	appLog := decodeLine(t, lines[0])
	assert.Equal(t, testTraceIDHex, appLog[traceIDKey])
	assert.NotEmpty(t, appLog["request-id"])
	assert.Contains(t, appLog, "user-agent")
	assert.Contains(t, appLog, "request-ip")
	assert.Contains(t, appLog, "actor-id")

	auditLog := decodeLine(t, lines[1])
	assert.Equal(t, testTraceIDHex, auditLog[traceIDKey])
	assert.NotContains(t, auditLog, "request-id")
}

// With tracing disabled the platform installs a noop tracer provider but keeps
// the W3C propagator, so an inbound traceparent still reaches the logs while
// self-started spans do not.
func Test_NewLogger_NoopProviderPreservesInboundTraceContext(t *testing.T) {
	tracer := noop.NewTracerProvider().Tracer("test")

	t.Run("inbound trace context is kept", func(t *testing.T) {
		lines := captureStdout(t, func() {
			lg, err := NewLogger(Config{Level: "info", Output: "stdout", Type: "json"})
			require.NoError(t, err)

			ctx, span := tracer.Start(tracedContext(t), "rewrap")
			defer span.End()

			lg.InfoContext(ctx, "handled request")
			emitAuditEvent(ctx, t, lg)
		})
		require.Len(t, lines, 2)

		for _, line := range lines {
			entry := decodeLine(t, line)
			assert.Equal(t, testTraceIDHex, entry[traceIDKey])
			assert.Equal(t, testSpanIDHex, entry[spanIDKey])
		}
	})

	t.Run("span without inbound context emits nothing", func(t *testing.T) {
		lines := captureStdout(t, func() {
			lg, err := NewLogger(Config{Level: "info", Output: "stdout", Type: "json"})
			require.NoError(t, err)

			ctx, span := tracer.Start(context.Background(), "rewrap")
			defer span.End()

			lg.InfoContext(ctx, "handled request")
		})
		require.Len(t, lines, 1)

		entry := decodeLine(t, lines[0])
		assert.NotContains(t, entry, traceIDKey)
		assert.NotContains(t, entry, spanIDKey)
	})
}

func Test_NewLogger_UntracedRequestHasNoTraceFields(t *testing.T) {
	lines := captureStdout(t, func() {
		lg, err := NewLogger(Config{Level: "info", Output: "stdout", Type: "json"})
		require.NoError(t, err)

		lg.InfoContext(context.Background(), "startup")
	})
	require.Len(t, lines, 1)

	entry := decodeLine(t, lines[0])
	assert.NotContains(t, entry, traceIDKey)
	assert.NotContains(t, entry, spanIDKey)
}
