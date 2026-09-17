package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type callerCtxKey struct{}

const (
	callerAttrKey = "caller"
	testCaller    = "caller-1"
)

// callerAttrs models an embedder's closure: it derives an attribute from a
// value the caller put on the context, and stays silent when there is none.
func callerAttrs(ctx context.Context) []slog.Attr {
	caller, ok := ctx.Value(callerCtxKey{}).(string)
	if !ok || caller == "" {
		return nil
	}
	return []slog.Attr{slog.String(callerAttrKey, caller)}
}

func callerContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, callerCtxKey{}, testCaller)
}

func Test_ContextAttrs_RegisteredFuncAddsAttrs(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := newContextAttrsHandler(slog.NewJSONHandler(buf, nil), contextAttrSources(Config{ContextAttrs: []ContextAttrFunc{callerAttrs}})...)

	out := logJSON(callerContext(context.Background()), t, buf, handler)

	assert.Equal(t, testCaller, out[callerAttrKey])
}

func Test_ContextAttrs_NilReturnAddsNothing(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := newContextAttrsHandler(slog.NewJSONHandler(buf, nil), contextAttrSources(Config{ContextAttrs: []ContextAttrFunc{callerAttrs}})...)

	out := logJSON(context.Background(), t, buf, handler)

	assert.NotContains(t, out, callerAttrKey, "an absent value must omit the key, not emit an empty string")
}

// Trace correlation leads, then the caller's funcs in registration order.
func Test_ContextAttrs_ComposeInOrderAfterTraceAttrs(t *testing.T) {
	buf := &bytes.Buffer{}
	second := func(context.Context) []slog.Attr { return []slog.Attr{slog.Int("second", 2)} }

	cfg := Config{ContextAttrs: []ContextAttrFunc{callerAttrs, second}}
	handler := newContextAttrsHandler(slog.NewJSONHandler(buf, nil), contextAttrSources(cfg)...)

	logJSON(callerContext(tracedContext(t)), t, buf, handler)

	assert.Regexp(t, `"trace_id".*"caller".*"second"`, buf.String())
}

// The request metadata source stays last, so an embedder's attrs never displace it.
func Test_ContextAttrs_PrecedeLoggerSpecificExtras(t *testing.T) {
	cfg := Config{ContextAttrs: []ContextAttrFunc{callerAttrs}}

	sources := contextAttrSources(cfg, requestContextAttrs)

	require.Len(t, sources, 3)
}

// The attrs must reach the audit record envelope as well as the application
// log, so audit records are filterable without parsing the payload.
func Test_ContextAttrs_ReachBothAppLogAndAuditEnvelope(t *testing.T) {
	ctx := callerContext(tracedContext(t))

	lines := captureStdout(t, func() {
		lg, err := NewLogger(Config{
			Level: "info", Output: "stdout", Type: "json",
			ContextAttrs: []ContextAttrFunc{callerAttrs},
		})
		require.NoError(t, err)

		lg.InfoContext(ctx, "handled request")
		emitAuditEvent(ctx, t, lg)
	})
	require.Len(t, lines, 2, "expected one application log and one audit log")

	appLog := decodeLine(t, lines[0])
	assert.Equal(t, testCaller, appLog[callerAttrKey])

	auditLog := decodeLine(t, lines[1])
	assert.Equal(t, "AUDIT", auditLog["level"])
	assert.Equal(t, testCaller, auditLog[callerAttrKey])
}

// A nil entry must be dropped at construction. Left in place it would panic on
// every record, inside the handler, where the failure is hardest to attribute.
func Test_ContextAttrs_NilFuncIsSkipped(t *testing.T) {
	cfg := Config{ContextAttrs: []ContextAttrFunc{nil, callerAttrs, nil}}

	require.Len(t, contextAttrSources(cfg), 2, "trace attrs plus the one non-nil func")

	lines := captureStdout(t, func() {
		lg, err := NewLogger(Config{
			Level: "info", Output: "stdout", Type: "json",
			ContextAttrs: []ContextAttrFunc{nil, callerAttrs},
		})
		require.NoError(t, err)

		require.NotPanics(t, func() {
			lg.InfoContext(callerContext(context.Background()), "handled request")
		})
	})
	require.Len(t, lines, 1)
	assert.Equal(t, testCaller, decodeLine(t, lines[0])[callerAttrKey], "the surviving func still runs")
}

// A Go-only field must never reach a serialized config.
func Test_ContextAttrs_NotSerialized(t *testing.T) {
	cfg := Config{Level: "info", ContextAttrs: []ContextAttrFunc{callerAttrs}}

	serialized, err := json.Marshal(cfg)
	require.NoError(t, err)
	assert.NotContains(t, string(serialized), "ContextAttrs")
	assert.NotContains(t, string(serialized), "context_attrs")
}
