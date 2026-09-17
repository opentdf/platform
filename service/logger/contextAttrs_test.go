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

type tenantCtxKey struct{}

// tenantAttrs models an embedder's closure: it derives an attribute from a
// value the caller put on the context, and stays silent when there is none.
func tenantAttrs(ctx context.Context) []slog.Attr {
	tenant, ok := ctx.Value(tenantCtxKey{}).(string)
	if !ok || tenant == "" {
		return nil
	}
	return []slog.Attr{slog.String("org_id", tenant)}
}

func tenantContext(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, tenant)
}

func Test_ContextAttrs_RegisteredFuncAddsAttrs(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := newContextAttrsHandler(slog.NewJSONHandler(buf, nil), contextAttrSources(Config{ContextAttrs: []ContextAttrFunc{tenantAttrs}})...)

	out := logJSON(tenantContext(context.Background(), "acme"), t, buf, handler)

	assert.Equal(t, "acme", out["org_id"])
}

func Test_ContextAttrs_NilReturnAddsNothing(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := newContextAttrsHandler(slog.NewJSONHandler(buf, nil), contextAttrSources(Config{ContextAttrs: []ContextAttrFunc{tenantAttrs}})...)

	out := logJSON(context.Background(), t, buf, handler)

	assert.NotContains(t, out, "org_id", "an absent value must omit the key, not emit an empty string")
}

// Trace correlation leads, then the caller's funcs in registration order.
func Test_ContextAttrs_ComposeInOrderAfterTraceAttrs(t *testing.T) {
	buf := &bytes.Buffer{}
	second := func(context.Context) []slog.Attr { return []slog.Attr{slog.Int("second", 2)} }

	cfg := Config{ContextAttrs: []ContextAttrFunc{tenantAttrs, second}}
	handler := newContextAttrsHandler(slog.NewJSONHandler(buf, nil), contextAttrSources(cfg)...)

	logJSON(tenantContext(tracedContext(t), "acme"), t, buf, handler)

	assert.Regexp(t, `"trace_id".*"org_id".*"second"`, buf.String())
}

// The request metadata source stays last, so an embedder's attrs never displace it.
func Test_ContextAttrs_PrecedeLoggerSpecificExtras(t *testing.T) {
	cfg := Config{ContextAttrs: []ContextAttrFunc{tenantAttrs}}

	sources := contextAttrSources(cfg, requestContextAttrs)

	require.Len(t, sources, 3)
}

// The attrs must reach the audit record envelope as well as the application
// log, so audit records are filterable without parsing the payload.
func Test_ContextAttrs_ReachBothAppLogAndAuditEnvelope(t *testing.T) {
	ctx := tenantContext(tracedContext(t), "acme")

	lines := captureStdout(t, func() {
		lg, err := NewLogger(Config{
			Level: "info", Output: "stdout", Type: "json",
			ContextAttrs: []ContextAttrFunc{tenantAttrs},
		})
		require.NoError(t, err)

		lg.InfoContext(ctx, "handled request")
		emitAuditEvent(ctx, t, lg)
	})
	require.Len(t, lines, 2, "expected one application log and one audit log")

	appLog := decodeLine(t, lines[0])
	assert.Equal(t, "acme", appLog["org_id"])

	auditLog := decodeLine(t, lines[1])
	assert.Equal(t, "AUDIT", auditLog["level"])
	assert.Equal(t, "acme", auditLog["org_id"])
}

// A Go-only field must never reach a serialized config.
func Test_ContextAttrs_NotSerialized(t *testing.T) {
	cfg := Config{Level: "info", ContextAttrs: []ContextAttrFunc{tenantAttrs}}

	serialized, err := json.Marshal(cfg)
	require.NoError(t, err)
	assert.NotContains(t, string(serialized), "ContextAttrs")
	assert.NotContains(t, string(serialized), "context_attrs")
}
