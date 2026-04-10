package tracing_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/service/tracing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/emptypb"
)

// setupOTel configures an in-memory tracer provider and W3C trace propagator,
// returning the provider and a cleanup function that restores prior globals.
func setupOTel(t *testing.T) *sdktrace.TracerProvider {
	t.Helper()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp
}

// TestTraceContextPropagation_Unary verifies that the client interceptor
// injects traceparent/tracestate headers and the server interceptor extracts them,
// resulting in both sides sharing the same trace ID for unary RPCs.
func TestTraceContextPropagation_Unary(t *testing.T) {
	tp := setupOTel(t)

	serverInt, err := tracing.ConnectServerTraceInterceptor()
	require.NoError(t, err)
	clientInt, err := tracing.ConnectClientTraceInterceptor()
	require.NoError(t, err)

	var (
		mu            sync.Mutex
		serverTraceID trace.TraceID
	)

	mux := http.NewServeMux()
	handler := connect.NewUnaryHandler(
		"/test.v1.TestService/Ping",
		func(ctx context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			sc := trace.SpanContextFromContext(ctx)
			mu.Lock()
			serverTraceID = sc.TraceID()
			mu.Unlock()
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithInterceptors(serverInt),
	)
	mux.Handle("/test.v1.TestService/", handler)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		srv.Client(),
		srv.URL+"/test.v1.TestService/Ping",
		connect.WithInterceptors(clientInt),
	)

	ctx, span := tp.Tracer("test").Start(context.Background(), "client-call")
	clientTraceID := span.SpanContext().TraceID()

	_, err = client.CallUnary(ctx, connect.NewRequest(&emptypb.Empty{}))
	span.End()
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()

	assert.True(t, clientTraceID.IsValid(), "client trace ID should be valid")
	assert.True(t, serverTraceID.IsValid(), "server trace ID should be valid")
	assert.Equal(t, clientTraceID, serverTraceID,
		"server must see the same trace ID as the client")

	t.Logf("client trace: %s", clientTraceID)
	t.Logf("server trace: %s", serverTraceID)
}

// TestTraceContextPropagation_ServerStream verifies trace context propagation
// for server-streaming RPCs, exercising WrapStreamingClient on the client side
// and WrapStreamingHandler on the server side.
func TestTraceContextPropagation_ServerStream(t *testing.T) {
	tp := setupOTel(t)

	serverInt, err := tracing.ConnectServerTraceInterceptor()
	require.NoError(t, err)
	clientInt, err := tracing.ConnectClientTraceInterceptor()
	require.NoError(t, err)

	var (
		mu            sync.Mutex
		serverTraceID trace.TraceID
	)

	mux := http.NewServeMux()
	handler := connect.NewServerStreamHandler(
		"/test.v1.TestService/StreamPing",
		func(ctx context.Context, _ *connect.Request[emptypb.Empty], stream *connect.ServerStream[emptypb.Empty]) error {
			sc := trace.SpanContextFromContext(ctx)
			mu.Lock()
			serverTraceID = sc.TraceID()
			mu.Unlock()
			return stream.Send(&emptypb.Empty{})
		},
		connect.WithInterceptors(serverInt),
	)
	mux.Handle("/test.v1.TestService/", handler)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		srv.Client(),
		srv.URL+"/test.v1.TestService/StreamPing",
		connect.WithInterceptors(clientInt),
	)

	ctx, span := tp.Tracer("test").Start(context.Background(), "client-stream-call")
	clientTraceID := span.SpanContext().TraceID()

	stream, err := client.CallServerStream(ctx, connect.NewRequest(&emptypb.Empty{}))
	require.NoError(t, err)
	for stream.Receive() {
	}
	require.NoError(t, stream.Err())
	require.NoError(t, stream.Close())
	span.End()

	mu.Lock()
	defer mu.Unlock()

	assert.True(t, clientTraceID.IsValid(), "client trace ID should be valid")
	assert.True(t, serverTraceID.IsValid(), "server trace ID should be valid")
	assert.Equal(t, clientTraceID, serverTraceID,
		"server must see the same trace ID as the client (streaming)")

	t.Logf("client trace: %s", clientTraceID)
	t.Logf("server trace: %s", serverTraceID)
}

// TestTraceContextPropagation_NoTraceContext verifies that a no-op propagator
// prevents trace context from reaching the server, even when the client has
// an active span. This proves the interceptor respects the propagator config.
func TestTraceContextPropagation_NoTraceContext(t *testing.T) {
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	defer func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	}()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())

	serverInt, err := tracing.ConnectServerTraceInterceptor()
	require.NoError(t, err)
	clientInt, err := tracing.ConnectClientTraceInterceptor()
	require.NoError(t, err)

	var serverTraceID trace.TraceID

	mux := http.NewServeMux()
	handler := connect.NewUnaryHandler(
		"/test.v1.TestService/Ping",
		func(ctx context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			serverTraceID = trace.SpanContextFromContext(ctx).TraceID()
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithInterceptors(serverInt),
	)
	mux.Handle("/test.v1.TestService/", handler)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		srv.Client(),
		srv.URL+"/test.v1.TestService/Ping",
		connect.WithInterceptors(clientInt),
	)

	ctx, span := tp.Tracer("test").Start(context.Background(), "client-call")
	clientTraceID := span.SpanContext().TraceID()
	require.True(t, clientTraceID.IsValid(), "client must have a valid trace ID for this test")

	_, err = client.CallUnary(ctx, connect.NewRequest(&emptypb.Empty{}))
	span.End()
	require.NoError(t, err)

	// With a no-op propagator, the client's trace context is not injected into
	// headers. otelconnect still creates a server span, but it starts a new
	// independent trace — the trace IDs must differ.
	assert.NotEqual(t, clientTraceID, serverTraceID,
		"server should have a different trace ID when no propagator is configured")
}
