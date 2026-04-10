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

// TestTraceContextPropagation_EndToEnd verifies that the client interceptor
// injects traceparent/tracestate headers and the server interceptor extracts them,
// resulting in both sides sharing the same trace ID.
func TestTraceContextPropagation_EndToEnd(t *testing.T) {
	// 1. Set up an in-memory OTel tracer so we can inspect spans
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	// Save and restore globals
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	defer func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	}()

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// 2. Record the trace ID seen on the server side
	var (
		mu            sync.Mutex
		serverTraceID trace.TraceID
		serverSpanID  trace.SpanID
	)

	// 3. Create a Connect handler with the server-side trace interceptor
	mux := http.NewServeMux()
	handler := connect.NewUnaryHandler(
		"/test.v1.TestService/Ping",
		func(ctx context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			// The server interceptor should have extracted trace context into ctx
			sc := trace.SpanContextFromContext(ctx)
			mu.Lock()
			serverTraceID = sc.TraceID()
			serverSpanID = sc.SpanID()
			mu.Unlock()
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithInterceptors(tracing.ConnectServerTraceInterceptor()),
	)
	mux.Handle("/test.v1.TestService/", handler)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 4. Create a Connect client with the client-side trace interceptor
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		srv.Client(),
		srv.URL+"/test.v1.TestService/Ping",
		connect.WithInterceptors(tracing.ConnectClientTraceInterceptor()),
	)

	// 5. Start a client-side span to establish a trace context
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "client-call")
	clientTraceID := span.SpanContext().TraceID()
	clientSpanID := span.SpanContext().SpanID()

	// 6. Make the Connect RPC call
	_, err := client.CallUnary(ctx, connect.NewRequest(&emptypb.Empty{}))
	span.End()
	require.NoError(t, err)

	// 7. Verify trace context was propagated
	mu.Lock()
	defer mu.Unlock()

	assert.True(t, clientTraceID.IsValid(), "client trace ID should be valid")
	assert.True(t, serverTraceID.IsValid(), "server trace ID should be valid")
	assert.Equal(t, clientTraceID, serverTraceID,
		"server must see the same trace ID as the client — trace context was propagated")
	assert.Equal(t, clientSpanID, serverSpanID,
		"server must see the client's span ID as the remote parent")

	t.Logf("client trace ID: %s  span ID: %s", clientTraceID, clientSpanID)
	t.Logf("server trace ID: %s  span ID: %s", serverTraceID, serverSpanID)
}

// TestTraceContextPropagation_NoTraceContext verifies that the interceptors
// are safe when no trace context exists (no-op propagator behavior).
func TestTraceContextPropagation_NoTraceContext(t *testing.T) {
	// Use a no-op propagator — simulates a deployment without OTel configured
	prevProp := otel.GetTextMapPropagator()
	defer otel.SetTextMapPropagator(prevProp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())

	var serverTraceID trace.TraceID

	mux := http.NewServeMux()
	handler := connect.NewUnaryHandler(
		"/test.v1.TestService/Ping",
		func(ctx context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			serverTraceID = trace.SpanContextFromContext(ctx).TraceID()
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithInterceptors(tracing.ConnectServerTraceInterceptor()),
	)
	mux.Handle("/test.v1.TestService/", handler)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		srv.Client(),
		srv.URL+"/test.v1.TestService/Ping",
		connect.WithInterceptors(tracing.ConnectClientTraceInterceptor()),
	)

	_, err := client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	require.NoError(t, err)

	// With no propagator, server should not see any trace context
	assert.False(t, serverTraceID.IsValid(),
		"server should not see a trace ID when no propagator is configured")
}
