package tracing

import (
	"context"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// ConnectClientTraceInterceptor returns a Connect unary interceptor that injects
// OpenTelemetry trace context (traceparent/tracestate) into outbound HTTP
// request headers, enabling distributed trace propagation across Connect RPCs.
func ConnectClientTraceInterceptor() connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if req.Spec().IsClient {
				otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header()))
			}
			return next(ctx, req)
		}
	})
}

// ConnectServerTraceInterceptor returns a Connect unary interceptor that
// extracts OpenTelemetry trace context (traceparent/tracestate) from incoming
// HTTP request headers into the Go context, enabling distributed trace
// continuity for Connect RPC handlers.
func ConnectServerTraceInterceptor() connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if !req.Spec().IsClient {
				ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(req.Header()))
			}
			return next(ctx, req)
		}
	})
}
