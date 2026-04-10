package tracing

import (
	"context"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// ConnectClientTraceInterceptor returns a Connect interceptor that injects
// OpenTelemetry trace context (traceparent/tracestate) into outbound HTTP
// request headers, enabling distributed trace propagation across Connect RPCs.
// Handles both unary and streaming calls.
func ConnectClientTraceInterceptor() connect.Interceptor {
	return &connectClientTraceInterceptor{}
}

type connectClientTraceInterceptor struct{}

func (i *connectClientTraceInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Spec().IsClient {
			otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header()))
		}
		return next(ctx, req)
	}
}

func (i *connectClientTraceInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(conn.RequestHeader()))
		return conn
	}
}

func (i *connectClientTraceInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// ConnectServerTraceInterceptor returns a Connect interceptor that extracts
// OpenTelemetry trace context (traceparent/tracestate) from incoming HTTP
// request headers into the Go context, enabling distributed trace continuity
// for Connect RPC handlers. Handles both unary and streaming calls.
func ConnectServerTraceInterceptor() connect.Interceptor {
	return &connectServerTraceInterceptor{}
}

type connectServerTraceInterceptor struct{}

func (i *connectServerTraceInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if !req.Spec().IsClient {
			ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(req.Header()))
		}
		return next(ctx, req)
	}
}

func (i *connectServerTraceInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i *connectServerTraceInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(conn.RequestHeader()))
		return next(ctx, conn)
	}
}
