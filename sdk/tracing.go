package sdk

import (
	"context"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// TraceContextInterceptor returns a Connect unary interceptor that injects
// OpenTelemetry trace context (traceparent/tracestate) into outbound HTTP
// request headers, enabling distributed trace propagation across Connect RPCs.
func TraceContextInterceptor() connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if req.Spec().IsClient {
				otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header()))
			}
			return next(ctx, req)
		}
	})
}
