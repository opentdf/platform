package tracing

import (
	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
)

// ConnectClientTraceInterceptor returns a Connect interceptor backed by
// otelconnect that injects OpenTelemetry trace context into outbound requests
// and creates per-RPC spans and metrics.
func ConnectClientTraceInterceptor() (connect.Interceptor, error) {
	return otelconnect.NewInterceptor(
		otelconnect.WithoutTraceEvents(),
	)
}

// ConnectServerTraceInterceptor returns a Connect interceptor backed by
// otelconnect that extracts OpenTelemetry trace context from incoming requests
// and creates per-RPC spans and metrics.
//
// WithTrustRemote makes server spans children of the incoming trace rather
// than linked root spans. WithoutServerPeerAttributes reduces cardinality.
func ConnectServerTraceInterceptor() (connect.Interceptor, error) {
	return otelconnect.NewInterceptor(
		otelconnect.WithTrustRemote(),
		otelconnect.WithoutServerPeerAttributes(),
		otelconnect.WithoutTraceEvents(),
	)
}
