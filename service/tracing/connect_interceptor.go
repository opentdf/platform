package tracing

import (
	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/otelconnect"
)

// ConnectClientTraceInterceptor returns a Connect interceptor backed by
// otelconnect that injects OpenTelemetry trace context into outbound requests
// and creates per-RPC spans and metrics.
func ConnectClientTraceInterceptor() (connect.Interceptor, error) {
	return otelconnect.NewInterceptor()
}

// ConnectServerTraceInterceptor returns a Connect interceptor backed by
// otelconnect that extracts OpenTelemetry trace context from incoming requests
// and creates per-RPC spans and metrics. Server spans include the incoming
// User-Agent header as request metadata.
//
// WithTrustRemote makes server spans children of the incoming trace rather
// than linked root spans. otelconnect omits server peer attributes and
// per-message trace events by default.
func ConnectServerTraceInterceptor() (connect.Interceptor, error) {
	return otelconnect.NewInterceptor(serverTraceOptions()...)
}

// ConnectServerTraceInterceptorV2 is ConnectServerTraceInterceptor for
// connect-go v2 servers.
func ConnectServerTraceInterceptorV2() (connectv2.ServerInterceptor, error) {
	return otelconnect.NewServerInterceptor(serverTraceOptions()...)
}

func serverTraceOptions() []otelconnect.Option {
	return []otelconnect.Option{
		otelconnect.WithTrustRemote(),
		otelconnect.WithTraceRequestHeader("User-Agent"),
	}
}
