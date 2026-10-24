package auth

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
)

type (
	httpMethodContextKey        struct{}
	gateAuthenticatedContextKey struct{}
)

// ContextWithHTTPMethod records the HTTP method of an incoming request. Connect
// request gates run before Connect exposes call information, so the server's
// HTTP router stores the method here for ConnectAuthNRequestGate to bind DPoP
// proofs to the method the client actually used.
func ContextWithHTTPMethod(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, httpMethodContextKey{}, method)
}

// HTTPMethodFromContext returns the HTTP method stored by ContextWithHTTPMethod.
func HTTPMethodFromContext(ctx context.Context) (string, bool) {
	method, ok := ctx.Value(httpMethodContextKey{}).(string)
	return method, ok && method != ""
}

// ConnectAuthNRequestGate authenticates Connect requests from their headers
// before Connect reads, decompresses, or unmarshals the request body. It covers
// unary, streaming, and bidi RPCs.
//
// The gate reads the HTTP method from ContextWithHTTPMethod and assumes POST
// when none is stored, which matches gRPC, gRPC-Web, and streaming requests. A
// Connect GET without a stored method fails DPoP method binding.
//
// ConnectAuthNInterceptor skips authentication for requests this gate already
// authenticated, so each DPoP proof is validated once and does not trip replay
// detection. The interceptor still sets DPoP-Nonce response headers, which a
// gate cannot write.
func (a Authentication) ConnectAuthNRequestGate() connect.RequestGateFunc {
	return func(ctx context.Context, spec connect.Spec, _ connect.Peer, header http.Header) (context.Context, error) {
		method, ok := HTTPMethodFromContext(ctx)
		if !ok {
			method = http.MethodPost
		}
		authedCtx, cerr := a.authenticateConnect(ctx, spec.Procedure, method, header)
		if cerr != nil {
			return nil, cerr
		}
		return context.WithValue(authedCtx, gateAuthenticatedContextKey{}, true), nil
	}
}

// authenticatedByGate reports whether ConnectAuthNRequestGate already
// authenticated the request carried by ctx.
func authenticatedByGate(ctx context.Context) bool {
	authed, _ := ctx.Value(gateAuthenticatedContextKey{}).(bool)
	return authed
}
