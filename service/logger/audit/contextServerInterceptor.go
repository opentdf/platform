package audit

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
)

// The audit unary server interceptor is a gRPC interceptor that adds metadata
// to the context of incoming requests. This metadata is used to log audit
// audit events.
func ContextServerInterceptor() connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Get metadata from the context
			headers := req.Header()

			// Add request ID from existing header or create a new one
			var requestID uuid.UUID
			var err error

			requestIDFromMetadata := headers[http.CanonicalHeaderKey(sdkAudit.RequestIDHeaderKey.String())]
			if len(requestIDFromMetadata) > 0 {
				requestID, err = uuid.Parse(requestIDFromMetadata[0])
				if err != nil {
					requestID = uuid.New()
				}
			} else {
				requestID = uuid.New()
			}
			ctx = context.WithValue(ctx, sdkAudit.RequestIDContextKey, requestID)

			// Get the request IP from the metadata header
			requestIPFromMetadata := headers[http.CanonicalHeaderKey(sdkAudit.RequestIPHeaderKey.String())]
			if len(requestIPFromMetadata) > 0 {
				ctx = context.WithValue(ctx, sdkAudit.RequestIPContextKey, requestIPFromMetadata[0])
			}

			// Get the actor ID from the metadata header
			actorIDFromMetadata := headers[http.CanonicalHeaderKey(sdkAudit.ActorIDHeaderKey.String())]
			if len(actorIDFromMetadata) > 0 {
				ctx = context.WithValue(ctx, sdkAudit.ActorIDContextKey, actorIDFromMetadata[0])
			}

			// Sets the user agent header on the context if it is present in the metadata
			userAgent := headers[http.CanonicalHeaderKey(sdkAudit.UserAgentHeaderKey.String())]
			if len(userAgent) > 0 {
				ctx = context.WithValue(ctx, sdkAudit.UserAgentContextKey, userAgent[0])
			}

			return next(ctx, req)
		})
	}

	return connect.UnaryInterceptorFunc(interceptor)
}
