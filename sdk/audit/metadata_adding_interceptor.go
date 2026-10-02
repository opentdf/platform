package audit

import (
	"context"

	"connectrpc.com/connect"
	"github.com/google/uuid"
)

func MetadataAddingConnectInterceptor() connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Only apply to outgoing client requests
			if !req.Spec().IsClient {
				return next(ctx, req)
			}

			// Get any existing request ID from context
			requestID, ok := ctx.Value(RequestIDContextKey).(uuid.UUID)
			if !ok || requestID == uuid.Nil {
				requestID = uuid.New()
			}
			req.Header().Set(string(RequestIDHeaderKey), requestID.String())

			// Add the request IP to a custom header so it is preserved
			if requestIP, okIP := ctx.Value(RequestIPContextKey).(string); okIP {
				req.Header().Set(string(RequestIPHeaderKey), requestIP)
			}

			return next(ctx, req)
		}
	})
}
