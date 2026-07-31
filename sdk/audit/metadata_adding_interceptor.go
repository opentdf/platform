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

			// Add the actor ID from the request so it is preserved if we need it
			if actorID, okAct := ctx.Value(ActorIDContextKey).(string); okAct {
				req.Header().Set(string(ActorIDHeaderKey), actorID)
			}

			return next(ctx, req)
		}
	})
}
