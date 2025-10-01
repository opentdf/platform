package audit

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// MetadataAddingClientInterceptor is a client side gRPC interceptor that adds an
// X-Request-ID header to outgoing requests. If a request ID is already present
// in the context, it will be used. Otherwise, a new request ID will be generated.
func MetadataAddingClientInterceptor(
	ctx context.Context,
	method string,
	req, reply any,
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	// Get any existing request ID from context
	requestID, ok := ctx.Value(RequestIDContextKey).(uuid.UUID)
	if !ok || requestID == uuid.Nil {
		requestID = uuid.New()
	}
	ctx = metadata.AppendToOutgoingContext(ctx, string(RequestIDHeaderKey), requestID.String())

	// Add the request IP to a custom header so it is preserved
	requestIP, isOK := realip.FromContext(ctx)
	if isOK {
		ctx = metadata.AppendToOutgoingContext(ctx, string(RequestIPHeaderKey), requestIP.String())
	}

	// Add the actor ID from the request so it is preserved if we need it
	actorID, isOK := ctx.Value(ActorIDContextKey).(string)
	if isOK {
		ctx = metadata.AppendToOutgoingContext(ctx, string(ActorIDHeaderKey), actorID)
	}

	err := invoker(ctx, method, req, reply, cc, opts...)
	return err
}

func MetadataAddingConnectInterceptor(l *slog.Logger) connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			incoming, _ := metadata.FromIncomingContext(ctx)
			ougoing, _ := metadata.FromOutgoingContext(ctx)
			l.Info("MetadataAddingConnectInterceptor ran",
				slog.Any("headers", req.Header()),
				slog.Any("context", ctx),
				slog.Any("incoming metadata", incoming),
				slog.Any("outgoing metadata", ougoing),
			)
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
