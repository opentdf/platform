package audit

import (
	"context"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	requestIDHeaderKey = "x-request-id"
	requestIPHeaderKey = "x-forwarded-request-ip"
	actorIDHeaderKey   = "x-forwarded-actor-id"
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
	newMetadata := make([]string, 0)

	// Get any existing request ID from context
	requestID, ok := ctx.Value(RequestIDContextKey).(uuid.UUID)
	if !ok || requestID == uuid.Nil {
		requestID = uuid.New()
	}
	newMetadata = append(newMetadata, requestIDHeaderKey, requestID.String())

	// Add the request IP to a custom header so it is preserved
	requestIP, isOK := realip.FromContext(ctx)
	if isOK {
		newMetadata = append(newMetadata, requestIPHeaderKey, requestIP.String())
	}

	// Add the actor ID from the request so it is preserved if we need it
	actorID, isOK := ctx.Value(ActorIDContextKey).(string)
	if isOK {
		newMetadata = append(newMetadata, actorIDHeaderKey, actorID)
	}

	newCtx := metadata.AppendToOutgoingContext(ctx, newMetadata...)
	err := invoker(newCtx, method, req, reply, cc, opts...)

	return err
}
