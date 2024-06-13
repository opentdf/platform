package audit

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	requestIDContextKey = "request-id"
	requestIDHeaderKey  = "x-request-id"
)

// RequestIDClientInterceptor is a client side gRPC interceptor that adds an
// X-Request-ID header to outgoing requests. If a request ID is already present
// in the context, it will be used. Otherwise, a new request ID will be generated.
func RequestIDClientInterceptor(
	ctx context.Context,
	method string,
	req, reply any,
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	newMetadata := make([]string, 0)

	// Get any existing request ID from context
	requestID, ok := ctx.Value(requestIDContextKey).(uuid.UUID)
	if !ok || requestID == uuid.Nil {
		requestID = uuid.New()
	}
	newMetadata = append(newMetadata, requestIDHeaderKey, requestID.String())

	slog.Info("BACON Request Info", "reqID", requestID.String())
	newCtx := metadata.AppendToOutgoingContext(ctx, newMetadata...)

	err := invoker(newCtx, method, req, reply, cc, opts...)

	return err
}
