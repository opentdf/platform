package audit

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The audit unary server interceptor is a gRPC interceptor that adds metadata
// to the context of incoming requests. This metadata is used to log audit
// audit events.
func UnaryServerInterceptor(ctx context.Context, req any, i *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// Get metadata from the context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "missing metadata")
	}

	// Add request ID from existing header or create a new one
	var requestID uuid.UUID
	var err error
	requestIDFromMetadata := md[string(RequestIDHeaderKey)]
	if len(requestIDFromMetadata) > 0 {
		requestID, err = uuid.Parse(requestIDFromMetadata[0])
		if err != nil {
			requestID = uuid.New()
		}
	} else {
		requestID = uuid.New()
	}
	ctx = context.WithValue(ctx, RequestIDContextKey, requestID)

	// Sets the user agent header on the context if it is present in the metadata
	userAgent := md[string(UserAgentHeaderKey)]
	if len(userAgent) > 0 {
		ctx = context.WithValue(ctx, UserAgentContextKey, userAgent[0])
	}

	return handler(ctx, req)
}

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
	requestID, ok := ctx.Value(RequestIDContextKey).(uuid.UUID)
	if !ok || requestID == uuid.Nil {
		requestID = uuid.New()
	}
	newMetadata = append(newMetadata, string(RequestIDHeaderKey), requestID.String())

	newCtx := metadata.AppendToOutgoingContext(ctx, newMetadata...)

	err := invoker(newCtx, method, req, reply, cc, opts...)

	return err
}
