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
// to the context of incoming requests. This metadata is used to log audit events
func UnaryServerInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// Generate and set a request ID on incoming requests
	requestUUID := uuid.New()
	ctx = context.WithValue(ctx, RequestIDContextKey, requestUUID)

	// Get metadata from the context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "missing metadata")
	}

	// Sets the user agent header on the context if it is present in the metadata
	userAgent := md[UserAgentHeaderKey]
	if len(userAgent) > 0 {
		ctx = context.WithValue(ctx, UserAgentContextKey, userAgent[0])
	}

	return handler(ctx, req)
}
