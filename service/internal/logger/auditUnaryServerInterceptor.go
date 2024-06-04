package logger

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	userAgentHeader     = "user-agent"
	userAgentContextKey = "user-agent"
	requestIdContextKey = "request-id"
)

// The audit unary server interceptor is a gRPC interceptor that adds metadata
// to the context of incoming requests. This metadata is used to log audit events
func AuditUnaryServerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// Generate and set a request ID on incoming requests
	requestUUID := uuid.New()
	ctx = context.WithValue(ctx, requestIdContextKey, requestUUID)

	// Get metadata from the context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}

	// Sets the user agent header on the context if it is present in the metadata
	userAgent := md[userAgentHeader]
	if len(userAgent) > 0 {
		ctx = context.WithValue(ctx, userAgentContextKey, userAgent[0])
	}

	return handler(ctx, req)
}
