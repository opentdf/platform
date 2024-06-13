package audit

import (
	"context"
	"log/slog"

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
		slog.Info("BACON(ServerInterceptor)", "method", i.FullMethod, "X-Request-ID", requestID)
		if err != nil {
			requestID = uuid.New()
		}
	} else {
		slog.Info("BACON(ServerInterceptor)", "method", i.FullMethod, "X-Request-ID", "NONE")
		requestID = uuid.New()
	}
	slog.Info("BACON(ServerInterceptor)", "method", i.FullMethod, "Set-ReqIDCxt", requestID)
	ctx = context.WithValue(ctx, RequestIDContextKey, requestID)

	// Sets the user agent header on the context if it is present in the metadata
	userAgent := md[string(UserAgentHeaderKey)]
	if len(userAgent) > 0 {
		ctx = context.WithValue(ctx, UserAgentContextKey, userAgent[0])
	}

	return handler(ctx, req)
}
