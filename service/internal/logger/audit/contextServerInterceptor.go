package audit

import (
	"context"

	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The audit unary server interceptor is a gRPC interceptor that adds metadata
// to the context of incoming requests. This metadata is used to log audit
// audit events.
func ContextServerInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// Get metadata from the context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "missing metadata")
	}

	// Add request ID from existing header or create a new one
	var requestID uuid.UUID
	var err error
	requestIDFromMetadata := md[string(sdkAudit.RequestIDHeaderKey)]
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
	requestIPFromMetadata := md[string(sdkAudit.RequestIPHeaderKey)]
	if len(requestIPFromMetadata) > 0 {
		ctx = context.WithValue(ctx, sdkAudit.RequestIPContextKey, requestIPFromMetadata[0])
	}

	// Get the actor ID from the metadata header
	actorIDFromMetadata := md[string(sdkAudit.ActorIDHeaderKey)]
	if len(actorIDFromMetadata) > 0 {
		ctx = context.WithValue(ctx, sdkAudit.ActorIDContextKey, actorIDFromMetadata[0])
	}

	// Sets the user agent header on the context if it is present in the metadata
	userAgent := md[string(sdkAudit.UserAgentHeaderKey)]
	if len(userAgent) > 0 {
		ctx = context.WithValue(ctx, sdkAudit.UserAgentContextKey, userAgent[0])
	}

	return handler(ctx, req)
}
