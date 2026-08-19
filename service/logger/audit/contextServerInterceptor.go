package audit

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/server/realip"
)

// ContextServerInterceptor snapshots request attribution for audit recording.
func ContextServerInterceptor(logger *Logger) connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Get metadata from the context
			headers := req.Header()
			auditData := GetAuditDataFromContext(ctx)

			// Add request ID from existing header or create a new one
			var requestID uuid.UUID
			var err error

			requestIDFromMetadata := headers[http.CanonicalHeaderKey(sdkAudit.RequestIDHeaderKey.String())]
			if len(requestIDFromMetadata) > 0 {
				requestID, err = uuid.Parse(requestIDFromMetadata[0])
				if err != nil {
					requestID = uuid.New()
				}
			} else {
				requestID = uuid.New()
			}
			auditCtx := auditContext{
				data: ContextData{
					RequestID: requestID,
					UserAgent: "",
					RequestIP: "",
					ActorID:   auditData.ActorID,
				},
				logger: logger,
			}
			requestIPFromMetadata := headers[http.CanonicalHeaderKey(sdkAudit.RequestIPHeaderKey.String())]
			if len(requestIPFromMetadata) > 0 {
				auditCtx.data.RequestIP = requestIPFromMetadata[0]
			} else {
				// FIXME AFAICT the RealIPUnaryInterceptor is not being used
				// If we do use it, make sure it is added *before* this interceptor
				ip := realip.FromContext(ctx)
				if ip.String() != "" && ip.String() != "<nil>" {
					auditCtx.data.RequestIP = ip.String()
				}
			}
			userAgent := headers[http.CanonicalHeaderKey(sdkAudit.UserAgentHeaderKey.String())]
			if len(userAgent) > 0 {
				auditCtx.data.UserAgent = userAgent[0]
			}
			ctx = context.WithValue(ctx, contextKey{}, auditCtx)

			return next(ctx, req)
		})
	}

	return connect.UnaryInterceptorFunc(interceptor)
}
