package audit

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/server/realip"
)

// ContextServerInterceptor adds request attribution without owning audit delivery.
func ContextServerInterceptor() connect.UnaryInterceptorFunc {
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
			data := ContextData{
				RequestID: requestID,
				ActorID:   auditData.ActorID,
			}
			ip := realip.FromContext(ctx)
			if ip != nil {
				data.RequestIP = ip.String()
				ctx = context.WithValue(ctx, sdkAudit.RequestIPContextKey, data.RequestIP)
			}
			userAgent := headers[http.CanonicalHeaderKey(sdkAudit.UserAgentHeaderKey.String())]
			if len(userAgent) > 0 {
				data.UserAgent = userAgent[0]
			}
			ctx = context.WithValue(ctx, sdkAudit.RequestIDContextKey, requestID)
			ctx = context.WithValue(ctx, contextKey{}, data)

			return next(ctx, req)
		})
	}

	return connect.UnaryInterceptorFunc(interceptor)
}
