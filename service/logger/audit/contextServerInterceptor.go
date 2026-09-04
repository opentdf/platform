package audit

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/server/realip"
)

// ContextServerInterceptor allows audit events to track request state.
// This is required for audit logging.
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
			tx := auditTransaction{
				ContextData: ContextData{
					RequestID: requestID,
					UserAgent: "",
					RequestIP: "",
					ActorID:   auditData.ActorID,
				},
				events: make([]pendingEvent, 0),
			}
			ip := realip.FromContext(ctx)
			if ip != nil {
				tx.RequestIP = ip.String()
				ctx = context.WithValue(ctx, sdkAudit.RequestIPContextKey, tx.RequestIP)
			}
			userAgent := headers[http.CanonicalHeaderKey(sdkAudit.UserAgentHeaderKey.String())]
			if len(userAgent) > 0 {
				tx.UserAgent = userAgent[0]
			}
			ctx = context.WithValue(ctx, sdkAudit.RequestIDContextKey, requestID)
			ctx = context.WithValue(ctx, contextKey{}, &tx)

			defer func() {
				if r := recover(); r != nil {
					if err, ok := r.(error); ok {
						tx.logClose(ctx, logger, false, err)
					} else {
						tx.logClose(ctx, logger, false, nil)
					}
					panic(r)
				}
			}()

			response, nextErr := next(ctx, req)
			tx.logClose(ctx, logger, nextErr == nil, nextErr)
			return response, nextErr
		})
	}

	return connect.UnaryInterceptorFunc(interceptor)
}
