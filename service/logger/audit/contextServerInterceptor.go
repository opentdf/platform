package audit

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/server/realip"
)

// ContextServerInterceptor allows audit events to track request state.
// This is required for audit logging.
func ContextServerInterceptor(logger *slog.Logger) connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Get metadata from the context
			headers := req.Header()

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
					ActorID:   "",
				},
				events: make([]pendingEvent, 0),
			}
			requestIPFromMetadata := headers[http.CanonicalHeaderKey(sdkAudit.RequestIPHeaderKey.String())]
			if len(requestIPFromMetadata) > 0 {
				tx.RequestIP = requestIPFromMetadata[0]
			} else {
				// FIXME AFAICT the RealIPUnaryInterceptor is not being used
				// If we do use it, make sure it is added *before* this interceptor
				ip := realip.FromContext(ctx)
				if ip.String() != "" && ip.String() != "<nil>" {
					tx.RequestIP = ip.String()
				}
			}
			actorIDFromMetadata := headers[http.CanonicalHeaderKey(sdkAudit.ActorIDHeaderKey.String())]
			if len(actorIDFromMetadata) > 0 {
				tx.ActorID = actorIDFromMetadata[0]
			}
			userAgent := headers[http.CanonicalHeaderKey(sdkAudit.UserAgentHeaderKey.String())]
			if len(userAgent) > 0 {
				tx.UserAgent = userAgent[0]
			}
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
				tx.logClose(ctx, logger, true, nil)
			}()

			return next(ctx, req)
		})
	}

	return connect.UnaryInterceptorFunc(interceptor)
}
