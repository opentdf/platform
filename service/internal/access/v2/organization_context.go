package access

import (
	"context"

	"connectrpc.com/connect"
)

const OrganizationIDHeader = "X-Virtru-Organization-Id"

type organizationIDContextKey struct{}

// WithOrganizationID preserves an optional organization filter across the
// authorization-to-ERS boundary. An absent header intentionally leaves the
// context unchanged for backward-compatible cross-organization resolution.
func WithOrganizationID(ctx context.Context, organizationID string) context.Context {
	if organizationID == "" {
		return ctx
	}
	return context.WithValue(ctx, organizationIDContextKey{}, organizationID)
}

// OrganizationIDFromContext returns the optional organization filter.
func OrganizationIDFromContext(ctx context.Context) (string, bool) {
	organizationID, ok := ctx.Value(organizationIDContextKey{}).(string)
	return organizationID, ok && organizationID != ""
}

// NewOrganizationIDClientInterceptor forwards the optional organization
// filter on internal SDK requests. It remains separate from authentication.
func NewOrganizationIDClientInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if organizationID, ok := OrganizationIDFromContext(ctx); ok {
				req.Header().Set(OrganizationIDHeader, organizationID)
			}
			return next(ctx, req)
		}
	}
}
