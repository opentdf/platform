package authz

import "context"

type rolesContextKey struct{}

// RequestClaims contains configured authorization claims resolved for a request.
type RequestClaims struct {
	Subject  string
	Roles    []string
	ClientID string
}

// ContextWithClaims returns a child context carrying configured authorization
// claims resolved for a request.
func ContextWithClaims(ctx context.Context, claims RequestClaims) context.Context {
	claims.Roles = append([]string(nil), claims.Roles...)
	return context.WithValue(ctx, rolesContextKey{}, claims)
}

// ClaimsFromContext returns configured authorization claims resolved for a
// request, if present.
func ClaimsFromContext(ctx context.Context) (RequestClaims, bool) {
	claims, ok := ctx.Value(rolesContextKey{}).(RequestClaims)
	if !ok {
		return RequestClaims{}, false
	}
	claims.Roles = append([]string(nil), claims.Roles...)
	return claims, true
}

// ContextWithRoles returns a child context carrying the request roles resolved
// by the authorization role provider.
func ContextWithRoles(ctx context.Context, roles []string) context.Context {
	claims, _ := ClaimsFromContext(ctx)
	claims.Roles = roles
	return ContextWithClaims(ctx, claims)
}

// ContextWithClientID returns a child context carrying the request client ID
// resolved from configured authentication claims.
func ContextWithClientID(ctx context.Context, clientID string) context.Context {
	claims, _ := ClaimsFromContext(ctx)
	claims.ClientID = clientID
	return ContextWithClaims(ctx, claims)
}

// RolesFromContext returns the request roles resolved by the authorization
// role provider, if present.
func RolesFromContext(ctx context.Context) ([]string, bool) {
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		return nil, false
	}
	return claims.Roles, true
}

// SubjectFromContext returns the configured subject claim resolved for the
// request, if present.
func SubjectFromContext(ctx context.Context) (string, bool) {
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		return "", false
	}
	return claims.Subject, true
}

// ClientIDFromContext returns the configured client ID claim resolved for the
// request, if present.
func ClientIDFromContext(ctx context.Context) (string, bool) {
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		return "", false
	}
	return claims.ClientID, true
}
