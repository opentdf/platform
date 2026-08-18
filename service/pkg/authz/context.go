package authz

import "context"

type claimsContextKey struct{}

// RequestClaims contains configured authorization claims resolved for a request.
type RequestClaims struct {
	Subject  string
	Groups   []string
	ClientID string
}

// ContextWithClaims returns a child context carrying configured authorization
// claims resolved for a request.
func ContextWithClaims(ctx context.Context, claims RequestClaims) context.Context {
	claims.Groups = append([]string(nil), claims.Groups...)
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// ClaimsFromContext returns configured authorization claims resolved for a
// request, if present.
func ClaimsFromContext(ctx context.Context) (RequestClaims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(RequestClaims)
	if !ok {
		return RequestClaims{}, false
	}
	claims.Groups = append([]string(nil), claims.Groups...)
	return claims, true
}

// ContextWithClientID returns a child context carrying the request client ID
// resolved from configured authentication claims.
func ContextWithClientID(ctx context.Context, clientID string) context.Context {
	claims, _ := ClaimsFromContext(ctx)
	claims.ClientID = clientID
	return ContextWithClaims(ctx, claims)
}

// GroupsFromContext returns the request groups resolved from configured
// authorization claims, if present.
func GroupsFromContext(ctx context.Context) ([]string, bool) {
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		return nil, false
	}
	return claims.Groups, true
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
