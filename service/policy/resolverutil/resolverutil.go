// Package resolverutil provides shared helpers for policy service authz resolvers.
//
// All policy authz resolvers expose the owning namespace as the "namespace"
// dimension using the namespace NAME (e.g. "virtru.com"), never its UUID or FQN,
// so a single scoped policy rule (namespace=virtru.com) matches regardless of how
// the caller identified the resource.
package resolverutil

import (
	"context"
	"fmt"
	"strings"

	"github.com/opentdf/platform/service/internal/auth/authz"
	policydb "github.com/opentdf/platform/service/policy/db"
)

// Single builds a ResolverContext with a single resource carrying the given
// namespace name as the "namespace" dimension.
func Single(namespace string) authz.ResolverContext {
	rc := authz.NewResolverContext()
	res := rc.NewResource()
	res.AddDimension("namespace", namespace)
	return rc
}

// OptionalNamespaceFromIDFqn is the standard resolver body for List* RPCs that
// accept an optional namespace filter (namespace_id / namespace_fqn). When neither
// is set it returns an empty context (no dimension), which fails closed for
// namespace-scoped subjects while leaving wildcard-granted roles unaffected.
func OptionalNamespaceFromIDFqn(ctx context.Context, db policydb.PolicyDBClient, id, fqn string) (authz.ResolverContext, error) {
	if id == "" && fqn == "" {
		return authz.NewResolverContext(), nil
	}
	name, err := NamespaceName(ctx, db, id, fqn)
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return Single(name), nil
}

// NamespaceNameFromFQN derives a namespace name (host) from any policy FQN.
// Works for a bare namespace FQN ("https://virtru.com" -> "virtru.com") and for
// nested resource FQNs ("https://virtru.com/obl/x" -> "virtru.com",
// "https://virtru.com/attr/a/value/v" -> "virtru.com").
func NamespaceNameFromFQN(fqn string) string {
	s := strings.TrimPrefix(fqn, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}

// NamespaceName resolves a namespace name from an optional id and/or fqn taken
// from a request (the NamespacedPolicy create-style fields). The FQN is preferred
// because it yields the name without a DB round-trip; otherwise the id is looked
// up via the policy DB client.
func NamespaceName(ctx context.Context, db policydb.PolicyDBClient, id, fqn string) (string, error) {
	if fqn != "" {
		return NamespaceNameFromFQN(fqn), nil
	}
	if id != "" {
		n, err := db.GetNamespace(ctx, id)
		if err != nil {
			return "", fmt.Errorf("failed to resolve namespace for authz: %w", err)
		}
		return n.GetName(), nil
	}
	return "", fmt.Errorf("namespace_id or namespace_fqn required for authorization")
}
