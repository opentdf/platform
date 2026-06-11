package namespaces

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/internal/auth/authz"
)

// Authorization resolvers for the Namespaces service.
//
// Each resolver extracts the owning policy namespace NAME and exposes it as the
// "namespace" dimension for fine-grained (v2) authorization. The namespace name
// (not its ID or FQN) is used consistently across all policy services so a single
// scoped policy rule (e.g. namespace=virtru.com) matches regardless of how the
// caller identified the resource.

// registerAuthzResolvers wires the per-RPC resolvers into the scoped registry.
// Called from RegisterFunc when a registry is available.
func (ns *NamespacesService) registerAuthzResolvers(reg *authz.ScopedResolverRegistry) {
	reg.MustRegister("CreateNamespace", ns.createNamespaceAuthzResolver)
	reg.MustRegister("GetNamespace", ns.getNamespaceAuthzResolver)
	reg.MustRegister("UpdateNamespace", ns.updateNamespaceAuthzResolver)
	reg.MustRegister("DeactivateNamespace", ns.deactivateNamespaceAuthzResolver)
	reg.MustRegister("ListNamespaces", ns.listNamespacesAuthzResolver)
}

// resolveNamespaceNameByID looks up a namespace by ID and returns its name.
func (ns *NamespacesService) resolveNamespaceNameByID(ctx context.Context, id string) (string, error) {
	n, err := ns.dbClient.GetNamespace(ctx, id)
	if err != nil {
		return "", fmt.Errorf("failed to resolve namespace for authz: %w", err)
	}
	return n.GetName(), nil
}

// createNamespaceAuthzResolver: the namespace name is the resource being created.
func (ns *NamespacesService) createNamespaceAuthzResolver(_ context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*namespaces.CreateNamespaceRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}
	res := resolverCtx.NewResource()
	res.AddDimension("namespace", msg.GetName())
	return resolverCtx, nil
}

// getNamespaceAuthzResolver: resolve the namespace by id/identifier.
func (ns *NamespacesService) getNamespaceAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*namespaces.GetNamespaceRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}

	var identifier any
	if msg.GetId() != "" { //nolint:staticcheck // Id can still be used until removed
		identifier = msg.GetId() //nolint:staticcheck // Id can still be used until removed
	} else {
		identifier = msg.GetIdentifier()
	}

	n, err := ns.dbClient.GetNamespace(ctx, identifier)
	if err != nil {
		return resolverCtx, fmt.Errorf("failed to resolve namespace for authz: %w", err)
	}
	res := resolverCtx.NewResource()
	res.AddDimension("namespace", n.GetName())
	return resolverCtx, nil
}

// updateNamespaceAuthzResolver: resolve the namespace by id.
func (ns *NamespacesService) updateNamespaceAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*namespaces.UpdateNamespaceRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := ns.resolveNamespaceNameByID(ctx, msg.GetId())
	if err != nil {
		return resolverCtx, err
	}
	res := resolverCtx.NewResource()
	res.AddDimension("namespace", name)
	return resolverCtx, nil
}

// deactivateNamespaceAuthzResolver: resolve the namespace by id.
func (ns *NamespacesService) deactivateNamespaceAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	msg, ok := req.Any().(*namespaces.DeactivateNamespaceRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := ns.resolveNamespaceNameByID(ctx, msg.GetId())
	if err != nil {
		return resolverCtx, err
	}
	res := resolverCtx.NewResource()
	res.AddDimension("namespace", name)
	return resolverCtx, nil
}

// listNamespacesAuthzResolver: ListNamespaces has no namespace filter, so no
// dimension is added (empty context => "*" dims). A namespace-scoped subject is
// therefore not authorized to list all namespaces (fail-closed); broad read
// access remains available to roles granted a wildcard rule.
func (ns *NamespacesService) listNamespacesAuthzResolver(_ context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()
	if _, ok := req.Any().(*namespaces.ListNamespacesRequest); !ok {
		return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return resolverCtx, nil
}
