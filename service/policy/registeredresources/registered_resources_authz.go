package registeredresources

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	rr "github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/policy/resolverutil"
)

// Authorization resolvers for the Registered Resources service. Each exposes the
// owning namespace NAME as the "namespace" dimension. GetRegisteredResourceValuesByFQNs
// is left unregistered (a multi-namespace read, available via broad read roles).

func (s *RegisteredResourcesService) registerAuthzResolvers(reg *authz.ScopedResolverRegistry) {
	reg.MustRegister("CreateRegisteredResource", s.createRegisteredResourceAuthzResolver)
	reg.MustRegister("GetRegisteredResource", s.getRegisteredResourceAuthzResolver)
	reg.MustRegister("UpdateRegisteredResource", s.updateRegisteredResourceAuthzResolver)
	reg.MustRegister("DeleteRegisteredResource", s.deleteRegisteredResourceAuthzResolver)
	reg.MustRegister("ListRegisteredResources", s.listRegisteredResourcesAuthzResolver)
	reg.MustRegister("CreateRegisteredResourceValue", s.createRegisteredResourceValueAuthzResolver)
	reg.MustRegister("GetRegisteredResourceValue", s.getRegisteredResourceValueAuthzResolver)
	reg.MustRegister("UpdateRegisteredResourceValue", s.updateRegisteredResourceValueAuthzResolver)
	reg.MustRegister("DeleteRegisteredResourceValue", s.deleteRegisteredResourceValueAuthzResolver)
	reg.MustRegister("ListRegisteredResourceValues", s.listRegisteredResourceValuesAuthzResolver)
}

func (s *RegisteredResourcesService) namespaceForResourceID(ctx context.Context, id string) (string, error) {
	res, err := s.dbClient.GetRegisteredResource(ctx, &rr.GetRegisteredResourceRequest{
		Identifier: &rr.GetRegisteredResourceRequest_Id{Id: id},
	})
	if err != nil {
		return "", fmt.Errorf("failed to resolve registered resource for authz: %w", err)
	}
	return res.GetNamespace().GetName(), nil
}

func (s *RegisteredResourcesService) namespaceForValueID(ctx context.Context, id string) (string, error) {
	val, err := s.dbClient.GetRegisteredResourceValue(ctx, &rr.GetRegisteredResourceValueRequest{
		Identifier: &rr.GetRegisteredResourceValueRequest_Id{Id: id},
	})
	if err != nil {
		return "", fmt.Errorf("failed to resolve registered resource value for authz: %w", err)
	}
	return val.GetResource().GetNamespace().GetName(), nil
}

// --- registered resources ---

func (s *RegisteredResourcesService) createRegisteredResourceAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*rr.CreateRegisteredResourceRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := resolverutil.NamespaceName(ctx, s.dbClient, msg.GetNamespaceId(), msg.GetNamespaceFqn())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *RegisteredResourcesService) getRegisteredResourceAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*rr.GetRegisteredResourceRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	if fqn := msg.GetNamespaceFqn(); fqn != "" {
		return resolverutil.Single(resolverutil.NamespaceNameFromFQN(fqn)), nil
	}
	res, err := s.dbClient.GetRegisteredResource(ctx, msg)
	if err != nil {
		return authz.NewResolverContext(), fmt.Errorf("failed to resolve registered resource for authz: %w", err)
	}
	return resolverutil.Single(res.GetNamespace().GetName()), nil
}

func (s *RegisteredResourcesService) updateRegisteredResourceAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*rr.UpdateRegisteredResourceRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForResourceID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *RegisteredResourcesService) deleteRegisteredResourceAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*rr.DeleteRegisteredResourceRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForResourceID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *RegisteredResourcesService) listRegisteredResourcesAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*rr.ListRegisteredResourcesRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return resolverutil.OptionalNamespaceFromIDFqn(ctx, s.dbClient, msg.GetNamespaceId(), msg.GetNamespaceFqn())
}

// --- registered resource values ---

func (s *RegisteredResourcesService) createRegisteredResourceValueAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*rr.CreateRegisteredResourceValueRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForResourceID(ctx, msg.GetResourceId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *RegisteredResourcesService) getRegisteredResourceValueAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*rr.GetRegisteredResourceValueRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	val, err := s.dbClient.GetRegisteredResourceValue(ctx, msg)
	if err != nil {
		return authz.NewResolverContext(), fmt.Errorf("failed to resolve registered resource value for authz: %w", err)
	}
	return resolverutil.Single(val.GetResource().GetNamespace().GetName()), nil
}

func (s *RegisteredResourcesService) updateRegisteredResourceValueAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*rr.UpdateRegisteredResourceValueRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForValueID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *RegisteredResourcesService) deleteRegisteredResourceValueAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*rr.DeleteRegisteredResourceValueRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForValueID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *RegisteredResourcesService) listRegisteredResourceValuesAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*rr.ListRegisteredResourceValuesRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	if resourceID := msg.GetResourceId(); resourceID != "" {
		name, err := s.namespaceForResourceID(ctx, resourceID)
		if err != nil {
			return authz.NewResolverContext(), err
		}
		return resolverutil.Single(name), nil
	}
	return authz.NewResolverContext(), nil
}
