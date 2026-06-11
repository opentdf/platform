package resourcemapping

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	resourcemapping "github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/policy/resolverutil"
)

// Authorization resolvers for the Resource Mapping service. The owning namespace
// is resolved from the mapping's group (group.namespace_id -> namespace name), not
// from the mapped attribute value. (When optional per-mapping namespaces land via
// the namespaced-resource-mappings work, prefer the mapping's own namespace field.)

func (s *ResourceMappingService) registerAuthzResolvers(reg *authz.ScopedResolverRegistry) {
	reg.MustRegister("CreateResourceMappingGroup", s.createResourceMappingGroupAuthzResolver)
	reg.MustRegister("GetResourceMappingGroup", s.getResourceMappingGroupAuthzResolver)
	reg.MustRegister("UpdateResourceMappingGroup", s.updateResourceMappingGroupAuthzResolver)
	reg.MustRegister("DeleteResourceMappingGroup", s.deleteResourceMappingGroupAuthzResolver)
	reg.MustRegister("ListResourceMappingGroups", s.listResourceMappingGroupsAuthzResolver)
	reg.MustRegister("CreateResourceMapping", s.createResourceMappingAuthzResolver)
	reg.MustRegister("GetResourceMapping", s.getResourceMappingAuthzResolver)
	reg.MustRegister("UpdateResourceMapping", s.updateResourceMappingAuthzResolver)
	reg.MustRegister("DeleteResourceMapping", s.deleteResourceMappingAuthzResolver)
	reg.MustRegister("ListResourceMappings", s.listResourceMappingsAuthzResolver)
	reg.MustRegister("ListResourceMappingsByGroupFqns", s.listResourceMappingsByGroupFqnsAuthzResolver)
}

// namespaceForGroupID resolves the namespace name owning a resource mapping group.
func (s *ResourceMappingService) namespaceForGroupID(ctx context.Context, groupID string) (string, error) {
	grp, err := s.dbClient.GetResourceMappingGroup(ctx, groupID)
	if err != nil {
		return "", fmt.Errorf("failed to resolve resource mapping group for authz: %w", err)
	}
	return resolverutil.NamespaceName(ctx, s.dbClient, grp.GetNamespaceId(), "")
}

// namespaceForMappingID resolves the namespace name owning a resource mapping.
func (s *ResourceMappingService) namespaceForMappingID(ctx context.Context, mappingID string) (string, error) {
	m, err := s.dbClient.GetResourceMapping(ctx, mappingID)
	if err != nil {
		return "", fmt.Errorf("failed to resolve resource mapping for authz: %w", err)
	}
	if nsID := m.GetGroup().GetNamespaceId(); nsID != "" {
		return resolverutil.NamespaceName(ctx, s.dbClient, nsID, "")
	}
	if groupID := m.GetGroup().GetId(); groupID != "" {
		return s.namespaceForGroupID(ctx, groupID)
	}
	return "", fmt.Errorf("resource mapping %s has no resolvable namespace", mappingID)
}

// --- resource mapping groups ---

func (s *ResourceMappingService) createResourceMappingGroupAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*resourcemapping.CreateResourceMappingGroupRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := resolverutil.NamespaceName(ctx, s.dbClient, msg.GetNamespaceId(), "")
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *ResourceMappingService) getResourceMappingGroupAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*resourcemapping.GetResourceMappingGroupRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForGroupID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *ResourceMappingService) updateResourceMappingGroupAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*resourcemapping.UpdateResourceMappingGroupRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForGroupID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *ResourceMappingService) deleteResourceMappingGroupAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*resourcemapping.DeleteResourceMappingGroupRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForGroupID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *ResourceMappingService) listResourceMappingGroupsAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*resourcemapping.ListResourceMappingGroupsRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return resolverutil.OptionalNamespaceFromIDFqn(ctx, s.dbClient, msg.GetNamespaceId(), "")
}

// --- resource mappings ---

func (s *ResourceMappingService) createResourceMappingAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*resourcemapping.CreateResourceMappingRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForGroupID(ctx, msg.GetGroupId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *ResourceMappingService) getResourceMappingAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*resourcemapping.GetResourceMappingRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForMappingID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *ResourceMappingService) updateResourceMappingAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*resourcemapping.UpdateResourceMappingRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForMappingID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *ResourceMappingService) deleteResourceMappingAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*resourcemapping.DeleteResourceMappingRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForMappingID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *ResourceMappingService) listResourceMappingsAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*resourcemapping.ListResourceMappingsRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	if groupID := msg.GetGroupId(); groupID != "" {
		name, err := s.namespaceForGroupID(ctx, groupID)
		if err != nil {
			return authz.NewResolverContext(), err
		}
		return resolverutil.Single(name), nil
	}
	return authz.NewResolverContext(), nil
}

func (s *ResourceMappingService) listResourceMappingsByGroupFqnsAuthzResolver(_ context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*resourcemapping.ListResourceMappingsByGroupFqnsRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	rc := authz.NewResolverContext()
	for _, fqn := range msg.GetFqns() {
		res := rc.NewResource()
		res.AddDimension("namespace", resolverutil.NamespaceNameFromFQN(fqn))
	}
	return rc, nil
}
