package subjectmapping

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/policy/resolverutil"
)

// Authorization resolvers for the Subject Mapping service (subject mappings and
// subject condition sets). Each exposes the owning namespace NAME as the
// "namespace" dimension. MatchSubjectMappings and DeleteAllUnmappedSubjectConditionSets
// are intentionally unregistered: the former is a PEP query (granted via broad read
// roles) and the latter is a cross-namespace maintenance op that must fail closed
// for namespace-scoped subjects.

func (s *SubjectMappingService) registerAuthzResolvers(reg *authz.ScopedResolverRegistry) {
	reg.MustRegister("CreateSubjectMapping", s.createSubjectMappingAuthzResolver)
	reg.MustRegister("GetSubjectMapping", s.getSubjectMappingAuthzResolver)
	reg.MustRegister("UpdateSubjectMapping", s.updateSubjectMappingAuthzResolver)
	reg.MustRegister("DeleteSubjectMapping", s.deleteSubjectMappingAuthzResolver)
	reg.MustRegister("ListSubjectMappings", s.listSubjectMappingsAuthzResolver)
	reg.MustRegister("CreateSubjectConditionSet", s.createSubjectConditionSetAuthzResolver)
	reg.MustRegister("GetSubjectConditionSet", s.getSubjectConditionSetAuthzResolver)
	reg.MustRegister("UpdateSubjectConditionSet", s.updateSubjectConditionSetAuthzResolver)
	reg.MustRegister("DeleteSubjectConditionSet", s.deleteSubjectConditionSetAuthzResolver)
	reg.MustRegister("ListSubjectConditionSets", s.listSubjectConditionSetsAuthzResolver)
}

func (s *SubjectMappingService) namespaceForSubjectMapping(ctx context.Context, id string) (string, error) {
	m, err := s.dbClient.GetSubjectMapping(ctx, id)
	if err != nil {
		return "", fmt.Errorf("failed to resolve subject mapping for authz: %w", err)
	}
	return m.GetNamespace().GetName(), nil
}

func (s *SubjectMappingService) namespaceForSCS(ctx context.Context, id string) (string, error) {
	scs, err := s.dbClient.GetSubjectConditionSet(ctx, id)
	if err != nil {
		return "", fmt.Errorf("failed to resolve subject condition set for authz: %w", err)
	}
	return scs.GetNamespace().GetName(), nil
}

// --- subject mappings ---

func (s *SubjectMappingService) createSubjectMappingAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*sm.CreateSubjectMappingRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := resolverutil.NamespaceName(ctx, s.dbClient, msg.GetNamespaceId(), msg.GetNamespaceFqn())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *SubjectMappingService) getSubjectMappingAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*sm.GetSubjectMappingRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForSubjectMapping(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *SubjectMappingService) updateSubjectMappingAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*sm.UpdateSubjectMappingRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForSubjectMapping(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *SubjectMappingService) deleteSubjectMappingAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*sm.DeleteSubjectMappingRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForSubjectMapping(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *SubjectMappingService) listSubjectMappingsAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*sm.ListSubjectMappingsRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return resolverutil.OptionalNamespaceFromIDFqn(ctx, s.dbClient, msg.GetNamespaceId(), msg.GetNamespaceFqn())
}

// --- subject condition sets ---

func (s *SubjectMappingService) createSubjectConditionSetAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*sm.CreateSubjectConditionSetRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := resolverutil.NamespaceName(ctx, s.dbClient, msg.GetNamespaceId(), msg.GetNamespaceFqn())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *SubjectMappingService) getSubjectConditionSetAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*sm.GetSubjectConditionSetRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForSCS(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *SubjectMappingService) updateSubjectConditionSetAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*sm.UpdateSubjectConditionSetRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForSCS(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *SubjectMappingService) deleteSubjectConditionSetAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*sm.DeleteSubjectConditionSetRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForSCS(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (s *SubjectMappingService) listSubjectConditionSetsAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*sm.ListSubjectConditionSetsRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return resolverutil.OptionalNamespaceFromIDFqn(ctx, s.dbClient, msg.GetNamespaceId(), msg.GetNamespaceFqn())
}
