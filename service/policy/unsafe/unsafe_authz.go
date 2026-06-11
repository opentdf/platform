package unsafe

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/policy/resolverutil"
)

// Authorization resolvers for the Unsafe service. Unsafe mutations are bound to
// the owning namespace NAME so a namespace-scoped subject cannot perform unsafe
// operations outside its namespace. UnsafeDeleteKasKey targets a global KAS key
// and is intentionally left unregistered (fails closed for scoped subjects).

func (s *UnsafeService) registerAuthzResolvers(reg *authz.ScopedResolverRegistry) {
	reg.MustRegister("UnsafeUpdateNamespace", s.unsafeNamespaceAuthzResolver)
	reg.MustRegister("UnsafeReactivateNamespace", s.unsafeReactivateNamespaceAuthzResolver)
	reg.MustRegister("UnsafeDeleteNamespace", s.unsafeDeleteNamespaceAuthzResolver)
	reg.MustRegister("UnsafeUpdateAttribute", s.unsafeUpdateAttributeAuthzResolver)
	reg.MustRegister("UnsafeReactivateAttribute", s.unsafeReactivateAttributeAuthzResolver)
	reg.MustRegister("UnsafeDeleteAttribute", s.unsafeDeleteAttributeAuthzResolver)
	reg.MustRegister("UnsafeUpdateAttributeValue", s.unsafeUpdateAttributeValueAuthzResolver)
	reg.MustRegister("UnsafeReactivateAttributeValue", s.unsafeReactivateAttributeValueAuthzResolver)
	reg.MustRegister("UnsafeDeleteAttributeValue", s.unsafeDeleteAttributeValueAuthzResolver)
}

func (s *UnsafeService) namespaceByID(ctx context.Context, id string) (string, error) {
	n, err := s.dbClient.GetNamespace(ctx, id)
	if err != nil {
		return "", fmt.Errorf("failed to resolve namespace for authz: %w", err)
	}
	return n.GetName(), nil
}

func (s *UnsafeService) namespaceByAttributeID(ctx context.Context, id string) (string, error) {
	attr, err := s.dbClient.GetAttribute(ctx, id)
	if err != nil {
		return "", fmt.Errorf("failed to resolve attribute for authz: %w", err)
	}
	return attr.GetNamespace().GetName(), nil
}

func (s *UnsafeService) namespaceByValueID(ctx context.Context, id string) (string, error) {
	val, err := s.dbClient.GetAttributeValue(ctx, id)
	if err != nil {
		return "", fmt.Errorf("failed to resolve attribute value for authz: %w", err)
	}
	return val.GetAttribute().GetNamespace().GetName(), nil
}

func (s *UnsafeService) resolveNamespace(name string, err error) (authz.ResolverContext, error) {
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

// --- namespaces ---

func (s *UnsafeService) unsafeNamespaceAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*unsafe.UnsafeUpdateNamespaceRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return s.resolveNamespace(s.namespaceByID(ctx, msg.GetId()))
}

func (s *UnsafeService) unsafeReactivateNamespaceAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*unsafe.UnsafeReactivateNamespaceRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return s.resolveNamespace(s.namespaceByID(ctx, msg.GetId()))
}

func (s *UnsafeService) unsafeDeleteNamespaceAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*unsafe.UnsafeDeleteNamespaceRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return s.resolveNamespace(s.namespaceByID(ctx, msg.GetId()))
}

// --- attributes ---

func (s *UnsafeService) unsafeUpdateAttributeAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*unsafe.UnsafeUpdateAttributeRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return s.resolveNamespace(s.namespaceByAttributeID(ctx, msg.GetId()))
}

func (s *UnsafeService) unsafeReactivateAttributeAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*unsafe.UnsafeReactivateAttributeRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return s.resolveNamespace(s.namespaceByAttributeID(ctx, msg.GetId()))
}

func (s *UnsafeService) unsafeDeleteAttributeAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*unsafe.UnsafeDeleteAttributeRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return s.resolveNamespace(s.namespaceByAttributeID(ctx, msg.GetId()))
}

// --- attribute values ---

func (s *UnsafeService) unsafeUpdateAttributeValueAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*unsafe.UnsafeUpdateAttributeValueRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return s.resolveNamespace(s.namespaceByValueID(ctx, msg.GetId()))
}

func (s *UnsafeService) unsafeReactivateAttributeValueAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*unsafe.UnsafeReactivateAttributeValueRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return s.resolveNamespace(s.namespaceByValueID(ctx, msg.GetId()))
}

func (s *UnsafeService) unsafeDeleteAttributeValueAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*unsafe.UnsafeDeleteAttributeValueRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return s.resolveNamespace(s.namespaceByValueID(ctx, msg.GetId()))
}
