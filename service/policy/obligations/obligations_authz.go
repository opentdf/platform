package obligations

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/policy/resolverutil"
)

// Authorization resolvers for the Obligations service.
//
// Every resolver exposes the owning policy namespace NAME as the "namespace"
// dimension (see resolverutil for why the name, not id/fqn, is used).

func (s *Service) registerAuthzResolvers(reg *authz.ScopedResolverRegistry) {
	reg.MustRegister("CreateObligation", s.createObligationAuthzResolver)
	reg.MustRegister("GetObligation", s.getObligationAuthzResolver)
	reg.MustRegister("ListObligations", s.listObligationsAuthzResolver)
	reg.MustRegister("UpdateObligation", s.updateObligationAuthzResolver)
	reg.MustRegister("DeleteObligation", s.deleteObligationAuthzResolver)
	reg.MustRegister("CreateObligationValue", s.createObligationValueAuthzResolver)
	reg.MustRegister("GetObligationValue", s.getObligationValueAuthzResolver)
	reg.MustRegister("UpdateObligationValue", s.updateObligationValueAuthzResolver)
	reg.MustRegister("DeleteObligationValue", s.deleteObligationValueAuthzResolver)
	reg.MustRegister("GetObligationTrigger", s.getObligationTriggerAuthzResolver)
	reg.MustRegister("AddObligationTrigger", s.addObligationTriggerAuthzResolver)
	reg.MustRegister("RemoveObligationTrigger", s.removeObligationTriggerAuthzResolver)
	reg.MustRegister("ListObligationTriggers", s.listObligationTriggersAuthzResolver)
}

// --- helpers ---

func single(namespace string) authz.ResolverContext {
	rc := authz.NewResolverContext()
	res := rc.NewResource()
	res.AddDimension("namespace", namespace)
	return rc
}

// namespaceForObligation resolves the owning namespace name for an obligation
// identified by id and/or fqn.
func (s *Service) namespaceForObligation(ctx context.Context, id, fqn string) (string, error) {
	if fqn != "" {
		return resolverutil.NamespaceNameFromFQN(fqn), nil
	}
	obl, err := s.dbClient.GetObligation(ctx, &obligations.GetObligationRequest{Id: id})
	if err != nil {
		return "", fmt.Errorf("failed to resolve obligation for authz: %w", err)
	}
	return obl.GetNamespace().GetName(), nil
}

// namespaceForObligationValue resolves the owning namespace name for an obligation
// value identified by id and/or fqn.
func (s *Service) namespaceForObligationValue(ctx context.Context, id, fqn string) (string, error) {
	if fqn != "" {
		return resolverutil.NamespaceNameFromFQN(fqn), nil
	}
	val, err := s.dbClient.GetObligationValue(ctx, &obligations.GetObligationValueRequest{Id: id})
	if err != nil {
		return "", fmt.Errorf("failed to resolve obligation value for authz: %w", err)
	}
	return val.GetObligation().GetNamespace().GetName(), nil
}

// --- obligation definition resolvers ---

func (s *Service) createObligationAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.CreateObligationRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := resolverutil.NamespaceName(ctx, s.dbClient, msg.GetNamespaceId(), msg.GetNamespaceFqn())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return single(name), nil
}

func (s *Service) getObligationAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.GetObligationRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForObligation(ctx, msg.GetId(), msg.GetFqn())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return single(name), nil
}

func (s *Service) listObligationsAuthzResolver(_ context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.ListObligationsRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	if id, fqn := msg.GetNamespaceId(), msg.GetNamespaceFqn(); id != "" || fqn != "" {
		if fqn != "" {
			return single(resolverutil.NamespaceNameFromFQN(fqn)), nil
		}
		name, err := resolverutil.NamespaceName(context.Background(), s.dbClient, id, "")
		if err != nil {
			return authz.NewResolverContext(), err
		}
		return single(name), nil
	}
	return authz.NewResolverContext(), nil
}

func (s *Service) updateObligationAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.UpdateObligationRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForObligation(ctx, msg.GetId(), "")
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return single(name), nil
}

func (s *Service) deleteObligationAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.DeleteObligationRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForObligation(ctx, msg.GetId(), msg.GetFqn())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return single(name), nil
}

// --- obligation value resolvers ---

func (s *Service) createObligationValueAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.CreateObligationValueRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForObligation(ctx, msg.GetObligationId(), msg.GetObligationFqn())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return single(name), nil
}

func (s *Service) getObligationValueAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.GetObligationValueRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForObligationValue(ctx, msg.GetId(), msg.GetFqn())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return single(name), nil
}

func (s *Service) updateObligationValueAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.UpdateObligationValueRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForObligationValue(ctx, msg.GetId(), "")
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return single(name), nil
}

func (s *Service) deleteObligationValueAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.DeleteObligationValueRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := s.namespaceForObligationValue(ctx, msg.GetId(), msg.GetFqn())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return single(name), nil
}

// --- obligation trigger resolvers ---

func (s *Service) getObligationTriggerAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.GetObligationTriggerRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	trigger, err := s.dbClient.GetObligationTrigger(ctx, &obligations.GetObligationTriggerRequest{Id: msg.GetId()})
	if err != nil {
		return authz.NewResolverContext(), fmt.Errorf("failed to resolve obligation trigger for authz: %w", err)
	}
	return single(trigger.GetObligationValue().GetObligation().GetNamespace().GetName()), nil
}

func (s *Service) addObligationTriggerAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.AddObligationTriggerRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	ov := msg.GetObligationValue()
	name, err := s.namespaceForObligationValue(ctx, ov.GetId(), ov.GetFqn())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return single(name), nil
}

func (s *Service) removeObligationTriggerAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.RemoveObligationTriggerRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	trigger, err := s.dbClient.GetObligationTrigger(ctx, &obligations.GetObligationTriggerRequest{Id: msg.GetId()})
	if err != nil {
		return authz.NewResolverContext(), fmt.Errorf("failed to resolve obligation trigger for authz: %w", err)
	}
	return single(trigger.GetObligationValue().GetObligation().GetNamespace().GetName()), nil
}

func (s *Service) listObligationTriggersAuthzResolver(_ context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*obligations.ListObligationTriggersRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	if id, fqn := msg.GetNamespaceId(), msg.GetNamespaceFqn(); id != "" || fqn != "" {
		if fqn != "" {
			return single(resolverutil.NamespaceNameFromFQN(fqn)), nil
		}
		name, err := resolverutil.NamespaceName(context.Background(), s.dbClient, id, "")
		if err != nil {
			return authz.NewResolverContext(), err
		}
		return single(name), nil
	}
	return authz.NewResolverContext(), nil
}
