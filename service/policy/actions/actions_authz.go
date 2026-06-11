package actions

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/policy/resolverutil"
)

// Authorization resolvers for the Actions service. Each exposes the owning
// namespace NAME as the "namespace" dimension.

func (a *ActionService) registerAuthzResolvers(reg *authz.ScopedResolverRegistry) {
	reg.MustRegister("CreateAction", a.createActionAuthzResolver)
	reg.MustRegister("GetAction", a.getActionAuthzResolver)
	reg.MustRegister("UpdateAction", a.updateActionAuthzResolver)
	reg.MustRegister("DeleteAction", a.deleteActionAuthzResolver)
	reg.MustRegister("ListActions", a.listActionsAuthzResolver)
}

func (a *ActionService) namespaceForActionID(ctx context.Context, id string) (string, error) {
	act, err := a.dbClient.GetAction(ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{Id: id},
	})
	if err != nil {
		return "", fmt.Errorf("failed to resolve action for authz: %w", err)
	}
	return act.GetNamespace().GetName(), nil
}

func (a *ActionService) createActionAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*actions.CreateActionRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := resolverutil.NamespaceName(ctx, a.dbClient, msg.GetNamespaceId(), msg.GetNamespaceFqn())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (a *ActionService) getActionAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*actions.GetActionRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	// Prefer the namespace carried directly on the request when present.
	if fqn := msg.GetNamespaceFqn(); fqn != "" {
		return resolverutil.Single(resolverutil.NamespaceNameFromFQN(fqn)), nil
	}
	act, err := a.dbClient.GetAction(ctx, msg)
	if err != nil {
		return authz.NewResolverContext(), fmt.Errorf("failed to resolve action for authz: %w", err)
	}
	return resolverutil.Single(act.GetNamespace().GetName()), nil
}

func (a *ActionService) updateActionAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*actions.UpdateActionRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := a.namespaceForActionID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (a *ActionService) deleteActionAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*actions.DeleteActionRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	name, err := a.namespaceForActionID(ctx, msg.GetId())
	if err != nil {
		return authz.NewResolverContext(), err
	}
	return resolverutil.Single(name), nil
}

func (a *ActionService) listActionsAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	msg, ok := req.Any().(*actions.ListActionsRequest)
	if !ok {
		return authz.NewResolverContext(), fmt.Errorf("unexpected request type: %T", req.Any())
	}
	return resolverutil.OptionalNamespaceFromIDFqn(ctx, a.dbClient, msg.GetNamespaceId(), msg.GetNamespaceFqn())
}
