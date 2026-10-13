package actions

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/service/internal/connectv2/policy/actions/actionsconnectv2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"

	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

// Re-exported action names for consumers of ActionService protos
const (
	// Stored name of the standard 'create' action
	ActionNameCreate = string(policydb.ActionCreate)
	// Stored name of the standard 'read' action
	ActionNameRead = string(policydb.ActionRead)
	// Stored name of the standard 'update' action
	ActionNameUpdate = string(policydb.ActionUpdate)
	// Stored name of the standard 'delete' action
	ActionNameDelete = string(policydb.ActionDelete)
)

type ActionService struct {
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

var errNamespacedPolicyNamespaceRequired = errors.New("either namespace_id or namespace_fqn must be provided")

func OnConfigUpdate(actionsSvc *ActionService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		actionsSvc.config = sharedCfg
		actionsSvc.dbClient = policydb.NewClient(actionsSvc.dbClient.Client, actionsSvc.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))

		actionsSvc.logger.Info("actions service config reloaded")

		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[actionsconnectv2.ActionServiceHandler] {
	actionsSvc := new(ActionService)
	onUpdateConfigHook := OnConfigUpdate(actionsSvc)

	return &serviceregistry.Service[actionsconnectv2.ActionServiceHandler]{
		Close: actionsSvc.Close,
		ServiceOptions: serviceregistry.ServiceOptions[actionsconnectv2.ActionServiceHandler]{
			Namespace:              ns,
			DB:                     dbRegister,
			ServiceDesc:            &actions.ActionService_ServiceDesc,
			ConnectRPCRegisterFunc: actionsconnectv2.RegisterActionServiceHandler,
			OnConfigUpdate:         onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (actionsconnectv2.ActionServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting actions service policy config", slog.String("error", err.Error()))
					panic(err)
				}

				actionsSvc.logger = logger
				actionsSvc.config = cfg
				actionsSvc.dbClient = policydb.NewClient(srp.DBClient, logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))
				return actionsSvc, nil
			},
		},
	}
}

// Close gracefully shuts down the actions service, closing the database client.
func (a *ActionService) Close() {
	a.logger.Info("gracefully shutting down actions service")
	a.dbClient.Close()
}

func (a *ActionService) GetAction(ctx context.Context, req *actions.GetActionRequest) (*actions.GetActionResponse, error) {
	rsp := &actions.GetActionResponse{}

	a.logger.DebugContext(ctx, "getting action", slog.Any("identifier", req.GetIdentifier()))

	action, err := a.dbClient.GetAction(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, a.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("identifier", req.GetIdentifier()))
	}
	rsp.Action = action

	return rsp, nil
}

func (a *ActionService) ListActions(ctx context.Context, req *actions.ListActionsRequest) (*actions.ListActionsResponse, error) {
	a.logger.DebugContext(ctx, "listing actions")
	rsp, err := a.dbClient.ListActions(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, a.logger, err, db.ErrTextListRetrievalFailed)
	}
	a.logger.DebugContext(ctx, "listed actions")
	return rsp, nil
}

func (a *ActionService) CreateAction(ctx context.Context, req *actions.CreateActionRequest) (*actions.CreateActionResponse, error) {
	a.logger.DebugContext(ctx, "creating action", slog.String("name", req.GetName()))
	if a.config.NamespacedPolicy && req.GetNamespaceId() == "" && req.GetNamespaceFqn() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errNamespacedPolicyNamespaceRequired.Error()).WithCause(errNamespacedPolicyNamespaceRequired)
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeAction,
	}
	rsp := &actions.CreateActionResponse{}

	err := a.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		action, err := txClient.CreateAction(ctx, req)
		if err != nil {
			return err
		}

		auditParams.ObjectID = action.GetId()
		auditParams.Original = action

		rsp.Action = action
		return nil
	})
	if err != nil {
		a.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, a.logger, err, db.ErrTextCreationFailed, slog.String("action", req.String()))
	}
	a.logger.LogPolicyCRUDSuccess(ctx, auditParams)
	return rsp, nil
}

func (a *ActionService) UpdateAction(ctx context.Context, req *actions.UpdateActionRequest) (*actions.UpdateActionResponse, error) {
	actionID := req.GetId()
	a.logger.DebugContext(ctx, "updating action", slog.String("id", actionID))
	rsp := &actions.UpdateActionResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAction,
		ObjectID:   actionID,
	}

	err := a.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetAction(ctx, &actions.GetActionRequest{
			Identifier: &actions.GetActionRequest_Id{
				Id: actionID,
			},
		})
		if err != nil {
			return err
		}

		updated, err := txClient.UpdateAction(ctx, req)
		if err != nil {
			return err
		}

		auditParams.Original = original
		auditParams.Updated = updated

		rsp.Action = updated
		return nil
	})
	if err != nil {
		a.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, a.logger, err, db.ErrTextUpdateFailed, slog.String("action", req.String()))
	}
	a.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}

func (a *ActionService) DeleteAction(ctx context.Context, req *actions.DeleteActionRequest) (*actions.DeleteActionResponse, error) {
	rsp := &actions.DeleteActionResponse{}
	actionID := req.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeAction,
		ObjectID:   actionID,
	}
	a.logger.DebugContext(ctx, "deleting action", slog.String("id", actionID))

	deleted, err := a.dbClient.DeleteAction(ctx, req)
	if err != nil {
		a.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, a.logger, err, db.ErrTextDeletionFailed, slog.String("action", req.String()))
	}

	a.logger.LogPolicyCRUDSuccess(ctx, auditParams)
	rsp.Action = deleted

	return rsp, nil
}
