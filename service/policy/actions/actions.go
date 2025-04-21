package actions

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/actions/actionsconnect"
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

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[actionsconnect.ActionServiceHandler] {
	actionsSvc := new(ActionService)
	onUpdateConfigHook := OnConfigUpdate(actionsSvc)

	return &serviceregistry.Service[actionsconnect.ActionServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[actionsconnect.ActionServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &actions.ActionService_ServiceDesc,
			ConnectRPCFunc: actionsconnect.NewActionServiceHandler,
			OnConfigUpdate: onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (actionsconnect.ActionServiceHandler, serviceregistry.HandlerServer) {
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

func (a *ActionService) GetAction(ctx context.Context, req *connect.Request[actions.GetActionRequest]) (*connect.Response[actions.GetActionResponse], error) {
	rsp := &actions.GetActionResponse{}

	var loggableIdentifier slog.Attr
	if req.Msg.GetId() != "" {
		loggableIdentifier = slog.String("id", req.Msg.GetId())
	} else {
		loggableIdentifier = slog.String("name", req.Msg.GetName())
	}

	a.logger.DebugContext(ctx, "getting action", loggableIdentifier)

	action, err := a.dbClient.GetAction(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, loggableIdentifier)
	}
	rsp.Action = action

	return connect.NewResponse(rsp), nil
}

func (a *ActionService) ListActions(ctx context.Context, req *connect.Request[actions.ListActionsRequest]) (*connect.Response[actions.ListActionsResponse], error) {
	a.logger.DebugContext(ctx, "listing actions")
	rsp, err := a.dbClient.ListActions(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}
	a.logger.DebugContext(ctx, "listed actions")
	return connect.NewResponse(rsp), nil
}

func (a *ActionService) CreateAction(ctx context.Context, req *connect.Request[actions.CreateActionRequest]) (*connect.Response[actions.CreateActionResponse], error) {
	a.logger.DebugContext(ctx, "creating action", slog.String("name", req.Msg.GetName()))
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeAction,
	}
	rsp := &actions.CreateActionResponse{}

	err := a.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		action, err := txClient.CreateAction(ctx, req.Msg)
		if err != nil {
			a.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.ObjectID = action.GetId()
		auditParams.Original = action
		a.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Action = action
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("action", req.Msg.String()))
	}
	return connect.NewResponse(rsp), nil
}

func (a *ActionService) UpdateAction(ctx context.Context, req *connect.Request[actions.UpdateActionRequest]) (*connect.Response[actions.UpdateActionResponse], error) {
	actionID := req.Msg.GetId()
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
			a.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", actionID))
		}

		updated, err := txClient.UpdateAction(ctx, req.Msg)
		if err != nil {
			a.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", actionID))
		}

		auditParams.Original = original
		auditParams.Updated = updated
		a.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Action = updated
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", actionID))
	}

	return connect.NewResponse(rsp), nil
}

func (a *ActionService) DeleteAction(ctx context.Context, req *connect.Request[actions.DeleteActionRequest]) (*connect.Response[actions.DeleteActionResponse], error) {
	rsp := &actions.DeleteActionResponse{}
	actionID := req.Msg.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeAction,
		ObjectID:   actionID,
	}
	a.logger.DebugContext(ctx, "deleting action", slog.String("id", actionID))

	_, err := a.dbClient.DeleteAction(ctx, req.Msg)
	if err != nil {
		a.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", actionID))
	}

	a.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return connect.NewResponse(rsp), nil
}
