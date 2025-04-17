package actions

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/actions/actionsconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"

	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type ActionsService struct { //nolint:revive // ActionsService is a valid name for this struct
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func OnConfigUpdate(actionsSvc *ActionsService) serviceregistry.OnConfigUpdateHook {
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
	actionsSvc := new(ActionsService)
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

func (a *ActionsService) GetAction(context.Context, *connect.Request[actions.GetActionRequest]) (*connect.Response[actions.GetActionResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetAction is not implemented"))
}

func (a *ActionsService) ListActions(context.Context, *connect.Request[actions.ListActionsRequest]) (*connect.Response[actions.ListActionsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ListActions is not implemented"))
}

func (a *ActionsService) CreateAction(context.Context, *connect.Request[actions.CreateActionRequest]) (*connect.Response[actions.CreateActionResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("CreateAction is not implemented"))
}

func (a *ActionsService) UpdateAction(context.Context, *connect.Request[actions.UpdateActionRequest]) (*connect.Response[actions.UpdateActionResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("UpdateAction is not implemented"))
}

func (a *ActionsService) DeleteAction(context.Context, *connect.Request[actions.DeleteActionRequest]) (*connect.Response[actions.DeleteActionResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("DeleteAction is not implemented"))
}
