package actions

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/actions/actionsconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"

	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type ActionsService struct { //nolint:revive // ActionsService is a valid name for this struct
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[actionsconnect.ActionServiceHandler] {
	return &serviceregistry.Service[actionsconnect.ActionServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[actionsconnect.ActionServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &actions.ActionService_ServiceDesc,
			ConnectRPCFunc: actionsconnect.NewActionServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (actionsconnect.ActionServiceHandler, serviceregistry.HandlerServer) {
				cfg := policyconfig.GetSharedPolicyConfig(srp)
				return &ActionsService{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault)),
					logger:   srp.Logger,
					config:   cfg,
				}, nil
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
