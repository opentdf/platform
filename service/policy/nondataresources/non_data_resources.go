package nondataresources

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/nondataresources"
	"github.com/opentdf/platform/protocol/go/policy/nondataresources/nondataresourcesconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type NonDataResourcesService struct { //nolint:revive // NonDataResourcesService is a valid name
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[nondataresourcesconnect.NonDataResourcesServiceHandler] {
	return &serviceregistry.Service[nondataresourcesconnect.NonDataResourcesServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[nondataresourcesconnect.NonDataResourcesServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &nondataresources.NonDataResourcesService_ServiceDesc,
			ConnectRPCFunc: nondataresourcesconnect.NewNonDataResourcesServiceHandler,
			// todo: why does this not compile?
			// GRPCGatewayFunc: nondataresources.RegisterNonDataResourcesServiceServer,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (nondataresourcesconnect.NonDataResourcesServiceHandler, serviceregistry.HandlerServer) {
				cfg := policyconfig.GetSharedPolicyConfig(srp)
				s := &NonDataResourcesService{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault)),
					logger:   srp.Logger,
					config:   cfg,
				}

				if err := srp.RegisterReadinessCheck("policy", s.IsReady); err != nil {
					srp.Logger.Error("failed to register policy readiness check", slog.String("error", err.Error()))
				}

				return s, nil
			},
		},
	}
}

func (s NonDataResourcesService) IsReady(ctx context.Context) error {
	s.logger.TraceContext(ctx, "checking readiness of nondataresources service")
	if err := s.dbClient.SQLDB.PingContext(ctx); err != nil {
		return err
	}

	return nil
}

/// Non Data Resource Groups Handlers

func (s NonDataResourcesService) CreateNonDataResourceGroup(context.Context, *connect.Request[nondataresources.CreateNonDataResourceGroupRequest]) (*connect.Response[nondataresources.CreateNonDataResourceGroupResponse], error) {
	return nil, errors.New("not implemented")
}

func (s NonDataResourcesService) GetNonDataResourceGroup(context.Context, *connect.Request[nondataresources.GetNonDataResourceGroupRequest]) (*connect.Response[nondataresources.GetNonDataResourceGroupResponse], error) {
	return nil, errors.New("not implemented")
}

func (s NonDataResourcesService) ListNonDataResourceGroup(context.Context, *connect.Request[nondataresources.ListNonDataResourceGroupRequest]) (*connect.Response[nondataresources.ListNonDataResourceGroupResponse], error) {
	return nil, errors.New("not implemented")
}

func (s NonDataResourcesService) UpdateNonDataResourceGroup(context.Context, *connect.Request[nondataresources.UpdateNonDataResourceGroupRequest]) (*connect.Response[nondataresources.UpdateNonDataResourceGroupResponse], error) {
	return nil, errors.New("not implemented")
}

func (s NonDataResourcesService) DeleteNonDataResourceGroup(context.Context, *connect.Request[nondataresources.DeleteNonDataResourceGroupRequest]) (*connect.Response[nondataresources.DeleteNonDataResourceGroupResponse], error) {
	return nil, errors.New("not implemented")
}

/// Non Data Resource Values Handlers

func (s NonDataResourcesService) CreateNonDataResourceValue(context.Context, *connect.Request[nondataresources.CreateNonDataResourceValueRequest]) (*connect.Response[nondataresources.CreateNonDataResourceValueResponse], error) {
	return nil, errors.New("not implemented")
}

func (s NonDataResourcesService) GetNonDataResourceValue(context.Context, *connect.Request[nondataresources.GetNonDataResourceValueRequest]) (*connect.Response[nondataresources.GetNonDataResourceValueResponse], error) {
	return nil, errors.New("not implemented")
}

func (s NonDataResourcesService) ListNonDataResourceValue(context.Context, *connect.Request[nondataresources.ListNonDataResourceValueRequest]) (*connect.Response[nondataresources.ListNonDataResourceValueResponse], error) {
	return nil, errors.New("not implemented")
}

func (s NonDataResourcesService) UpdateNonDataResourceValue(context.Context, *connect.Request[nondataresources.UpdateNonDataResourceValueRequest]) (*connect.Response[nondataresources.UpdateNonDataResourceValueResponse], error) {
	return nil, errors.New("not implemented")
}

func (s NonDataResourcesService) DeleteNonDataResourceValue(context.Context, *connect.Request[nondataresources.DeleteNonDataResourceValueRequest]) (*connect.Response[nondataresources.DeleteNonDataResourceValueResponse], error) {
	return nil, errors.New("not implemented")
}
