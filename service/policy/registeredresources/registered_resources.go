package registeredresources

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources/registeredresourcesconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type RegisteredResourcesService struct { //nolint:revive // RegisteredResourcesService is a valid name
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func OnConfigUpdate(s *RegisteredResourcesService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		s.config = sharedCfg
		s.dbClient = policydb.NewClient(s.dbClient.Client, s.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))

		s.logger.Info("registered resources service config reloaded")

		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[registeredresourcesconnect.RegisteredResourcesServiceHandler] {
	rrService := new(RegisteredResourcesService)
	onUpdateConfigHook := OnConfigUpdate(rrService)

	return &serviceregistry.Service[registeredresourcesconnect.RegisteredResourcesServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[registeredresourcesconnect.RegisteredResourcesServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &registeredresources.RegisteredResourcesService_ServiceDesc,
			ConnectRPCFunc: registeredresourcesconnect.NewRegisteredResourcesServiceHandler,
			OnConfigUpdate: onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (registeredresourcesconnect.RegisteredResourcesServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting registered resources service policy config", slog.String("error", err.Error()))
					panic(err)
				}

				rrService.logger = logger
				rrService.dbClient = policydb.NewClient(srp.DBClient, logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))
				rrService.config = cfg
				return rrService, nil
			},
		},
	}
}

func (s RegisteredResourcesService) IsReady(ctx context.Context) error {
	s.logger.TraceContext(ctx, "checking readiness of registered resources service")
	if err := s.dbClient.SQLDB.PingContext(ctx); err != nil {
		return err
	}

	return nil
}

/// Registered Resources Handlers

func (s RegisteredResourcesService) CreateRegisteredResource(context.Context, *connect.Request[registeredresources.CreateRegisteredResourceRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceResponse], error) {
	return nil, errors.New("not implemented")
}

func (s RegisteredResourcesService) GetRegisteredResource(context.Context, *connect.Request[registeredresources.GetRegisteredResourceRequest]) (*connect.Response[registeredresources.GetRegisteredResourceResponse], error) {
	return nil, errors.New("not implemented")
}

func (s RegisteredResourcesService) ListRegisteredResources(context.Context, *connect.Request[registeredresources.ListRegisteredResourcesRequest]) (*connect.Response[registeredresources.ListRegisteredResourcesResponse], error) {
	return nil, errors.New("not implemented")
}

func (s RegisteredResourcesService) UpdateRegisteredResource(context.Context, *connect.Request[registeredresources.UpdateRegisteredResourceRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceResponse], error) {
	return nil, errors.New("not implemented")
}

func (s RegisteredResourcesService) DeleteRegisteredResource(context.Context, *connect.Request[registeredresources.DeleteRegisteredResourceRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceResponse], error) {
	return nil, errors.New("not implemented")
}

/// Registered Resource Values Handlers

func (s RegisteredResourcesService) CreateRegisteredResourceValue(context.Context, *connect.Request[registeredresources.CreateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceValueResponse], error) {
	return nil, errors.New("not implemented")
}

func (s RegisteredResourcesService) GetRegisteredResourceValue(context.Context, *connect.Request[registeredresources.GetRegisteredResourceValueRequest]) (*connect.Response[registeredresources.GetRegisteredResourceValueResponse], error) {
	return nil, errors.New("not implemented")
}

func (s RegisteredResourcesService) ListRegisteredResourceValues(context.Context, *connect.Request[registeredresources.ListRegisteredResourceValuesRequest]) (*connect.Response[registeredresources.ListRegisteredResourceValuesResponse], error) {
	return nil, errors.New("not implemented")
}

func (s RegisteredResourcesService) UpdateRegisteredResourceValue(context.Context, *connect.Request[registeredresources.UpdateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceValueResponse], error) {
	return nil, errors.New("not implemented")
}

func (s RegisteredResourcesService) DeleteRegisteredResourceValue(context.Context, *connect.Request[registeredresources.DeleteRegisteredResourceValueRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceValueResponse], error) {
	return nil, errors.New("not implemented")
}
