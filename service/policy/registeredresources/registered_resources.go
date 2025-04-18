package registeredresources

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources/registeredresourcesconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
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

func (s RegisteredResourcesService) CreateRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.CreateRegisteredResourceRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceResponse], error) {
	rsp := &registeredresources.CreateRegisteredResourceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeRegisteredResource,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		item, err := txClient.CreateRegisteredResource(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.ObjectID = item.GetId()
		auditParams.Original = item
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Resource = item
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("registered resouce", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s RegisteredResourcesService) GetRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.GetRegisteredResourceRequest]) (*connect.Response[registeredresources.GetRegisteredResourceResponse], error) {
	rsp := &registeredresources.GetRegisteredResourceResponse{}

	var identifier any
	if req.Msg.GetResourceId() != "" {
		identifier = req.Msg.GetResourceId()
	} else {
		identifier = req.Msg.GetFqn()
	}

	item, err := s.dbClient.GetRegisteredResource(ctx, identifier)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.Any("id", identifier))
	}
	rsp.Resource = item

	return connect.NewResponse(rsp), nil
}

func (s RegisteredResourcesService) ListRegisteredResources(ctx context.Context, req *connect.Request[registeredresources.ListRegisteredResourcesRequest]) (*connect.Response[registeredresources.ListRegisteredResourcesResponse], error) {
	rsp, err := s.dbClient.ListRegisteredResources(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s RegisteredResourcesService) UpdateRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.UpdateRegisteredResourceRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceResponse], error) {
	rsp := &registeredresources.UpdateRegisteredResourceResponse{}

	resourceID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeRegisteredResource,
		ObjectID:   resourceID,
	}

	original, err := s.dbClient.GetRegisteredResource(ctx, resourceID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", resourceID))
	}

	updated, err := s.dbClient.UpdateRegisteredResource(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("resource", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Resource = &policy.RegisteredResource{
		Id: resourceID,
	}

	return connect.NewResponse(rsp), nil
}

func (s RegisteredResourcesService) DeleteRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.DeleteRegisteredResourceRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceResponse], error) {
	resourceID := req.Msg.GetId()

	rsp := &registeredresources.DeleteRegisteredResourceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeRegisteredResource,
		ObjectID:   resourceID,
	}

	_, err := s.dbClient.DeleteRegisteredResource(ctx, resourceID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", resourceID))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Resource = &policy.RegisteredResource{
		Id: resourceID,
	}

	return connect.NewResponse(rsp), nil
}

/// Registered Resource Values Handlers

func (s RegisteredResourcesService) CreateRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.CreateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceValueResponse], error) {
	rsp := &registeredresources.CreateRegisteredResourceValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeRegisteredResourceValue,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		item, err := txClient.CreateRegisteredResourceValue(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.ObjectID = item.GetId()
		auditParams.Original = item
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Value = item
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("registered resource value", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s RegisteredResourcesService) GetRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.GetRegisteredResourceValueRequest]) (*connect.Response[registeredresources.GetRegisteredResourceValueResponse], error) {
	rsp := &registeredresources.GetRegisteredResourceValueResponse{}

	var identifier any
	if req.Msg.GetValueId() != "" {
		identifier = req.Msg.GetValueId()
	} else {
		identifier = req.Msg.GetFqn()
	}

	item, err := s.dbClient.GetRegisteredResourceValue(ctx, identifier)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.Any("id", identifier))
	}
	rsp.Value = item

	return connect.NewResponse(rsp), nil
}

func (s RegisteredResourcesService) ListRegisteredResourceValues(ctx context.Context, req *connect.Request[registeredresources.ListRegisteredResourceValuesRequest]) (*connect.Response[registeredresources.ListRegisteredResourceValuesResponse], error) {
	rsp, err := s.dbClient.ListRegisteredResourceValues(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s RegisteredResourcesService) UpdateRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.UpdateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceValueResponse], error) {
	rsp := &registeredresources.UpdateRegisteredResourceValueResponse{}

	valueID := req.Msg.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeRegisteredResourceValue,
		ObjectID:   valueID,
	}

	original, err := s.dbClient.GetRegisteredResourceValue(ctx, valueID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", valueID))
	}

	updated, err := s.dbClient.UpdateRegisteredResourceValue(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("resource", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = &policy.RegisteredResourceValue{
		Id: valueID,
	}

	return connect.NewResponse(rsp), nil
}

func (s RegisteredResourcesService) DeleteRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.DeleteRegisteredResourceValueRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceValueResponse], error) {
	valueID := req.Msg.GetId()

	rsp := &registeredresources.DeleteRegisteredResourceValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeRegisteredResourceValue,
		ObjectID:   valueID,
	}

	_, err := s.dbClient.DeleteRegisteredResourceValue(ctx, valueID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", valueID))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = &policy.RegisteredResourceValue{
		Id: valueID,
	}

	return connect.NewResponse(rsp), nil
}
