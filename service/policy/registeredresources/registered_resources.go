package registeredresources

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
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
		Close: rrService.Close,
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

func (s *RegisteredResourcesService) IsReady(ctx context.Context) error {
	s.logger.TraceContext(ctx, "checking readiness of registered resources service")
	if err := s.dbClient.SQLDB.PingContext(ctx); err != nil {
		return err
	}

	return nil
}

// Close gracefully shuts down the service, closing the database client.
func (s *RegisteredResourcesService) Close() {
	s.logger.Info("gracefully shutting down registered resources service")
	s.dbClient.Close()
}

/// Registered Resources Handlers

func (s *RegisteredResourcesService) CreateRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.CreateRegisteredResourceRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceResponse], error) {
	rsp := &registeredresources.CreateRegisteredResourceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeRegisteredResource,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	s.logger.DebugContext(ctx, "creating registered resource", slog.String("name", req.Msg.GetName()))

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		resource, err := txClient.CreateRegisteredResource(ctx, req.Msg)
		if err != nil {
			return err
		}

		auditEvent.UpdateObjectID(resource.GetId())
		auditEvent.UpdateOriginal(resource)
		auditEvent.Success(ctx, resource)

		rsp.Resource = resource
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("registered resource", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *RegisteredResourcesService) GetRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.GetRegisteredResourceRequest]) (*connect.Response[registeredresources.GetRegisteredResourceResponse], error) {
	rsp := &registeredresources.GetRegisteredResourceResponse{}

	s.logger.DebugContext(ctx, "getting registered resource", slog.Any("identifier", req.Msg.GetIdentifier()))

	resource, err := s.dbClient.GetRegisteredResource(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("identifier", req.Msg.GetIdentifier()))
	}
	rsp.Resource = resource

	return connect.NewResponse(rsp), nil
}

func (s *RegisteredResourcesService) ListRegisteredResources(ctx context.Context, req *connect.Request[registeredresources.ListRegisteredResourcesRequest]) (*connect.Response[registeredresources.ListRegisteredResourcesResponse], error) {
	s.logger.DebugContext(ctx, "listing registered resources")

	rsp, err := s.dbClient.ListRegisteredResources(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s *RegisteredResourcesService) UpdateRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.UpdateRegisteredResourceRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceResponse], error) {
	resourceID := req.Msg.GetId()

	rsp := &registeredresources.UpdateRegisteredResourceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeRegisteredResource,
		ObjectID:   resourceID,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	s.logger.DebugContext(ctx, "updating registered resource", slog.String("id", resourceID))

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetRegisteredResource(ctx, &registeredresources.GetRegisteredResourceRequest{
			Identifier: &registeredresources.GetRegisteredResourceRequest_Id{
				Id: resourceID,
			},
		})
		if err != nil {
			return err
		}

		updated, err := txClient.UpdateRegisteredResource(ctx, req.Msg)
		if err != nil {
			return err
		}

		auditEvent.UpdateOriginal(original)
		auditEvent.Success(ctx, updated)

		rsp.Resource = updated
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("registered resource", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *RegisteredResourcesService) DeleteRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.DeleteRegisteredResourceRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceResponse], error) {
	resourceID := req.Msg.GetId()

	rsp := &registeredresources.DeleteRegisteredResourceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeRegisteredResource,
		ObjectID:   resourceID,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	s.logger.DebugContext(ctx, "deleting registered resource", slog.String("id", resourceID))

	deleted, err := s.dbClient.DeleteRegisteredResource(ctx, resourceID)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("registered resource", req.Msg.String()))
	}

	auditEvent.Success(ctx, deleted)

	rsp.Resource = deleted

	return connect.NewResponse(rsp), nil
}

/// Registered Resource Values Handlers

func (s *RegisteredResourcesService) CreateRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.CreateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceValueResponse], error) {
	rsp := &registeredresources.CreateRegisteredResourceValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeRegisteredResourceValue,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	s.logger.DebugContext(ctx, "creating registered resource value", slog.String("value", req.Msg.GetValue()))

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		value, err := txClient.CreateRegisteredResourceValue(ctx, req.Msg)
		if err != nil {
			return err
		}

		auditEvent.UpdateObjectID(value.GetId())
		auditEvent.UpdateOriginal(value)
		auditEvent.Success(ctx, value)

		rsp.Value = value
		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("registered resource value", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *RegisteredResourcesService) GetRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.GetRegisteredResourceValueRequest]) (*connect.Response[registeredresources.GetRegisteredResourceValueResponse], error) {
	rsp := &registeredresources.GetRegisteredResourceValueResponse{}

	s.logger.DebugContext(ctx, "getting registered resource value", slog.Any("identifier", req.Msg.GetIdentifier()))

	value, err := s.dbClient.GetRegisteredResourceValue(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("identifier", req.Msg.GetIdentifier()))
	}
	rsp.Value = value

	return connect.NewResponse(rsp), nil
}

func (s *RegisteredResourcesService) GetRegisteredResourceValuesByFQNs(ctx context.Context, req *connect.Request[registeredresources.GetRegisteredResourceValuesByFQNsRequest]) (*connect.Response[registeredresources.GetRegisteredResourceValuesByFQNsResponse], error) {
	rsp := &registeredresources.GetRegisteredResourceValuesByFQNsResponse{}

	s.logger.DebugContext(ctx, "getting registered resource values by FQNs", slog.Any("fqns", req.Msg.GetFqns()))

	fqnValueMap, err := s.dbClient.GetRegisteredResourceValuesByFQNs(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("fqns", req.Msg.GetFqns()))
	}
	rsp.FqnValueMap = fqnValueMap

	return connect.NewResponse(rsp), nil
}

func (s *RegisteredResourcesService) ListRegisteredResourceValues(ctx context.Context, req *connect.Request[registeredresources.ListRegisteredResourceValuesRequest]) (*connect.Response[registeredresources.ListRegisteredResourceValuesResponse], error) {
	s.logger.DebugContext(ctx, "listing registered resource values")

	rsp, err := s.dbClient.ListRegisteredResourceValues(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	s.logger.DebugContext(ctx, "listed registered resource values")

	return connect.NewResponse(rsp), nil
}

func (s *RegisteredResourcesService) UpdateRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.UpdateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceValueResponse], error) {
	valueID := req.Msg.GetId()

	rsp := &registeredresources.UpdateRegisteredResourceValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeRegisteredResourceValue,
		ObjectID:   valueID,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	s.logger.DebugContext(ctx, "updating registered resource value", slog.String("id", valueID))

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetRegisteredResourceValue(ctx, &registeredresources.GetRegisteredResourceValueRequest{
			Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
				Id: valueID,
			},
		})
		if err != nil {
			return err
		}

		updated, err := txClient.UpdateRegisteredResourceValue(ctx, req.Msg)
		if err != nil {
			return err
		}

		auditEvent.UpdateOriginal(original)
		auditEvent.Success(ctx, updated)

		rsp.Value = updated

		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("registered resource value", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *RegisteredResourcesService) DeleteRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.DeleteRegisteredResourceValueRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceValueResponse], error) {
	valueID := req.Msg.GetId()

	rsp := &registeredresources.DeleteRegisteredResourceValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeRegisteredResourceValue,
		ObjectID:   valueID,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	s.logger.DebugContext(ctx, "deleting registered resource value", slog.String("id", valueID))

	deleted, err := s.dbClient.DeleteRegisteredResourceValue(ctx, valueID)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("registered resource value", req.Msg.String()))
	}

	auditEvent.Success(ctx, deleted)

	rsp.Value = deleted

	return connect.NewResponse(rsp), nil
}
