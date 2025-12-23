package resourcemapping

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping/resourcemappingconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type ResourceMappingService struct { //nolint:revive // ResourceMappingService is a valid name for this struct
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func OnConfigUpdate(rmSvc *ResourceMappingService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		rmSvc.config = sharedCfg
		rmSvc.dbClient = policydb.NewClient(rmSvc.dbClient.Client, rmSvc.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))

		rmSvc.logger.Info("resource mapping service config reloaded")

		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[resourcemappingconnect.ResourceMappingServiceHandler] {
	rmSvc := new(ResourceMappingService)
	onUpdateConfigHook := OnConfigUpdate(rmSvc)

	return &serviceregistry.Service[resourcemappingconnect.ResourceMappingServiceHandler]{
		Close: rmSvc.Close,
		ServiceOptions: serviceregistry.ServiceOptions[resourcemappingconnect.ResourceMappingServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &resourcemapping.ResourceMappingService_ServiceDesc,
			ConnectRPCFunc: resourcemappingconnect.NewResourceMappingServiceHandler,
			OnConfigUpdate: onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (resourcemappingconnect.ResourceMappingServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting attributes service policy config", slog.String("error", err.Error()))
					panic(err)
				}

				rmSvc.logger = logger
				rmSvc.dbClient = policydb.NewClient(srp.DBClient, logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))
				rmSvc.config = cfg
				return rmSvc, nil
			},
		},
	}
}

// Close gracefully shuts down the service, closing the database client.
func (s *ResourceMappingService) Close() {
	s.logger.Info("gracefully shutting down resource mapping service")
	s.dbClient.Close()
}

/*
	Resource Mapping Groups
*/

func (s ResourceMappingService) ListResourceMappingGroups(ctx context.Context, req *connect.Request[resourcemapping.ListResourceMappingGroupsRequest]) (*connect.Response[resourcemapping.ListResourceMappingGroupsResponse], error) {
	rsp, err := s.dbClient.ListResourceMappingGroups(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s ResourceMappingService) GetResourceMappingGroup(ctx context.Context, req *connect.Request[resourcemapping.GetResourceMappingGroupRequest]) (*connect.Response[resourcemapping.GetResourceMappingGroupResponse], error) {
	rsp := &resourcemapping.GetResourceMappingGroupResponse{}

	rmGroup, err := s.dbClient.GetResourceMappingGroup(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", req.Msg.GetId()))
	}

	rsp.ResourceMappingGroup = rmGroup

	return connect.NewResponse(rsp), nil
}

func (s ResourceMappingService) CreateResourceMappingGroup(ctx context.Context, req *connect.Request[resourcemapping.CreateResourceMappingGroupRequest]) (*connect.Response[resourcemapping.CreateResourceMappingGroupResponse], error) {
	rsp := &resourcemapping.CreateResourceMappingGroupResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	rmGroup, err := s.dbClient.CreateResourceMappingGroup(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("resourceMappingGroup", req.Msg.String()))
	}

	auditEvent.UpdateObjectID(rmGroup.GetId())
	auditEvent.UpdateOriginal(rmGroup)
	auditEvent.Success(ctx, rmGroup)

	rsp.ResourceMappingGroup = rmGroup

	return connect.NewResponse(rsp), nil
}

func (s ResourceMappingService) UpdateResourceMappingGroup(ctx context.Context, req *connect.Request[resourcemapping.UpdateResourceMappingGroupRequest]) (*connect.Response[resourcemapping.UpdateResourceMappingGroupResponse], error) {
	rsp := &resourcemapping.UpdateResourceMappingGroupResponse{}

	id := req.Msg.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
		ObjectID:   id,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	originalRmGroup, err := s.dbClient.GetResourceMappingGroup(ctx, id)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updatedRmGroup, err := s.dbClient.UpdateResourceMappingGroup(ctx, id, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", id))
	}

	auditEvent.UpdateOriginal(originalRmGroup)

	auditEvent.Success(ctx, updatedRmGroup)

	rsp.ResourceMappingGroup = &policy.ResourceMappingGroup{
		Id: id,
	}

	return connect.NewResponse(rsp), nil
}

func (s ResourceMappingService) DeleteResourceMappingGroup(ctx context.Context, req *connect.Request[resourcemapping.DeleteResourceMappingGroupRequest]) (*connect.Response[resourcemapping.DeleteResourceMappingGroupResponse], error) {
	rsp := &resourcemapping.DeleteResourceMappingGroupResponse{}

	id := req.Msg.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
		ObjectID:   id,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	_, err := s.dbClient.DeleteResourceMappingGroup(ctx, id)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	auditEvent.Success(ctx, &policy.ResourceMappingGroup{
		Id: id,
	})

	rsp.ResourceMappingGroup = &policy.ResourceMappingGroup{
		Id: id,
	}

	return connect.NewResponse(rsp), nil
}

/*
	Resource Mappings
*/

func (s ResourceMappingService) ListResourceMappings(ctx context.Context,
	req *connect.Request[resourcemapping.ListResourceMappingsRequest],
) (*connect.Response[resourcemapping.ListResourceMappingsResponse], error) {
	rsp, err := s.dbClient.ListResourceMappings(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return connect.NewResponse(rsp), nil
}

func (s ResourceMappingService) ListResourceMappingsByGroupFqns(ctx context.Context, req *connect.Request[resourcemapping.ListResourceMappingsByGroupFqnsRequest]) (*connect.Response[resourcemapping.ListResourceMappingsByGroupFqnsResponse], error) {
	rsp := &resourcemapping.ListResourceMappingsByGroupFqnsResponse{}

	fqns := req.Msg.GetFqns()

	fqnRmGroupMap, err := s.dbClient.ListResourceMappingsByGroupFqns(ctx, fqns)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed, slog.Any("fqns", fqns))
	}

	rsp.FqnResourceMappingGroups = fqnRmGroupMap

	return connect.NewResponse(rsp), nil
}

func (s ResourceMappingService) GetResourceMapping(ctx context.Context,
	req *connect.Request[resourcemapping.GetResourceMappingRequest],
) (*connect.Response[resourcemapping.GetResourceMappingResponse], error) {
	rsp := &resourcemapping.GetResourceMappingResponse{}

	rm, err := s.dbClient.GetResourceMapping(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", req.Msg.GetId()))
	}

	rsp.ResourceMapping = rm

	return connect.NewResponse(rsp), nil
}

func (s ResourceMappingService) CreateResourceMapping(ctx context.Context,
	req *connect.Request[resourcemapping.CreateResourceMappingRequest],
) (*connect.Response[resourcemapping.CreateResourceMappingResponse], error) {
	rsp := &resourcemapping.CreateResourceMappingResponse{}

	s.logger.DebugContext(ctx, "creating resource mapping")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeResourceMapping,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	rm, err := s.dbClient.CreateResourceMapping(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("resourceMapping", req.Msg.String()))
	}

	auditEvent.UpdateObjectID(rm.GetId())
	auditEvent.UpdateOriginal(rm)
	auditEvent.Success(ctx, rm)

	rsp.ResourceMapping = rm

	return connect.NewResponse(rsp), nil
}

func (s ResourceMappingService) UpdateResourceMapping(ctx context.Context,
	req *connect.Request[resourcemapping.UpdateResourceMappingRequest],
) (*connect.Response[resourcemapping.UpdateResourceMappingResponse], error) {
	rsp := &resourcemapping.UpdateResourceMappingResponse{}

	resourceMappingID := req.Msg.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeResourceMapping,
		ObjectID:   resourceMappingID,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	originalRM, err := s.dbClient.GetResourceMapping(ctx, resourceMappingID)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	updatedRM, err := s.dbClient.UpdateResourceMapping(ctx, resourceMappingID, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed,
			slog.String("id", req.Msg.GetId()),
			slog.String("resourceMapping", req.Msg.String()),
		)
	}

	auditEvent.UpdateOriginal(originalRM)
	auditEvent.Success(ctx, updatedRM)

	rsp.ResourceMapping = &policy.ResourceMapping{
		Id: resourceMappingID,
	}

	return connect.NewResponse(rsp), nil
}

func (s ResourceMappingService) DeleteResourceMapping(ctx context.Context,
	req *connect.Request[resourcemapping.DeleteResourceMappingRequest],
) (*connect.Response[resourcemapping.DeleteResourceMappingResponse], error) {
	rsp := &resourcemapping.DeleteResourceMappingResponse{}

	resourceMappingID := req.Msg.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeResourceMapping,
		ObjectID:   resourceMappingID,
	}
	auditEvent := s.logger.Audit.PolicyCRUD(ctx, auditParams)
	defer auditEvent.Log(ctx)

	_, err := s.dbClient.DeleteResourceMapping(ctx, resourceMappingID)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", resourceMappingID))
	}

	auditEvent.Success(ctx, &policy.ResourceMapping{
		Id: resourceMappingID,
	})

	rsp.ResourceMapping = &policy.ResourceMapping{
		Id: resourceMappingID,
	}

	return connect.NewResponse(rsp), nil
}
