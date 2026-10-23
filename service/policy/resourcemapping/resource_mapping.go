package resourcemapping

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping/resourcemappingconnectv2"
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

var errNamespacedPolicyNamespaceRequired = errors.New("namespace is required: provide either namespace_id, namespace_fqn, or group_id")

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

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[resourcemappingconnectv2.ResourceMappingServiceHandler] {
	rmSvc := new(ResourceMappingService)
	onUpdateConfigHook := OnConfigUpdate(rmSvc)

	return &serviceregistry.Service[resourcemappingconnectv2.ResourceMappingServiceHandler]{
		Close: rmSvc.Close,
		ServiceOptions: serviceregistry.ServiceOptions[resourcemappingconnectv2.ResourceMappingServiceHandler]{
			Namespace:              ns,
			DB:                     dbRegister,
			ServiceDesc:            &resourcemapping.ResourceMappingService_ServiceDesc,
			ConnectRPCRegisterFunc: resourcemappingconnectv2.RegisterResourceMappingServiceHandler,
			OnConfigUpdate:         onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (resourcemappingconnectv2.ResourceMappingServiceHandler, serviceregistry.HandlerServer) {
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

func (s ResourceMappingService) ListResourceMappingGroups(ctx context.Context, req *resourcemapping.ListResourceMappingGroupsRequest) (*resourcemapping.ListResourceMappingGroupsResponse, error) {
	rsp, err := s.dbClient.ListResourceMappingGroups(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return rsp, nil
}

func (s ResourceMappingService) GetResourceMappingGroup(ctx context.Context, req *resourcemapping.GetResourceMappingGroupRequest) (*resourcemapping.GetResourceMappingGroupResponse, error) {
	rsp := &resourcemapping.GetResourceMappingGroupResponse{}

	rmGroup, err := s.dbClient.GetResourceMappingGroup(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	rsp.ResourceMappingGroup = rmGroup

	return rsp, nil
}

func (s ResourceMappingService) CreateResourceMappingGroup(ctx context.Context, req *resourcemapping.CreateResourceMappingGroupRequest) (*resourcemapping.CreateResourceMappingGroupResponse, error) {
	rsp := &resourcemapping.CreateResourceMappingGroupResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
	}

	var rmGroup *policy.ResourceMappingGroup
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		var err error
		rmGroup, err = txClient.CreateResourceMappingGroup(ctx, req)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("resource_mapping_group", req.String()))
	}

	auditParams.ObjectID = rmGroup.GetId()
	auditParams.Original = rmGroup
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.ResourceMappingGroup = rmGroup

	return rsp, nil
}

func (s ResourceMappingService) UpdateResourceMappingGroup(ctx context.Context, req *resourcemapping.UpdateResourceMappingGroupRequest) (*resourcemapping.UpdateResourceMappingGroupResponse, error) {
	rsp := &resourcemapping.UpdateResourceMappingGroupResponse{}

	id := req.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
		ObjectID:   id,
	}

	var originalRmGroup *policy.ResourceMappingGroup
	var updatedRmGroup *policy.ResourceMappingGroup
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		var err error
		originalRmGroup, err = txClient.GetResourceMappingGroup(ctx, id)
		if err != nil {
			return err
		}

		updatedRmGroup, err = txClient.UpdateResourceMappingGroup(ctx, id, req)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", id))
	}

	auditParams.Original = originalRmGroup
	auditParams.Updated = updatedRmGroup
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.ResourceMappingGroup = updatedRmGroup

	return rsp, nil
}

func (s ResourceMappingService) DeleteResourceMappingGroup(ctx context.Context, req *resourcemapping.DeleteResourceMappingGroupRequest) (*resourcemapping.DeleteResourceMappingGroupResponse, error) {
	rsp := &resourcemapping.DeleteResourceMappingGroupResponse{}

	id := req.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
		ObjectID:   id,
	}

	var deletedRmGroup *policy.ResourceMappingGroup
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		var err error
		deletedRmGroup, err = txClient.DeleteResourceMappingGroup(ctx, id)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.ResourceMappingGroup = deletedRmGroup

	return rsp, nil
}

/*
	Resource Mappings
*/

func (s ResourceMappingService) ListResourceMappings(ctx context.Context,
	req *resourcemapping.ListResourceMappingsRequest,
) (*resourcemapping.ListResourceMappingsResponse, error) {
	rsp, err := s.dbClient.ListResourceMappings(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}

	return rsp, nil
}

func (s ResourceMappingService) ListResourceMappingsByGroupFqns(ctx context.Context, req *resourcemapping.ListResourceMappingsByGroupFqnsRequest) (*resourcemapping.ListResourceMappingsByGroupFqnsResponse, error) {
	rsp := &resourcemapping.ListResourceMappingsByGroupFqnsResponse{}

	fqns := req.GetFqns()

	fqnRmGroupMap, err := s.dbClient.ListResourceMappingsByGroupFqns(ctx, fqns)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed, slog.Any("fqns", fqns))
	}

	rsp.FqnResourceMappingGroups = fqnRmGroupMap

	return rsp, nil
}

func (s ResourceMappingService) GetResourceMapping(ctx context.Context,
	req *resourcemapping.GetResourceMappingRequest,
) (*resourcemapping.GetResourceMappingResponse, error) {
	rsp := &resourcemapping.GetResourceMappingResponse{}

	rm, err := s.dbClient.GetResourceMapping(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	rsp.ResourceMapping = rm

	return rsp, nil
}

func (s ResourceMappingService) CreateResourceMapping(ctx context.Context,
	req *resourcemapping.CreateResourceMappingRequest,
) (*resourcemapping.CreateResourceMappingResponse, error) {
	rsp := &resourcemapping.CreateResourceMappingResponse{}

	s.logger.DebugContext(ctx, "creating resource mapping")

	// --- BEGIN namespace enforcement (remove when namespaced_policy flag is phased out) ---
	// A group implies a namespace, so a mapping assigned to a group satisfies the requirement.
	if s.config.NamespacedPolicy && req.GetNamespaceId() == "" && req.GetNamespaceFqn() == "" && req.GetGroupId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errNamespacedPolicyNamespaceRequired.Error()).WithCause(errNamespacedPolicyNamespaceRequired)
	}
	// --- END namespace enforcement ---

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeResourceMapping,
	}

	var rm *policy.ResourceMapping
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		var err error
		rm, err = txClient.CreateResourceMapping(ctx, req)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("resource_mapping", req.String()))
	}

	auditParams.ObjectID = rm.GetId()
	auditParams.Original = rm
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.ResourceMapping = rm

	return rsp, nil
}

func (s ResourceMappingService) UpdateResourceMapping(ctx context.Context,
	req *resourcemapping.UpdateResourceMappingRequest,
) (*resourcemapping.UpdateResourceMappingResponse, error) {
	rsp := &resourcemapping.UpdateResourceMappingResponse{}

	resourceMappingID := req.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeResourceMapping,
		ObjectID:   resourceMappingID,
	}

	var originalRM *policy.ResourceMapping
	var updatedRM *policy.ResourceMapping
	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		var err error
		originalRM, err = txClient.GetResourceMapping(ctx, resourceMappingID)
		if err != nil {
			return err
		}

		updatedRM, err = txClient.UpdateResourceMapping(ctx, resourceMappingID, req)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed,
			slog.String("id", req.GetId()),
			slog.String("resource_mapping", req.String()),
		)
	}

	auditParams.Original = originalRM
	auditParams.Updated = updatedRM
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.ResourceMapping = updatedRM

	return rsp, nil
}

func (s ResourceMappingService) DeleteResourceMapping(ctx context.Context,
	req *resourcemapping.DeleteResourceMappingRequest,
) (*resourcemapping.DeleteResourceMappingResponse, error) {
	rsp := &resourcemapping.DeleteResourceMappingResponse{}

	resourceMappingID := req.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeResourceMapping,
		ObjectID:   resourceMappingID,
	}

	_, err := s.dbClient.DeleteResourceMapping(ctx, resourceMappingID)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", resourceMappingID))
	}

	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.ResourceMapping = &policy.ResourceMapping{
		Id: resourceMappingID,
	}

	return rsp, nil
}
