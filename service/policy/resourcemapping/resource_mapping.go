package resourcemapping

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type ResourceMappingService struct { //nolint:revive // ResourceMappingService is a valid name for this struct
	resourcemapping.UnimplementedResourceMappingServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &resourcemapping.ResourceMappingService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &ResourceMappingService{dbClient: policydb.NewClient(srp.DBClient, srp.Logger), logger: srp.Logger}, func(ctx context.Context, mux *runtime.ServeMux, s any) error {
				server, ok := s.(resourcemapping.ResourceMappingServiceServer)
				if !ok {
					return fmt.Errorf("failed to assert server as resourcemapping.ResourceMappingServiceServer")
				}
				return resourcemapping.RegisterResourceMappingServiceHandlerServer(ctx, mux, server)
			}
		},
	}
}

/*
	Resource Mapping Groups
*/

func (s ResourceMappingService) ListResourceMappingGroups(ctx context.Context, req *resourcemapping.ListResourceMappingGroupsRequest) (*resourcemapping.ListResourceMappingGroupsResponse, error) {
	rmGroups, err := s.dbClient.ListResourceMappingGroups(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return &resourcemapping.ListResourceMappingGroupsResponse{
		ResourceMappingGroups: rmGroups,
	}, nil
}

func (s ResourceMappingService) GetResourceMappingGroup(ctx context.Context, req *resourcemapping.GetResourceMappingGroupRequest) (*resourcemapping.GetResourceMappingGroupResponse, error) {
	rmGroup, err := s.dbClient.GetResourceMappingGroup(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	return &resourcemapping.GetResourceMappingGroupResponse{
		ResourceMappingGroup: rmGroup,
	}, nil
}

func (s ResourceMappingService) CreateResourceMappingGroup(ctx context.Context, req *resourcemapping.CreateResourceMappingGroupRequest) (*resourcemapping.CreateResourceMappingGroupResponse, error) {
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
	}

	rmGroup, err := s.dbClient.CreateResourceMappingGroup(ctx, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("resourceMappingGroup", req.String()))
	}

	auditParams.ObjectID = rmGroup.GetId()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return &resourcemapping.CreateResourceMappingGroupResponse{
		ResourceMappingGroup: rmGroup,
	}, nil
}

func (s ResourceMappingService) UpdateResourceMappingGroup(ctx context.Context, req *resourcemapping.UpdateResourceMappingGroupRequest) (*resourcemapping.UpdateResourceMappingGroupResponse, error) {
	id := req.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
		ObjectID:   id,
	}

	originalRmGroup, err := s.dbClient.GetResourceMappingGroup(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updatedRmGroup, err := s.dbClient.UpdateResourceMappingGroup(ctx, id, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", id))
	}

	auditParams.Original = originalRmGroup
	auditParamsUpdated := &policy.ResourceMappingGroup{
		Id:          originalRmGroup.Id,
		Metadata:    updatedRmGroup.GetMetadata(),
		NamespaceId: originalRmGroup.GetNamespaceId(),
		Name:        originalRmGroup.GetName(),
	}
	if updatedRmGroup.GetNamespaceId() != "" {
		auditParamsUpdated.NamespaceId = updatedRmGroup.GetNamespaceId()
	}
	if updatedRmGroup.GetName() != "" {
		auditParamsUpdated.Name = updatedRmGroup.GetName()
	}
	auditParams.Updated = auditParamsUpdated

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return &resourcemapping.UpdateResourceMappingGroupResponse{
		ResourceMappingGroup: &policy.ResourceMappingGroup{
			Id: id,
		},
	}, nil
}

func (s ResourceMappingService) DeleteResourceMappingGroup(ctx context.Context, req *resourcemapping.DeleteResourceMappingGroupRequest) (*resourcemapping.DeleteResourceMappingGroupResponse, error) {
	id := req.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeResourceMappingGroup,
		ObjectID:   id,
	}

	_, err := s.dbClient.DeleteResourceMappingGroup(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return &resourcemapping.DeleteResourceMappingGroupResponse{
		ResourceMappingGroup: &policy.ResourceMappingGroup{
			Id: id,
		},
	}, nil
}

/*
	Resource Mappings
*/

func (s ResourceMappingService) ListResourceMappings(ctx context.Context,
	req *resourcemapping.ListResourceMappingsRequest,
) (*resourcemapping.ListResourceMappingsResponse, error) {
	resourceMappings, err := s.dbClient.ListResourceMappings(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return &resourcemapping.ListResourceMappingsResponse{
		ResourceMappings: resourceMappings,
	}, nil
}

func (s ResourceMappingService) ListResourceMappingsByGroupFqns(ctx context.Context, req *resourcemapping.ListResourceMappingsByGroupFqnsRequest) (*resourcemapping.ListResourceMappingsByGroupFqnsResponse, error) {
	fqns := req.GetFqns()

	fqnRmGroupMap, err := s.dbClient.ListResourceMappingsByGroupFqns(ctx, fqns)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed, slog.Any("fqns", fqns))
	}

	return &resourcemapping.ListResourceMappingsByGroupFqnsResponse{
		FqnResourceMappingGroups: fqnRmGroupMap,
	}, nil
}

func (s ResourceMappingService) GetResourceMapping(ctx context.Context,
	req *resourcemapping.GetResourceMappingRequest,
) (*resourcemapping.GetResourceMappingResponse, error) {
	rm, err := s.dbClient.GetResourceMapping(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	return &resourcemapping.GetResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}

func (s ResourceMappingService) CreateResourceMapping(ctx context.Context,
	req *resourcemapping.CreateResourceMappingRequest,
) (*resourcemapping.CreateResourceMappingResponse, error) {
	s.logger.Debug("creating resource mapping")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeResourceMapping,
	}

	rm, err := s.dbClient.CreateResourceMapping(ctx, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("resourceMapping", req.String()))
	}

	auditParams.ObjectID = rm.GetId()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return &resourcemapping.CreateResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}

func (s ResourceMappingService) UpdateResourceMapping(ctx context.Context,
	req *resourcemapping.UpdateResourceMappingRequest,
) (*resourcemapping.UpdateResourceMappingResponse, error) {
	resourceMappingID := req.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeResourceMapping,
		ObjectID:   resourceMappingID,
	}

	originalRM, err := s.dbClient.GetResourceMapping(ctx, resourceMappingID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	updatedRM, err := s.dbClient.UpdateResourceMapping(ctx, resourceMappingID, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed,
			slog.String("id", req.GetId()),
			slog.String("resourceMapping", req.String()),
		)
	}

	auditParams.Original = originalRM
	auditParamsUpdated := &policy.ResourceMapping{
		Id:             originalRM.Id,
		Metadata:       updatedRM.Metadata,
		AttributeValue: originalRM.AttributeValue,
		Terms:          originalRM.Terms,
		Group:          originalRM.Group,
	}
	if updatedRM.AttributeValue != nil {
		auditParamsUpdated.AttributeValue = updatedRM.AttributeValue
	}
	if updatedRM.Terms != nil {
		auditParamsUpdated.Terms = updatedRM.Terms
	}
	if updatedRM.Group != nil {
		auditParamsUpdated.Group = updatedRM.Group
	}
	auditParams.Updated = auditParamsUpdated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return &resourcemapping.UpdateResourceMappingResponse{
		ResourceMapping: &policy.ResourceMapping{
			Id: resourceMappingID,
		},
	}, nil
}

func (s ResourceMappingService) DeleteResourceMapping(ctx context.Context,
	req *resourcemapping.DeleteResourceMappingRequest,
) (*resourcemapping.DeleteResourceMappingResponse, error) {
	resourceMappingID := req.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeResourceMapping,
		ObjectID:   resourceMappingID,
	}

	_, err := s.dbClient.DeleteResourceMapping(ctx, resourceMappingID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", resourceMappingID))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return &resourcemapping.DeleteResourceMappingResponse{
		ResourceMapping: &policy.ResourceMapping{
			Id: resourceMappingID,
		},
	}, nil
}
