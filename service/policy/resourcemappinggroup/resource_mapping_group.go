package resourcemappinggroup

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/policy/resourcemappinggroup"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type ResourceMappingGroupService struct { //nolint:revive // ResourceMappingGroupService is a valid name for this struct
	resourcemappinggroup.UnimplementedResourceMappingGroupServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &resourcemappinggroup.ResourceMappingGroupService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &ResourceMappingGroupService{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger),
					logger:   srp.Logger,
				},
				func(ctx context.Context, mux *runtime.ServeMux, s any) error {
					server, ok := s.(resourcemappinggroup.ResourceMappingGroupServiceServer)
					if !ok {
						return fmt.Errorf("failed to assert server as resourcemappinggroup.ResourceMappingGroupServiceServer")
					}
					return resourcemappinggroup.RegisterResourceMappingGroupServiceHandlerServer(ctx, mux, server)
				}
		},
	}
}

/*
	Resource Mapping Groups
*/

func (s ResourceMappingGroupService) ListResourceMappingGroups(ctx context.Context, _ *resourcemappinggroup.ListResourceMappingGroupsRequest) (*resourcemappinggroup.ListResourceMappingGroupsResponse, error) {
	rmGroups, err := s.dbClient.ListResourceMappingGroups(ctx)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return &resourcemappinggroup.ListResourceMappingGroupsResponse{
		ResourceMappingGroups: rmGroups,
	}, nil
}

func (s ResourceMappingGroupService) GetResourceMappingGroup(ctx context.Context, req *resourcemappinggroup.GetResourceMappingGroupRequest) (*resourcemappinggroup.GetResourceMappingGroupResponse, error) {
	rmGroup, err := s.dbClient.GetResourceMappingGroup(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	return &resourcemappinggroup.GetResourceMappingGroupResponse{
		ResourceMappingGroup: rmGroup,
	}, nil
}

func (s ResourceMappingGroupService) CreateResourceMappingGroup(ctx context.Context, req *resourcemappinggroup.CreateResourceMappingGroupRequest) (*resourcemappinggroup.CreateResourceMappingGroupResponse, error) {
	rmGroup, err := s.dbClient.CreateResourceMappingGroup(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("resourceMappingGroup", req.String()))
	}

	return &resourcemappinggroup.CreateResourceMappingGroupResponse{
		ResourceMappingGroup: rmGroup,
	}, nil
}

func (s ResourceMappingGroupService) UpdateResourceMappingGroup(ctx context.Context, req *resourcemappinggroup.UpdateResourceMappingGroupRequest) (*resourcemappinggroup.UpdateResourceMappingGroupResponse, error) {
	id := req.GetId()

	rmGroup, err := s.dbClient.UpdateResourceMappingGroup(ctx, id, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", id), slog.String("resourceMappingGroup", req.String()))
	}

	return &resourcemappinggroup.UpdateResourceMappingGroupResponse{
		ResourceMappingGroup: rmGroup,
	}, nil
}

func (s ResourceMappingGroupService) DeleteResourceMappingGroup(ctx context.Context, req *resourcemappinggroup.DeleteResourceMappingGroupRequest) (*resourcemappinggroup.DeleteResourceMappingGroupResponse, error) {
	id := req.GetId()

	rmGroup, err := s.dbClient.DeleteResourceMappingGroup(ctx, id)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	return &resourcemappinggroup.DeleteResourceMappingGroupResponse{
		ResourceMappingGroup: rmGroup,
	}, nil
}
