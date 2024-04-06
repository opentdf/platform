package resourcemapping

import (
	"context"
	"log/slog"

	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/resourcemapping"
	"github.com/arkavo-org/opentdf-platform/service/internal/db"
	"github.com/arkavo-org/opentdf-platform/service/pkg/serviceregistry"
	policydb "github.com/arkavo-org/opentdf-platform/service/policy/db"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

type ResourceMappingService struct {
	resourcemapping.UnimplementedResourceMappingServiceServer
	dbClient *policydb.PolicyDBClient
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "policy",
		ServiceDesc: &resourcemapping.ResourceMappingService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &ResourceMappingService{dbClient: policydb.NewClient(*srp.DBClient)}, func(ctx context.Context, mux *runtime.ServeMux, s any) error {
				return resourcemapping.RegisterResourceMappingServiceHandlerServer(ctx, mux, s.(resourcemapping.ResourceMappingServiceServer))
			}
		},
	}
}

/*
	Resource Mappings
*/

func (s ResourceMappingService) CreateResourceMapping(ctx context.Context,
	req *resourcemapping.CreateResourceMappingRequest,
) (*resourcemapping.CreateResourceMappingResponse, error) {
	slog.Debug("creating resource mapping")

	rm, err := s.dbClient.CreateResourceMapping(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("resourceMapping", req.String()))
	}

	return &resourcemapping.CreateResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}

func (s ResourceMappingService) ListResourceMappings(ctx context.Context,
	req *resourcemapping.ListResourceMappingsRequest,
) (*resourcemapping.ListResourceMappingsResponse, error) {
	resourceMappings, err := s.dbClient.ListResourceMappings(ctx)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return &resourcemapping.ListResourceMappingsResponse{
		ResourceMappings: resourceMappings,
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

func (s ResourceMappingService) UpdateResourceMapping(ctx context.Context,
	req *resourcemapping.UpdateResourceMappingRequest,
) (*resourcemapping.UpdateResourceMappingResponse, error) {
	rm, err := s.dbClient.UpdateResourceMapping(
		ctx,
		req.GetId(),
		req,
	)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("resourceMapping", req.String()))
	}
	return &resourcemapping.UpdateResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}

func (s ResourceMappingService) DeleteResourceMapping(ctx context.Context,
	req *resourcemapping.DeleteResourceMappingRequest,
) (*resourcemapping.DeleteResourceMappingResponse, error) {
	rm, err := s.dbClient.DeleteResourceMapping(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}
	return &resourcemapping.DeleteResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}
