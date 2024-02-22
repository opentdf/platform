package resourcemapping

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/pkg/serviceregistry"
	"github.com/opentdf/opentdf-v2-poc/sdk/resourcemapping"
	"github.com/opentdf/opentdf-v2-poc/services"
)

type ResourceMappingService struct {
	resourcemapping.UnimplementedResourceMappingServiceServer
	dbClient *db.Client
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "policy",
		ServiceDesc: &resourcemapping.ResourceMappingService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &ResourceMappingService{dbClient: srp.DBClient}, func(ctx context.Context, mux *runtime.ServeMux, s any) error {
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

	rm, err := s.dbClient.CreateResourceMapping(ctx, req.ResourceMapping)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("resourceMapping", req.ResourceMapping.String()))
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
		return nil, services.HandleError(err, services.ErrListRetrievalFailed)
	}

	return &resourcemapping.ListResourceMappingsResponse{
		ResourceMappings: resourceMappings,
	}, nil
}

func (s ResourceMappingService) GetResourceMapping(ctx context.Context,
	req *resourcemapping.GetResourceMappingRequest,
) (*resourcemapping.GetResourceMappingResponse, error) {
	rm, err := s.dbClient.GetResourceMapping(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("id", req.Id))
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
		req.Id,
		req.ResourceMapping,
	)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("id", req.Id), slog.String("resourceMapping", req.ResourceMapping.String()))
	}
	return &resourcemapping.UpdateResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}

func (s ResourceMappingService) DeleteResourceMapping(ctx context.Context,
	req *resourcemapping.DeleteResourceMappingRequest,
) (*resourcemapping.DeleteResourceMappingResponse, error) {
	rm, err := s.dbClient.DeleteResourceMapping(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrDeletionFailed, slog.String("id", req.Id))
	}
	return &resourcemapping.DeleteResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}
