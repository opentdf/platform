package resourcemapping

import (
	"context"
	"errors"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/sdk/resourcemapping"
	"github.com/opentdf/platform/services"

	"google.golang.org/grpc"
)

type ResourceMappingService struct {
	resourcemapping.UnimplementedResourceMappingServiceServer
	dbClient *db.Client
}

func NewResourceMappingServer(dbClient *db.Client, grpcServer *grpc.Server, mux *runtime.ServeMux) error {
	as := &ResourceMappingService{
		dbClient: dbClient,
	}
	resourcemapping.RegisterResourceMappingServiceServer(grpcServer, as)
	err := resourcemapping.RegisterResourceMappingServiceHandlerServer(context.Background(), mux, as)
	if err != nil {
		return errors.New("failed to register resource encoding service handler")
	}
	return nil
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
