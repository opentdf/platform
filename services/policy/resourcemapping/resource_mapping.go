package resourcemapping

import (
	"context"
	"errors"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/internal/db"
	rsMp "github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/services"
	policydb "github.com/opentdf/platform/services/policy/db"

	"google.golang.org/grpc"
)

type ResourceMappingService struct {
	rsMp.UnimplementedResourceMappingServiceServer
	dbClient *policydb.PolicyDbClient
}

func NewResourceMappingServer(dbClient *db.Client, grpcServer *grpc.Server, mux *runtime.ServeMux) error {
	as := &ResourceMappingService{
		dbClient: policydb.NewClient(*dbClient),
	}
	rsMp.RegisterResourceMappingServiceServer(grpcServer, as)
	err := rsMp.RegisterResourceMappingServiceHandlerServer(context.Background(), mux, as)
	if err != nil {
		return errors.New("failed to register resource encoding service handler")
	}
	return nil
}

/*
	Resource Mappings
*/

func (s ResourceMappingService) CreateResourceMapping(ctx context.Context,
	req *rsMp.CreateResourceMappingRequest,
) (*rsMp.CreateResourceMappingResponse, error) {
	slog.Debug("creating resource mapping")

	rm, err := s.dbClient.CreateResourceMapping(ctx, req.ResourceMapping)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("resourceMapping", req.String()))
	}

	return &rsMp.CreateResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}

func (s ResourceMappingService) ListResourceMappings(ctx context.Context,
	req *rsMp.ListResourceMappingsRequest,
) (*rsMp.ListResourceMappingsResponse, error) {
	resourceMappings, err := s.dbClient.ListResourceMappings(ctx)
	if err != nil {
		return nil, services.HandleError(err, services.ErrListRetrievalFailed)
	}

	return &rsMp.ListResourceMappingsResponse{
		ResourceMappings: resourceMappings,
	}, nil
}

func (s ResourceMappingService) GetResourceMapping(ctx context.Context,
	req *rsMp.GetResourceMappingRequest,
) (*rsMp.GetResourceMappingResponse, error) {
	rm, err := s.dbClient.GetResourceMapping(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("id", req.Id))
	}

	return &rsMp.GetResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}

func (s ResourceMappingService) UpdateResourceMapping(ctx context.Context,
	req *rsMp.UpdateResourceMappingRequest,
) (*rsMp.UpdateResourceMappingResponse, error) {
	rm, err := s.dbClient.UpdateResourceMapping(
		ctx,
		req.Id,
		req.ResourceMapping,
	)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("id", req.Id), slog.String("resourceMapping", req.String()))
	}
	return &rsMp.UpdateResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}

func (s ResourceMappingService) DeleteResourceMapping(ctx context.Context,
	req *rsMp.DeleteResourceMappingRequest,
) (*rsMp.DeleteResourceMappingResponse, error) {
	rm, err := s.dbClient.DeleteResourceMapping(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrDeletionFailed, slog.String("id", req.Id))
	}
	return &rsMp.DeleteResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}
