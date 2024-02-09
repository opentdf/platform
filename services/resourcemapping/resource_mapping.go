package resourcemapping

import (
	"context"
	"errors"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/sdk/resourcemapping"
	"github.com/opentdf/opentdf-v2-poc/services"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("attributeValueId", req.ResourceMapping.AttributeValueId))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		slog.Error(services.ErrCreationFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrCreationFailed)
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
		slog.Error(services.ErrListRetrievalFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListRetrievalFailed)
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
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGetRetrievalFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGetRetrievalFailed)
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
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("attributeValueId", req.ResourceMapping.AttributeValueId))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrUpdateFailed, slog.String("error", err.Error()))
		return nil,
			status.Error(codes.Internal, services.ErrUpdateFailed)
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
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrDeletionFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrDeletionFailed)
	}
	return &resourcemapping.DeleteResourceMappingResponse{
		ResourceMapping: rm,
	}, nil
}
