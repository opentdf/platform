package acre

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
	"google.golang.org/protobuf/encoding/protojson"
)

type ResourceMappingService struct {
	resourcemapping.UnimplementedResourceMappingServiceServer
	dbClient *db.Client
}

func NewResourceMapping(dbClient *db.Client, grpcServer *grpc.Server, mux *runtime.ServeMux) error {
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
	req *resourcemapping.CreateResourceMappingRequest) (*resourcemapping.CreateResourceMappingResponse, error) {
	slog.Debug("creating resource mapping")

	// Set the version of the resource to 1 on create
	req.Mapping.Descriptor_.Version = 1

	resource, err := protojson.Marshal(req.Mapping)
	if err != nil {
		return &resourcemapping.CreateResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.CreateResource(ctx, req.Mapping.Descriptor_, resource)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &acre.CreateResourceMappingResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	return &acre.CreateResourceMappingResponse{}, nil
}

// //nolint:dupl // there probably is duplication in these crud operations but its not worth refactoring yet.
// func (s ResourceEncodingService) ListResourceMappings(ctx context.Context,
// 	req *acre.ListResourceMappingsRequest) (*acre.ListResourceMappingsResponse, error) {
// 	mappings := &acre.ListResourceMappingsResponse{}

// 	rows, err := s.dbClient.ListResources(
// 		ctx,
// 		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
// 		req.Selector,
// 	)
// 	if err != nil {
// 		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
// 		return mappings, status.Error(codes.Internal, services.ErrListingResource)
// 	}
// 	defer rows.Close()

// 	for rows.Next() {
// 		var (
// 			id         int32
// 			mapping    = new(acre.ResourceMapping)
// 			tmpMapping []byte
// 		)
// 		err = rows.Scan(&id, &tmpMapping)
// 		if err != nil {
// 			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
// 			return mappings, status.Error(codes.Internal, services.ErrListingResource)
// 		}

// 		err = protojson.Unmarshal(tmpMapping, mapping)
// 		if err != nil {
// 			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
// 			return mappings, status.Error(codes.Internal, services.ErrListingResource)
// 		}

// 		mapping.Descriptor_.Id = id
// 		mappings.Mappings = append(mappings.Mappings, mapping)
// 	}

// 	if err := rows.Err(); err != nil {
// 		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
// 		return mappings, status.Error(codes.Internal, services.ErrListingResource)
// 	}

// 	return mappings, nil
// }

// func (s ResourceEncodingService) GetResourceMapping(ctx context.Context,
// 	req *acre.GetResourceMappingRequest) (*acre.GetResourceMappingResponse, error) {
// 	var (
// 		mapping = &acre.GetResourceMappingResponse{
// 			Mapping: new(acre.ResourceMapping),
// 		}
// 		id       int32
// 		bMapping []byte
// 	)

// 	row, err := s.dbClient.GetResource(
// 		ctx,
// 		req.Id,
// 		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
// 	)
// 	if err != nil {
// 		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
// 		return mapping, status.Error(codes.Internal, services.ErrGettingResource)
// 	}

// 	err = row.Scan(&id, &bMapping)
// 	if err != nil {
// 		if errors.Is(err, pgx.ErrNoRows) {
// 			slog.Error(services.ErrNotFound, slog.String("error", err.Error()))
// 			return mapping, status.Error(codes.NotFound, services.ErrNotFound)
// 		}
// 		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
// 		return mapping, status.Error(codes.Internal, services.ErrGettingResource)
// 	}

// 	err = protojson.Unmarshal(bMapping, mapping.Mapping)
// 	if err != nil {
// 		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
// 		return mapping, status.Error(codes.Internal, services.ErrGettingResource)
// 	}

// 	mapping.Mapping.Descriptor_.Id = id

// 	return mapping, nil
// }

// func (s ResourceEncodingService) UpdateResourceMapping(ctx context.Context,
// 	req *acre.UpdateResourceMappingRequest) (*acre.UpdateResourceMappingResponse, error) {
// 	resource, err := protojson.Marshal(req.Mapping)
// 	if err != nil {
// 		return &acre.UpdateResourceMappingResponse{},
// 			status.Error(codes.Internal, services.ErrCreatingResource)
// 	}

// 	err = s.dbClient.UpdateResource(
// 		ctx,
// 		req.Mapping.Descriptor_,
// 		resource,
// 		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
// 	)
// 	if err != nil {
// 		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
// 		return &acre.UpdateResourceMappingResponse{},
// 			status.Error(codes.Internal, services.ErrUpdatingResource)
// 	}
// 	return &acre.UpdateResourceMappingResponse{}, nil
// }

// func (s ResourceEncodingService) DeleteResourceMapping(ctx context.Context,
// 	req *acre.DeleteResourceMappingRequest) (*acre.DeleteResourceMappingResponse, error) {
// 	if err := s.dbClient.DeleteResource(
// 		ctx,
// 		req.Id,
// 		common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
// 	); err != nil {
// 		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
// 		return &acre.DeleteResourceMappingResponse{},
// 			status.Error(codes.Internal, services.ErrDeletingResource)
// 	}
// 	return &acre.DeleteResourceMappingResponse{}, nil
// }
