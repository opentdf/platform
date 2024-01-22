package subjectmapping

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"github.com/opentdf/opentdf-v2-poc/sdk/subjectmapping"

	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type SubjectEncodingService struct {
	subjectmapping.UnimplementedSubjectMappingServiceServer
	dbClient *db.Client
}

func NewSubjectEncodingServer(dbClient *db.Client, grpcServer *grpc.Server,
	grpcInprocess *grpc.Server, mux *runtime.ServeMux) error {
	s := &SubjectEncodingService{
		dbClient: dbClient,
	}
	subjectmapping.RegisterSubjectMappingServiceServer(grpcServer, s)
	if grpcInprocess != nil {
		subjectmapping.RegisterSubjectMappingServiceServer(grpcInprocess, s)
	}
	err := subjectmapping.RegisterSubjectMappingServiceHandlerServer(context.Background(), mux, s)
	if err != nil {
		return fmt.Errorf("failed to register subject encoding service handler: %w", err)
	}
	return nil
}

func (s SubjectEncodingService) CreateSubjectMapping(ctx context.Context,
	req *subjectmapping.CreateSubjectMappingRequest) (*subjectmapping.CreateSubjectMappingResponse, error) {
	slog.Debug("creating subject mapping")

	resource, err := protojson.Marshal(req.SubjectMapping)
	if err != nil {
		return &subjectmapping.CreateSubjectMappingResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.CreateResource(ctx, req.SubjectMapping.Descriptor_, resource)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &subjectmapping.CreateSubjectMappingResponse{}, status.Error(codes.Internal,
			fmt.Sprintf("%v: %v", services.ErrCreatingResource, err))
	}

	return &subjectmapping.CreateSubjectMappingResponse{}, nil
}

func (s SubjectEncodingService) ListSubjectMappings(ctx context.Context,
	req *subjectmapping.ListSubjectMappingsRequest) (*subjectmapping.ListSubjectMappingsResponse, error) {
	mappings := &subjectmapping.ListSubjectMappingsResponse{}

	rows, err := s.dbClient.ListResources(
		ctx,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
		req.Selector,
	)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, services.ErrListingResource)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id       int32
			mapping  = new(subjectmapping.SubjectMapping)
			bMapping []byte
		)
		err = rows.Scan(&id, &bMapping)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return mappings, status.Error(codes.Internal, services.ErrListingResource)
		}

		err = protojson.Unmarshal(bMapping, mapping)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return mappings, status.Error(codes.Internal, services.ErrListingResource)
		}

		mapping.Descriptor_.Id = id
		mappings.SubjectMappings = append(mappings.SubjectMappings, mapping)
	}

	if err := rows.Err(); err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, services.ErrListingResource)
	}

	if err := rows.Err(); err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, services.ErrListingResource)
	}

	return mappings, nil
}

func (s SubjectEncodingService) GetSubjectMapping(ctx context.Context,
	req *subjectmapping.GetSubjectMappingRequest) (*subjectmapping.GetSubjectMappingResponse, error) {
	var (
		mapping = &subjectmapping.GetSubjectMappingResponse{
			SubjectMapping: new(subjectmapping.SubjectMapping),
		}
		id       int32
		bMapping []byte
	)

	row, err := s.dbClient.GetResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
	)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = row.Scan(&id, &bMapping)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info(services.ErrNotFound, slog.Int("id", int(req.Id)))
			return mapping, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = protojson.Unmarshal(bMapping, mapping.SubjectMapping)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, services.ErrGettingResource)
	}

	mapping.SubjectMapping.Descriptor_.Id = id

	return mapping, nil
}

func (s SubjectEncodingService) UpdateSubjectMapping(ctx context.Context,
	req *subjectmapping.UpdateSubjectMappingRequest) (*subjectmapping.UpdateSubjectMappingResponse, error) {
	resource, err := protojson.Marshal(req.SubjectMapping)
	if err != nil {
		return &subjectmapping.UpdateSubjectMappingResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.UpdateResource(
		ctx,
		req.SubjectMapping.Descriptor_,
		resource,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
	)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &subjectmapping.UpdateSubjectMappingResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &subjectmapping.UpdateSubjectMappingResponse{}, nil
}

func (s SubjectEncodingService) DeleteSubjectMapping(ctx context.Context,
	req *subjectmapping.DeleteSubjectMappingRequest) (*subjectmapping.DeleteSubjectMappingResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return &subjectmapping.DeleteSubjectMappingResponse{},
			status.Error(codes.Internal, services.ErrDeletingResource)
	}
	return &subjectmapping.DeleteSubjectMappingResponse{}, nil
}
