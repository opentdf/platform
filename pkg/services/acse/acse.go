package acse

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	acsev1 "github.com/opentdf/opentdf-v2-poc/gen/acse/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/pkg/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SubjectEncoding struct {
	acsev1.UnimplementedSubjectEncodingServiceServer
	dbClient *db.Client
}

func NewSubjectEncodingServer(dbClient *db.Client, grpcServer *grpc.Server,
	grpcInprocess *grpc.Server, mux *runtime.ServeMux) error {
	as := &SubjectEncoding{
		dbClient: dbClient,
	}
	acsev1.RegisterSubjectEncodingServiceServer(grpcServer, as)
	if grpcInprocess != nil {
		acsev1.RegisterSubjectEncodingServiceServer(grpcInprocess, as)
	}
	err := acsev1.RegisterSubjectEncodingServiceHandlerServer(context.Background(), mux, as)
	if err != nil {
		return fmt.Errorf("failed to register subject encoding service handler: %w", err)
	}
	return nil
}

func (s SubjectEncoding) CreateSubjectMapping(ctx context.Context,
	req *acsev1.CreateSubjectMappingRequest) (*acsev1.CreateSubjectMappingResponse, error) {
	slog.Debug("creating subject mapping")

	// Set the version of the resource to 1 on create
	req.SubjectMapping.Descriptor_.Version = 1

	err := s.dbClient.CreateResource(ctx, req.SubjectMapping.Descriptor_, req.SubjectMapping)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &acsev1.CreateSubjectMappingResponse{}, status.Error(codes.Internal,
			fmt.Sprintf("%v: %v", services.ErrCreatingResource, err))
	}

	return &acsev1.CreateSubjectMappingResponse{}, nil
}

func (s SubjectEncoding) ListSubjectMappings(ctx context.Context,
	req *acsev1.ListSubjectMappingsRequest) (*acsev1.ListSubjectMappingsResponse, error) {
	mappings := &acsev1.ListSubjectMappingsResponse{}

	rows, err := s.dbClient.ListResources(
		ctx,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
		req.Selector,
	)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, services.ErrListingResource)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id      int32
			mapping = new(acsev1.SubjectMapping)
		)
		err = rows.Scan(&id, &mapping)
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

func (s SubjectEncoding) GetSubjectMapping(ctx context.Context,
	req *acsev1.GetSubjectMappingRequest) (*acsev1.GetSubjectMappingResponse, error) {
	var (
		mapping = &acsev1.GetSubjectMappingResponse{
			SubjectMapping: new(acsev1.SubjectMapping),
		}
		id int32
	)

	row, err := s.dbClient.GetResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
	)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = row.Scan(&id, &mapping.SubjectMapping)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info(services.ErrNotFound, slog.Int("id", int(req.Id)))
			return mapping, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, services.ErrGettingResource)
	}

	mapping.SubjectMapping.Descriptor_.Id = id

	return mapping, nil
}

func (s SubjectEncoding) UpdateSubjectMapping(ctx context.Context,
	req *acsev1.UpdateSubjectMappingRequest) (*acsev1.UpdateSubjectMappingResponse, error) {
	err := s.dbClient.UpdateResource(
		ctx,
		req.SubjectMapping.Descriptor_,
		req.SubjectMapping,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
	)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &acsev1.UpdateSubjectMappingResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &acsev1.UpdateSubjectMappingResponse{}, nil
}

func (s SubjectEncoding) DeleteSubjectMapping(ctx context.Context,
	req *acsev1.DeleteSubjectMappingRequest) (*acsev1.DeleteSubjectMappingResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return &acsev1.DeleteSubjectMappingResponse{},
			status.Error(codes.Internal, services.ErrDeletingResource)
	}
	return &acsev1.DeleteSubjectMappingResponse{}, nil
}
