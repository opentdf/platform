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
	otdferrors "github.com/opentdf/opentdf-v2-poc/pkg/errors"
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
	return err
}

func (s SubjectEncoding) CreateSubjectMapping(ctx context.Context,
	req *acsev1.CreateSubjectMappingRequest) (*acsev1.CreateSubjectMappingResponse, error) {
	slog.Debug("creating subject mapping")

	// Set the version of the resource to 1 on create
	req.SubjectMapping.Descriptor_.Version = 1

	err := s.dbClient.CreateResource(ctx, req.SubjectMapping.Descriptor_, req.SubjectMapping)
	if err != nil {
		slog.Error(otdferrors.ErrCreatingResource.Error(), slog.String("error", err.Error()))
		return &acsev1.CreateSubjectMappingResponse{}, status.Error(codes.Internal,
			fmt.Sprintf("%v: %v", otdferrors.ErrCreatingResource, err))
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
		slog.Error(otdferrors.ErrListingResource.Error(), slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrListingResource, err))
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id      int32
			mapping = new(acsev1.SubjectMapping)
		)
		err = rows.Scan(&id, &mapping)
		if err != nil {
			slog.Error(otdferrors.ErrListingResource.Error(), slog.String("error", err.Error()))
			return mappings, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrListingResource, err))
		}

		mapping.Descriptor_.Id = id
		mappings.SubjectMappings = append(mappings.SubjectMappings, mapping)
	}

	if err := rows.Err(); err != nil {
		slog.Error(otdferrors.ErrListingResource.Error(), slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrListingResource, err))
	}

	if err := rows.Err(); err != nil {
		slog.Error(otdferrors.ErrListingResource.Error(), slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrListingResource, err))
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

	row := s.dbClient.GetResource(
		ctx,
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
	)

	err := row.Scan(&id, &mapping.SubjectMapping)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info(otdferrors.ErrNotFound.Error(), slog.Int("id", int(req.Id)))
			return mapping, status.Error(codes.NotFound, otdferrors.ErrNotFound.Error())
		}
		slog.Error(otdferrors.ErrGettingResource.Error(), slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrGettingResource, err))
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
		slog.Error(otdferrors.ErrUpdatingResource.Error(), slog.String("error", err.Error()))
		return &acsev1.UpdateSubjectMappingResponse{},
			status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrUpdatingResource, err))
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
		slog.Error(otdferrors.ErrDeletingResource.Error(), slog.String("error", err.Error()))
		return &acsev1.DeleteSubjectMappingResponse{},
			status.Error(codes.Internal, fmt.Sprintf("%v: %v", otdferrors.ErrDeletingResource, err))
	}
	return &acsev1.DeleteSubjectMappingResponse{}, nil
}
