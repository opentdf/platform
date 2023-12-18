package acse

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	acsev1 "github.com/opentdf/opentdf-v2-poc/gen/acse/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SubjectEncoding struct {
	acsev1.UnimplementedSubjectEncodingServiceServer
	dbClient *db.Client
}

func NewSubjectEncodingServer(dbClient *db.Client, grpcServer *grpc.Server, grpcInprocess *grpc.Server, mux *runtime.ServeMux) error {
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

func (s SubjectEncoding) CreateSubjectMapping(ctx context.Context, req *acsev1.CreateSubjectMappingRequest) (*acsev1.CreateSubjectMappingResponse, error) {
	slog.Debug("creating subject mapping")
	var (
		err error
	)

	// Set the version of the resource to 1 on create
	req.SubjectMapping.Descriptor_.Version = 1

	err = s.dbClient.CreateResource(req.SubjectMapping.Descriptor_, req.SubjectMapping)
	if err != nil {
		slog.Error("issue creating resource mapping", slog.String("error", err.Error()))
		return &acsev1.CreateSubjectMappingResponse{}, status.Error(codes.Internal, err.Error())
	}

	return &acsev1.CreateSubjectMappingResponse{}, nil
}

func (s SubjectEncoding) ListSubjectMappings(ctx context.Context, req *acsev1.ListSubjectMappingsRequest) (*acsev1.ListSubjectMappingsResponse, error) {
	mappings := &acsev1.ListSubjectMappingsResponse{}

	rows, err := s.dbClient.ListResources(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(), req.Selector)
	if err != nil {
		slog.Error("issue listing subject mappings", slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, err.Error())
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id      int32
			mapping = new(acsev1.SubjectMapping)
		)
		err = rows.Scan(&id, &mapping)
		if err != nil {
			slog.Error("issue listing subject mappings", slog.String("error", err.Error()))
			return mappings, status.Error(codes.Internal, err.Error())
		}

		mapping.Descriptor_.Id = id
		mappings.SubjectMappings = append(mappings.SubjectMappings, mapping)
	}

	return mappings, nil
}

func (s SubjectEncoding) GetSubjectMapping(ctx context.Context, req *acsev1.GetSubjectMappingRequest) (*acsev1.GetSubjectMappingResponse, error) {
	var (
		mapping = &acsev1.GetSubjectMappingResponse{
			SubjectMapping: new(acsev1.SubjectMapping),
		}
		err error
		id  int32
	)

	row := s.dbClient.GetResource(req.Id, commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String())
	if err != nil {
		slog.Error("issue getting subject mapping", slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, err.Error())
	}

	err = row.Scan(&id, &mapping.SubjectMapping)
	if err != nil {
		if err == pgx.ErrNoRows {
			slog.Info("subject mapping not found", slog.Int("id", int(req.Id)))
			return mapping, status.Error(codes.NotFound, "subject mapping not found")
		}
		slog.Error("issue getting subject mapping", slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, err.Error())
	}

	mapping.SubjectMapping.Descriptor_.Id = id

	return mapping, nil
}

func (s SubjectEncoding) UpdateSubjectMapping(ctx context.Context, req *acsev1.UpdateSubjectMappingRequest) (*acsev1.UpdateSubjectMappingResponse, error) {
	err := s.dbClient.UpdateResource(req.SubjectMapping.Descriptor_, req.SubjectMapping, commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String())
	if err != nil {
		slog.Error("issue updating subject mapping", slog.String("error", err.Error()))
		return &acsev1.UpdateSubjectMappingResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &acsev1.UpdateSubjectMappingResponse{}, nil
}

func (s SubjectEncoding) DeleteSubjectMapping(ctx context.Context, req *acsev1.DeleteSubjectMappingRequest) (*acsev1.DeleteSubjectMappingResponse, error) {
	if err := s.dbClient.DeleteResource(req.Id, commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String()); err != nil {
		slog.Error("issue deleting resource mapping", slog.String("error", err.Error()))
		return &acsev1.DeleteSubjectMappingResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &acsev1.DeleteSubjectMappingResponse{}, nil
}
