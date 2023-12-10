package acse

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	acsev1 "github.com/opentdf/opentdf-v2-poc/gen/acse/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	subjectMappingPolicyType = "subject_mapping"
)

type acseServer struct {
	acsev1.UnimplementedSubjectEncodingServiceServer
	dbClient *db.Client
}

func NewServer(dbClient *db.Client, grpcServer *grpc.Server, grpcInprocess *grpc.Server, mux *runtime.ServeMux) error {
	as := &acseServer{
		dbClient: dbClient,
	}
	acsev1.RegisterSubjectEncodingServiceServer(grpcServer, as)
	if grpcInprocess != nil {
		acsev1.RegisterSubjectEncodingServiceServer(grpcInprocess, as)
	}
	err := acsev1.RegisterSubjectEncodingServiceHandlerServer(context.Background(), mux, as)
	return err
}

func (s *acseServer) CreateSubjectMapping(ctx context.Context, req *acsev1.CreateSubjectMappingRequest) (*acsev1.CreateSubjectMappingResponse, error) {
	slog.Debug("creating subject mapping")
	var (
		err error
	)
	jsonResource, err := protojson.Marshal(req.SubjectMapping)
	if err != nil {
		return &acsev1.CreateSubjectMappingResponse{}, status.Error(codes.Internal, err.Error())
	}
	err = s.dbClient.CreateResource(req.SubjectMapping.Descriptor_, jsonResource, subjectMappingPolicyType)
	if err != nil {
		slog.Error("issue creating resource mapping", slog.String("error", err.Error()))
		return &acsev1.CreateSubjectMappingResponse{}, status.Error(codes.Internal, err.Error())
	}

	return &acsev1.CreateSubjectMappingResponse{}, nil
}

func (s *acseServer) ListSubjectMappings(ctx context.Context, req *acsev1.ListSubjectMappingsRequest) (*acsev1.ListSubjectMappingsResponse, error) {
	mappings := &acsev1.ListSubjectMappingsResponse{}

	rows, err := s.dbClient.ListResources(subjectMappingPolicyType)
	if err != nil {
		slog.Error("issue listing subject mappings", slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, err.Error())
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id       string
			mapping  = new(acsev1.SubjectMapping)
			bMapping []byte
		)
		err = rows.Scan(&id, &bMapping)
		if err != nil {
			slog.Error("issue listing subject mappings", slog.String("error", err.Error()))
			return mappings, status.Error(codes.Internal, err.Error())
		}
		err = protojson.Unmarshal(bMapping, mapping)
		if err != nil {
			slog.Error("issue unmarshalling subject mappings", slog.String("error", err.Error()))
			return mappings, status.Error(codes.Internal, err.Error())
		}
		mapping.Descriptor_.Id = id
		mappings.SubjectMappings = append(mappings.SubjectMappings, mapping)
	}

	return mappings, nil
}

func (s *acseServer) GetSubjectMapping(ctx context.Context, req *acsev1.GetSubjectMappingRequest) (*acsev1.GetSubjectMappingResponse, error) {
	var (
		mapping = &acsev1.GetSubjectMappingResponse{
			SubjectMapping: new(acsev1.SubjectMapping),
		}
		bMapping []byte
		err      error
		id       string
	)

	row := s.dbClient.GetResource(req.Id, subjectMappingPolicyType)
	if err != nil {
		slog.Error("issue getting subject mapping", slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, err.Error())
	}

	err = row.Scan(&id, &bMapping)
	if err != nil {
		if err == pgx.ErrNoRows {
			slog.Info("subject mapping not found", slog.String("id", req.Id))
			return mapping, status.Error(codes.NotFound, "resource mapping not found")
		}
		slog.Error("issue getting subject mapping", slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, err.Error())
	}
	err = protojson.Unmarshal(bMapping, mapping.SubjectMapping)
	if err != nil {
		slog.Error("issue unmarshalling subject mapping", slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, err.Error())
	}
	mapping.SubjectMapping.Descriptor_.Id = id

	return mapping, nil
}

func (s *acseServer) UpdateSubjectMapping(ctx context.Context, req *acsev1.UpdateSubjectMappingRequest) (*acsev1.UpdateSubjectMappingResponse, error) {
	jsonAttr, err := protojson.Marshal(req.SubjectMapping)
	if err != nil {
		slog.Error("issue marshalling subject mapping", slog.String("error", err.Error()))
		return &acsev1.UpdateSubjectMappingResponse{}, status.Error(codes.Internal, err.Error())
	}
	err = s.dbClient.UpdateResource(req.SubjectMapping.Descriptor_, jsonAttr, subjectMappingPolicyType)
	if err != nil {
		slog.Error("issue updating subject mapping", slog.String("error", err.Error()))
		return &acsev1.UpdateSubjectMappingResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &acsev1.UpdateSubjectMappingResponse{}, nil
}

func (s *acseServer) DeleteSubjectMapping(ctx context.Context, req *acsev1.DeleteSubjectMappingRequest) (*acsev1.DeleteSubjectMappingResponse, error) {
	if err := s.dbClient.DeleteResource(req.Id, subjectMappingPolicyType); err != nil {
		slog.Error("issue deleting resource mapping", slog.String("error", err.Error()))
		return &acsev1.DeleteSubjectMappingResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &acsev1.DeleteSubjectMappingResponse{}, nil
}
