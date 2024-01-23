package subjectmapping

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/sdk/subjectmapping"

	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SubjectMappingService struct {
	subjectmapping.UnimplementedSubjectMappingServiceServer
	dbClient *db.Client
}

func NewSubjectMappingServer(dbClient *db.Client, grpcServer *grpc.Server,
	grpcInprocess *grpc.Server, mux *runtime.ServeMux) error {
	s := &SubjectMappingService{
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

func (s SubjectMappingService) CreateSubjectMapping(ctx context.Context,
	req *subjectmapping.CreateSubjectMappingRequest) (*subjectmapping.CreateSubjectMappingResponse, error) {
	rsp := &subjectmapping.CreateSubjectMappingResponse{}
	slog.Debug("creating subject mapping")

	mappings, err := s.dbClient.CreateSubjectMapping(context.Background(), req.SubjectMapping)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrCreatingResource)
	}
	rsp.SubjectMapping = mappings

	return rsp, nil
}

func (s SubjectMappingService) ListSubjectMappings(ctx context.Context,
	req *subjectmapping.ListSubjectMappingsRequest) (*subjectmapping.ListSubjectMappingsResponse, error) {
	rsp := &subjectmapping.ListSubjectMappingsResponse{}

	mappings, err := s.dbClient.ListSubjectMappings(ctx)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListingResource)
	}

	rsp.SubjectMappings = mappings

	return rsp, nil
}

func (s SubjectMappingService) GetSubjectMapping(ctx context.Context,
	req *subjectmapping.GetSubjectMappingRequest) (*subjectmapping.GetSubjectMappingResponse, error) {
	rsp := &subjectmapping.GetSubjectMappingResponse{}

	mapping, err := s.dbClient.GetSubjectMapping(ctx, req.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	rsp.SubjectMapping = mapping

	return rsp, nil
}

func (s SubjectMappingService) UpdateSubjectMapping(ctx context.Context,
	req *subjectmapping.UpdateSubjectMappingRequest) (*subjectmapping.UpdateSubjectMappingResponse, error) {
	rsp := &subjectmapping.UpdateSubjectMappingResponse{}

	mapping, err := s.dbClient.UpdateSubjectMapping(ctx, req.Id, req.SubjectMapping)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrUpdatingResource)
	}

	rsp.SubjectMapping = mapping

	return rsp, nil
}

func (s SubjectMappingService) DeleteSubjectMapping(ctx context.Context,
	req *subjectmapping.DeleteSubjectMappingRequest) (*subjectmapping.DeleteSubjectMappingResponse, error) {
	rsp := &subjectmapping.DeleteSubjectMappingResponse{}

	mapping, err := s.dbClient.DeleteSubjectMapping(ctx, req.Id)
	if err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrDeletingResource)
	}

	rsp.SubjectMapping = mapping

	return rsp, nil
}
