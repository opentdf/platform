package subjectmapping

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/sdk/subjectmapping"

	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc"
)

type SubjectMappingService struct {
	subjectmapping.UnimplementedSubjectMappingServiceServer
	dbClient *db.Client
}

func NewSubjectMappingServer(dbClient *db.Client, grpcServer *grpc.Server,
	grpcInprocess *grpc.Server, mux *runtime.ServeMux,
) error {
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
	req *subjectmapping.CreateSubjectMappingRequest,
) (*subjectmapping.CreateSubjectMappingResponse, error) {
	rsp := &subjectmapping.CreateSubjectMappingResponse{}
	slog.Debug("creating subject mapping")

	mappings, err := s.dbClient.CreateSubjectMapping(context.Background(), req.SubjectMapping)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("subjectMapping", req.SubjectMapping.String()))
	}
	rsp.SubjectMapping = mappings

	return rsp, nil
}

func (s SubjectMappingService) ListSubjectMappings(ctx context.Context,
	req *subjectmapping.ListSubjectMappingsRequest,
) (*subjectmapping.ListSubjectMappingsResponse, error) {
	rsp := &subjectmapping.ListSubjectMappingsResponse{}

	mappings, err := s.dbClient.ListSubjectMappings(ctx)
	if err != nil {
		return nil, services.HandleError(err, services.ErrListRetrievalFailed)
	}

	rsp.SubjectMappings = mappings

	return rsp, nil
}

func (s SubjectMappingService) GetSubjectMapping(ctx context.Context,
	req *subjectmapping.GetSubjectMappingRequest,
) (*subjectmapping.GetSubjectMappingResponse, error) {
	rsp := &subjectmapping.GetSubjectMappingResponse{}

	mapping, err := s.dbClient.GetSubjectMapping(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("id", req.Id))
	}

	rsp.SubjectMapping = mapping

	return rsp, nil
}

func (s SubjectMappingService) UpdateSubjectMapping(ctx context.Context,
	req *subjectmapping.UpdateSubjectMappingRequest,
) (*subjectmapping.UpdateSubjectMappingResponse, error) {
	rsp := &subjectmapping.UpdateSubjectMappingResponse{}

	mapping, err := s.dbClient.UpdateSubjectMapping(ctx, req.Id, req.SubjectMapping)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("id", req.Id), slog.String("subjectMapping", req.SubjectMapping.String()))
	}

	rsp.SubjectMapping = mapping

	return rsp, nil
}

func (s SubjectMappingService) DeleteSubjectMapping(ctx context.Context,
	req *subjectmapping.DeleteSubjectMappingRequest,
) (*subjectmapping.DeleteSubjectMappingResponse, error) {
	rsp := &subjectmapping.DeleteSubjectMappingResponse{}

	mapping, err := s.dbClient.DeleteSubjectMapping(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrDeletionFailed, slog.String("id", req.Id))
	}

	rsp.SubjectMapping = mapping

	return rsp, nil
}
