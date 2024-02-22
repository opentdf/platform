package subjectmapping

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/pkg/server"
	"github.com/opentdf/opentdf-v2-poc/sdk/subjectmapping"

	"github.com/opentdf/opentdf-v2-poc/services"
)

type SubjectMappingService struct {
	subjectmapping.UnimplementedSubjectMappingServiceServer
	dbClient *db.Client
}

func init() {
	server.RegisterService("policy", &subjectmapping.SubjectMappingService_ServiceDesc, func(srp server.ServiceRegisterArgs) (any, server.ServiceHandlerServer) {
		return &SubjectMappingService{dbClient: srp.DBClient}, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
			return subjectmapping.RegisterSubjectMappingServiceHandlerServer(ctx, mux, server.(subjectmapping.SubjectMappingServiceServer))
		}
	})
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
