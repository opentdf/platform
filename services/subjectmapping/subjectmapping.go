package subjectmapping

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
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
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("attributeValueId", req.SubjectMapping.AttributeValueId))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		if errors.Is(err, db.ErrEnumValueInvalid) {
			slog.Error(services.ErrEnumValueInvalid, slog.String("error", err.Error()), slog.String("operator", req.SubjectMapping.Operator.String()))
			return nil, status.Error(codes.InvalidArgument, services.ErrEnumValueInvalid)
		}
		slog.Error(services.ErrCreationFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrCreationFailed)
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
		slog.Error(services.ErrListRetrievalFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListRetrievalFailed)
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
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGetRetrievalFailed, slog.String("error", err.Error()), slog.String("id", req.Id))
		return nil, status.Error(codes.Internal, services.ErrGetRetrievalFailed)
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
		if errors.Is(err, db.ErrForeignKeyViolation) {
			slog.Error(services.ErrRelationInvalid, slog.String("error", err.Error()), slog.String("attributeValueId", req.SubjectMapping.AttributeValueId))
			return nil, status.Error(codes.InvalidArgument, services.ErrRelationInvalid)
		}
		if errors.Is(err, db.ErrEnumValueInvalid) {
			slog.Error(services.ErrEnumValueInvalid, slog.String("error", err.Error()), slog.String("operator", req.SubjectMapping.Operator.String()))
			return nil, status.Error(codes.InvalidArgument, services.ErrEnumValueInvalid)
		}
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrUpdateFailed, slog.String("error", err.Error()), slog.String("id", req.Id), slog.String("subject mapping", req.SubjectMapping.String()))
		return nil, status.Error(codes.Internal, services.ErrUpdateFailed)
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
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrDeletionFailed, slog.String("error", err.Error()), slog.String("id", req.Id))
		return nil, status.Error(codes.Internal, services.ErrDeletionFailed)
	}

	rsp.SubjectMapping = mapping

	return rsp, nil
}
