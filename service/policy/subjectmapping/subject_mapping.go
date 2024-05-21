package subjectmapping

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type SubjectMappingService struct { //nolint:revive // SubjectMappingService is a valid name for this struct
	sm.UnimplementedSubjectMappingServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &sm.SubjectMappingService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &SubjectMappingService{dbClient: policydb.NewClient(srp.DBClient), logger: srp.Logger}, func(ctx context.Context, mux *runtime.ServeMux, s any) error {
				server, ok := s.(sm.SubjectMappingServiceServer)
				if !ok {
					return fmt.Errorf("failed to assert server as sm.SubjectMappingServiceServer")
				}
				return sm.RegisterSubjectMappingServiceHandlerServer(ctx, mux, server)
			}
		},
	}
}

/* ---------------------------------------------------
 * ----------------- SubjectMappings -----------------
 * --------------------------------------------------*/

func (s SubjectMappingService) CreateSubjectMapping(ctx context.Context,
	req *sm.CreateSubjectMappingRequest,
) (*sm.CreateSubjectMappingResponse, error) {
	rsp := &sm.CreateSubjectMappingResponse{}
	s.logger.Debug("creating subject mapping")

	sm, err := s.dbClient.CreateSubjectMapping(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("subjectMapping", req.String()))
	}

	rsp.SubjectMapping = sm
	return rsp, nil
}

func (s SubjectMappingService) ListSubjectMappings(ctx context.Context,
	_ *sm.ListSubjectMappingsRequest,
) (*sm.ListSubjectMappingsResponse, error) {
	rsp := &sm.ListSubjectMappingsResponse{}
	s.logger.Debug("listing subject mappings")

	mappings, err := s.dbClient.ListSubjectMappings(ctx)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	rsp.SubjectMappings = mappings
	return rsp, nil
}

func (s SubjectMappingService) GetSubjectMapping(ctx context.Context,
	req *sm.GetSubjectMappingRequest,
) (*sm.GetSubjectMappingResponse, error) {
	rsp := &sm.GetSubjectMappingResponse{}
	s.logger.Debug("getting subject mapping", slog.String("id", req.GetId()))

	mapping, err := s.dbClient.GetSubjectMapping(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	rsp.SubjectMapping = mapping
	return rsp, nil
}

func (s SubjectMappingService) UpdateSubjectMapping(ctx context.Context,
	req *sm.UpdateSubjectMappingRequest,
) (*sm.UpdateSubjectMappingResponse, error) {
	rsp := &sm.UpdateSubjectMappingResponse{}
	s.logger.Debug("updating subject mapping", slog.String("subjectMapping", req.String()))

	sm, err := s.dbClient.UpdateSubjectMapping(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("subjectMapping fields", req.String()))
	}

	rsp.SubjectMapping = sm
	return rsp, nil
}

func (s SubjectMappingService) DeleteSubjectMapping(ctx context.Context,
	req *sm.DeleteSubjectMappingRequest,
) (*sm.DeleteSubjectMappingResponse, error) {
	rsp := &sm.DeleteSubjectMappingResponse{}
	s.logger.Debug("deleting subject mapping", slog.String("id", req.GetId()))

	sm, err := s.dbClient.DeleteSubjectMapping(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}

	rsp.SubjectMapping = sm
	return rsp, nil
}

func (s SubjectMappingService) MatchSubjectMappings(ctx context.Context,
	req *sm.MatchSubjectMappingsRequest,
) (*sm.MatchSubjectMappingsResponse, error) {
	rsp := &sm.MatchSubjectMappingsResponse{}
	s.logger.Debug("matching subject mappings", slog.Any("subjectProperties", req.GetSubjectProperties()))

	smList, err := s.dbClient.GetMatchedSubjectMappings(ctx, req.GetSubjectProperties())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.Any("subjectProperties", req.GetSubjectProperties()))
	}

	rsp.SubjectMappings = smList
	return rsp, nil
}

/* --------------------------------------------------------
 * ----------------- SubjectConditionSets -----------------
 * -------------------------------------------------------*/

func (s SubjectMappingService) GetSubjectConditionSet(ctx context.Context,
	req *sm.GetSubjectConditionSetRequest,
) (*sm.GetSubjectConditionSetResponse, error) {
	rsp := &sm.GetSubjectConditionSetResponse{}
	s.logger.Debug("getting subject condition set", slog.String("id", req.GetId()))

	conditionSet, err := s.dbClient.GetSubjectConditionSet(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	rsp.SubjectConditionSet = conditionSet
	return rsp, nil
}

func (s SubjectMappingService) ListSubjectConditionSets(ctx context.Context,
	_ *sm.ListSubjectConditionSetsRequest,
) (*sm.ListSubjectConditionSetsResponse, error) {
	rsp := &sm.ListSubjectConditionSetsResponse{}
	s.logger.Debug("listing subject condition sets")

	conditionSets, err := s.dbClient.ListSubjectConditionSets(ctx)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	rsp.SubjectConditionSets = conditionSets
	return rsp, nil
}

func (s SubjectMappingService) CreateSubjectConditionSet(ctx context.Context,
	req *sm.CreateSubjectConditionSetRequest,
) (*sm.CreateSubjectConditionSetResponse, error) {
	rsp := &sm.CreateSubjectConditionSetResponse{}
	s.logger.Debug("creating subject condition set", slog.String("subjectConditionSet", req.String()))

	conditionSet, err := s.dbClient.CreateSubjectConditionSet(ctx, req.GetSubjectConditionSet())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("subjectConditionSet", req.String()))
	}
	rsp.SubjectConditionSet = conditionSet

	return rsp, nil
}

func (s SubjectMappingService) UpdateSubjectConditionSet(ctx context.Context,
	req *sm.UpdateSubjectConditionSetRequest,
) (*sm.UpdateSubjectConditionSetResponse, error) {
	rsp := &sm.UpdateSubjectConditionSetResponse{}
	s.logger.Debug("updating subject condition set", slog.String("subjectConditionSet", req.String()))

	conditionSet, err := s.dbClient.UpdateSubjectConditionSet(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("subjectConditionSet fields", req.String()))
	}

	rsp.SubjectConditionSet = conditionSet
	return rsp, nil
}

func (s SubjectMappingService) DeleteSubjectConditionSet(ctx context.Context,
	req *sm.DeleteSubjectConditionSetRequest,
) (*sm.DeleteSubjectConditionSetResponse, error) {
	rsp := &sm.DeleteSubjectConditionSetResponse{}
	s.logger.Debug("deleting subject condition set", slog.String("id", req.GetId()))

	conditionSet, err := s.dbClient.DeleteSubjectConditionSet(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}

	rsp.SubjectConditionSet = conditionSet
	return rsp, nil
}
