package subjectmapping

import (
	"context"
	"log/slog"

	sm "github.com/arkavo-org/opentdf-platform/protocol/go/policy/subjectmapping"
	"github.com/arkavo-org/opentdf-platform/service/internal/db"
	"github.com/arkavo-org/opentdf-platform/service/pkg/serviceregistry"
	policydb "github.com/arkavo-org/opentdf-platform/service/policy/db"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

type SubjectMappingService struct {
	sm.UnimplementedSubjectMappingServiceServer
	dbClient *policydb.PolicyDBClient
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "policy",
		ServiceDesc: &sm.SubjectMappingService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &SubjectMappingService{dbClient: policydb.NewClient(*srp.DBClient)}, func(ctx context.Context, mux *runtime.ServeMux, s any) error {
				return sm.RegisterSubjectMappingServiceHandlerServer(ctx, mux, s.(sm.SubjectMappingServiceServer))
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
	slog.Debug("creating subject mapping")

	sm, err := s.dbClient.CreateSubjectMapping(context.Background(), req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("subjectMapping", req.String()))
	}

	rsp.SubjectMapping = sm
	return rsp, nil
}

func (s SubjectMappingService) ListSubjectMappings(ctx context.Context,
	req *sm.ListSubjectMappingsRequest,
) (*sm.ListSubjectMappingsResponse, error) {
	rsp := &sm.ListSubjectMappingsResponse{}
	slog.Debug("listing subject mappings")

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
	slog.Debug("getting subject mapping", slog.String("id", req.GetId()))

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
	slog.Debug("updating subject mapping", slog.String("subjectMapping", req.String()))

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
	slog.Debug("deleting subject mapping", slog.String("id", req.GetId()))

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
	slog.Debug("matching subject mappings", slog.Any("subjectProperties", req.GetSubjectProperties()))

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
	slog.Debug("getting subject condition set", slog.String("id", req.GetId()))

	conditionSet, err := s.dbClient.GetSubjectConditionSet(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	rsp.SubjectConditionSet = conditionSet
	return rsp, nil
}

func (s SubjectMappingService) ListSubjectConditionSets(ctx context.Context,
	req *sm.ListSubjectConditionSetsRequest,
) (*sm.ListSubjectConditionSetsResponse, error) {
	rsp := &sm.ListSubjectConditionSetsResponse{}
	slog.Debug("listing subject condition sets")

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
	slog.Debug("creating subject condition set", slog.String("subjectConditionSet", req.String()))

	conditionSet, err := s.dbClient.CreateSubjectConditionSet(context.Background(), req.GetSubjectConditionSet())
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
	slog.Debug("updating subject condition set", slog.String("subjectConditionSet", req.String()))

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
	slog.Debug("deleting subject condition set", slog.String("id", req.GetId()))

	conditionSet, err := s.dbClient.DeleteSubjectConditionSet(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}

	rsp.SubjectConditionSet = conditionSet
	return rsp, nil
}
