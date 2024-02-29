package subjectmapping

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/pkg/serviceregistry"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	sm "github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	policydb "github.com/opentdf/platform/services/policy/db"

	"github.com/opentdf/platform/services"
)

type SubjectMappingService struct {
	sm.UnimplementedSubjectMappingServiceServer
	dbClient *policydb.PolicyDbClient
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "policy",
		ServiceDesc: &subjectmapping.SubjectMappingService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &SubjectMappingService{dbClient: policydb.NewClient(*srp.DBClient)}, func(ctx context.Context, mux *runtime.ServeMux, s any) error {
				return subjectmapping.RegisterSubjectMappingServiceHandlerServer(ctx, mux, s.(subjectmapping.SubjectMappingServiceServer))
			}
		},
	}
}

func (s SubjectMappingService) CreateSubjectMapping(ctx context.Context,
	req *sm.CreateSubjectMappingRequest,
) (*sm.CreateSubjectMappingResponse, error) {
	rsp := &sm.CreateSubjectMappingResponse{}
	slog.Debug("creating subject mapping")

	mappings, err := s.dbClient.CreateSubjectMapping(context.Background(), req.SubjectMapping)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("subjectMapping", req.String()))
	}
	rsp.SubjectMapping = mappings

	return rsp, nil
}

func (s SubjectMappingService) ListSubjectMappings(ctx context.Context,
	req *sm.ListSubjectMappingsRequest,
) (*sm.ListSubjectMappingsResponse, error) {
	rsp := &sm.ListSubjectMappingsResponse{}

	mappings, err := s.dbClient.ListSubjectMappings(ctx)
	if err != nil {
		return nil, services.HandleError(err, services.ErrListRetrievalFailed)
	}

	rsp.SubjectMappings = mappings

	return rsp, nil
}

func (s SubjectMappingService) GetSubjectMapping(ctx context.Context,
	req *sm.GetSubjectMappingRequest,
) (*sm.GetSubjectMappingResponse, error) {
	rsp := &sm.GetSubjectMappingResponse{}

	mapping, err := s.dbClient.GetSubjectMapping(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("id", req.Id))
	}

	rsp.SubjectMapping = mapping

	return rsp, nil
}

func (s SubjectMappingService) UpdateSubjectMapping(ctx context.Context,
	req *sm.UpdateSubjectMappingRequest,
) (*sm.UpdateSubjectMappingResponse, error) {
	rsp := &sm.UpdateSubjectMappingResponse{}

	mapping, err := s.dbClient.UpdateSubjectMapping(ctx, req.Id, req.SubjectMapping)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("id", req.Id), slog.String("subjectMapping", req.String()))
	}

	rsp.SubjectMapping = mapping

	return rsp, nil
}

func (s SubjectMappingService) DeleteSubjectMapping(ctx context.Context,
	req *sm.DeleteSubjectMappingRequest,
) (*sm.DeleteSubjectMappingResponse, error) {
	rsp := &sm.DeleteSubjectMappingResponse{}

	mapping, err := s.dbClient.DeleteSubjectMapping(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrDeletionFailed, slog.String("id", req.Id))
	}

	rsp.SubjectMapping = mapping

	return rsp, nil
}

func (s SubjectMappingService) GetSubjectSet(ctx context.Context, req *sm.GetSubjectSetRequest) (*sm.GetSubjectSetResponse, error) {
	// TODO replace mock below with database connection, add fixture
	slog.DebugContext(ctx, "GetSubjectSet", "id", req.Id)
	ssr := sm.GetSubjectSetResponse{
		SubjectSet: &sm.SubjectSet{
			Id:              req.Id,
			ConditionGroups: make([]*sm.ConditionGroup, 0),
		},
	}
	var cg = sm.ConditionGroup{
		BooleanType: sm.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
		Conditions: []*sm.Condition{
			{
				SubjectAttribute: "https://example.com/attr/attr1/value/value1",
				Operator:         sm.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
				SubjectValues:    []string{"ec11"},
			},
		},
	}
	ssr.SubjectSet.ConditionGroups = append(ssr.SubjectSet.ConditionGroups, &cg)
	return &ssr, nil
}
