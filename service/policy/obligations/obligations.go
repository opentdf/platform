package obligations

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/obligations/obligationsconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type Service struct {
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func OnConfigUpdate(s *Service) serviceregistry.OnConfigUpdateHook {
	return func(ctx context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		s.config = sharedCfg
		s.dbClient = policydb.NewClient(s.dbClient.Client, s.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))

		s.logger.InfoContext(ctx, "obligations service config reloaded")

		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[obligationsconnect.ServiceHandler] {
	service := new(Service)
	onUpdateConfigHook := OnConfigUpdate(service)

	return &serviceregistry.Service[obligationsconnect.ServiceHandler]{
		Close: service.Close,
		ServiceOptions: serviceregistry.ServiceOptions[obligationsconnect.ServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &obligations.Service_ServiceDesc,
			ConnectRPCFunc: obligationsconnect.NewServiceHandler,
			OnConfigUpdate: onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (obligationsconnect.ServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting obligations service policy config", slog.String("error", err.Error()))
					panic(err)
				}

				service.logger = logger
				service.dbClient = policydb.NewClient(srp.DBClient, logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))
				service.config = cfg
				return service, nil
			},
		},
	}
}

// IsReady checks if the service is ready to serve requests.
// Without a database connection, the service is not ready.
func (s *Service) IsReady(ctx context.Context) error {
	s.logger.TraceContext(ctx, "checking readiness of obligations service")
	if err := s.dbClient.SQLDB.PingContext(ctx); err != nil {
		return err
	}

	return nil
}

// Close gracefully shuts down the service, closing the database client.
func (s *Service) Close() {
	s.logger.Info("gracefully shutting down obligations service")
	s.dbClient.Close()
}

func (s *Service) ListObligations(ctx context.Context, req *connect.Request[obligations.ListObligationsRequest]) (*connect.Response[obligations.ListObligationsResponse], error) {
	s.logger.DebugContext(ctx, "listing obligations")

	os, pr, err := s.dbClient.ListObligations(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextListRetrievalFailed)
	}
	rsp := &obligations.ListObligationsResponse{
		Obligations: os,
		Pagination:  pr,
	}
	return connect.NewResponse(rsp), nil
}

func (s *Service) CreateObligation(ctx context.Context, req *connect.Request[obligations.CreateObligationRequest]) (*connect.Response[obligations.CreateObligationResponse], error) {
	rsp := &obligations.CreateObligationResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeObligationDefinition,
	}

	s.logger.DebugContext(ctx, "creating obligation", slog.String("name", req.Msg.GetName()))

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		obl, err := txClient.CreateObligation(ctx, req.Msg)
		if err != nil {
			return err
		}

		auditParams.ObjectID = obl.GetId()
		auditParams.Original = obl
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Obligation = obl
		return nil
	})
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("obligation", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *Service) GetObligation(ctx context.Context, req *connect.Request[obligations.GetObligationRequest]) (*connect.Response[obligations.GetObligationResponse], error) {
	s.logger.DebugContext(ctx, "getting obligation", slog.Any("identifier", req.Msg.GetIdentifier()))

	obl, err := s.dbClient.GetObligation(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("identifier", req.Msg.GetIdentifier()))
	}
	rsp := &obligations.GetObligationResponse{Obligation: obl}
	return connect.NewResponse(rsp), nil
}

func (s *Service) GetObligationsByFQNs(ctx context.Context, req *connect.Request[obligations.GetObligationsByFQNsRequest]) (*connect.Response[obligations.GetObligationsByFQNsResponse], error) {
	s.logger.DebugContext(ctx, "getting obligations")

	os, err := s.dbClient.GetObligationsByFQNs(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed)
	}
	obls := make(map[string]*policy.Obligation)
	for _, obl := range os {
		obls[policydb.BuildOblFQN(obl.GetNamespace().GetFqn(), obl.GetName())] = obl
	}
	rsp := &obligations.GetObligationsByFQNsResponse{FqnObligationMap: obls}
	return connect.NewResponse(rsp), nil
}

func (s *Service) UpdateObligation(ctx context.Context, req *connect.Request[obligations.UpdateObligationRequest]) (*connect.Response[obligations.UpdateObligationResponse], error) {
	id := req.Msg.GetId()

	rsp := &obligations.UpdateObligationResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeObligationDefinition,
		ObjectID:   id,
	}

	s.logger.DebugContext(ctx, "updating obligation", slog.String("id", id))

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetObligation(ctx, &obligations.GetObligationRequest{
			Identifier: &obligations.GetObligationRequest_Id{
				Id: id,
			},
		})
		if err != nil {
			return err
		}

		updated, err := txClient.UpdateObligation(ctx, req.Msg)
		if err != nil {
			return err
		}

		auditParams.Original = original
		auditParams.Updated = updated
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Obligation = updated
		return nil
	})
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("obligation", req.Msg.String()))
	}
	return connect.NewResponse(rsp), nil
}

func (s *Service) DeleteObligation(ctx context.Context, req *connect.Request[obligations.DeleteObligationRequest]) (*connect.Response[obligations.DeleteObligationResponse], error) {
	id := req.Msg.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeObligationDefinition,
		ObjectID:   id,
	}

	s.logger.DebugContext(ctx, "deleting obligation", slog.String("id", id))

	deleted, err := s.dbClient.DeleteObligation(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("obligation", req.Msg.String()))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp := &obligations.DeleteObligationResponse{Obligation: deleted}
	return connect.NewResponse(rsp), nil
}

func (s *Service) CreateObligationValue(ctx context.Context, req *connect.Request[obligations.CreateObligationValueRequest]) (*connect.Response[obligations.CreateObligationValueResponse], error) {
	rsp := &obligations.CreateObligationValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeObligationValue,
	}

	s.logger.DebugContext(ctx, "creating obligation value", slog.String("value", req.Msg.GetValue()))

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		val, err := txClient.CreateObligationValue(ctx, req.Msg)
		if err != nil {
			return err
		}

		auditParams.ObjectID = val.GetId()
		auditParams.Original = val
		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Value = val
		return nil
	})
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextCreationFailed, slog.String("obligation value", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *Service) GetObligationValue(ctx context.Context, req *connect.Request[obligations.GetObligationValueRequest]) (*connect.Response[obligations.GetObligationValueResponse], error) {
	s.logger.DebugContext(ctx, "getting obligation value", slog.Any("identifier", req.Msg.GetIdentifier()))

	val, err := s.dbClient.GetObligationValue(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("identifier", req.Msg.GetIdentifier()))
	}
	rsp := &obligations.GetObligationValueResponse{Value: val}
	return connect.NewResponse(rsp), nil
}

func (s *Service) GetObligationValuesByFQNs(_ context.Context, _ *connect.Request[obligations.GetObligationValuesByFQNsRequest]) (*connect.Response[obligations.GetObligationValuesByFQNsResponse], error) {
	// TODO: Implement GetObligationValuesByFQNs logic
	return connect.NewResponse(&obligations.GetObligationValuesByFQNsResponse{}), nil
}

func (s *Service) UpdateObligationValue(_ context.Context, _ *connect.Request[obligations.UpdateObligationValueRequest]) (*connect.Response[obligations.UpdateObligationValueResponse], error) {
	// TODO: Implement UpdateObligationValue logic
	return connect.NewResponse(&obligations.UpdateObligationValueResponse{}), nil
}

func (s *Service) DeleteObligationValue(_ context.Context, _ *connect.Request[obligations.DeleteObligationValueRequest]) (*connect.Response[obligations.DeleteObligationValueResponse], error) {
	// TODO: Implement DeleteObligationValue logic
	return connect.NewResponse(&obligations.DeleteObligationValueResponse{}), nil
}

func (s *Service) AddObligationTrigger(_ context.Context, _ *connect.Request[obligations.AddObligationTriggerRequest]) (*connect.Response[obligations.AddObligationTriggerResponse], error) {
	// TODO: Implement AddObligationTrigger logic
	return connect.NewResponse(&obligations.AddObligationTriggerResponse{}), nil
}

func (s *Service) RemoveObligationTrigger(_ context.Context, _ *connect.Request[obligations.RemoveObligationTriggerRequest]) (*connect.Response[obligations.RemoveObligationTriggerResponse], error) {
	// TODO: Implement RemoveObligationTrigger logic
	return connect.NewResponse(&obligations.RemoveObligationTriggerResponse{}), nil
}

// func (s *Service) AddObligationFulfiller(_ context.Context, _ *connect.Request[obligations.AddObligationFulfillerRequest]) (*connect.Response[obligations.AddObligationFulfillerResponse], error) {
// 	// TODO: Implement AddObligationFulfiller logic
// 	return connect.NewResponse(&obligations.AddObligationFulfillerResponse{}), nil
// }

// func (s *Service) RemoveObligationFulfiller(_ context.Context, _ *connect.Request[obligations.RemoveObligationFulfillerRequest]) (*connect.Response[obligations.RemoveObligationFulfillerResponse], error) {
// 	// TODO: Implement RemoveObligationFulfiller logic
// 	return connect.NewResponse(&obligations.RemoveObligationFulfillerResponse{}), nil
// }
