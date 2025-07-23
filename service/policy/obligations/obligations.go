package obligations

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/obligations/obligationsconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type ObligationsService struct { //nolint:revive // ObligationsService is a valid name
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func OnConfigUpdate(s *ObligationsService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		s.config = sharedCfg
		s.dbClient = policydb.NewClient(s.dbClient.Client, s.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))

		s.logger.Info("obligations service config reloaded")

		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[obligationsconnect.ObligationsServiceHandler] {
	service := new(ObligationsService)
	onUpdateConfigHook := OnConfigUpdate(service)

	return &serviceregistry.Service[obligationsconnect.ObligationsServiceHandler]{
		Close: service.Close,
		ServiceOptions: serviceregistry.ServiceOptions[obligationsconnect.ObligationsServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &obligations.ObligationsService_ServiceDesc,
			ConnectRPCFunc: obligationsconnect.NewObligationsServiceHandler,
			OnConfigUpdate: onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (obligationsconnect.ObligationsServiceHandler, serviceregistry.HandlerServer) {
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
func (s *ObligationsService) IsReady(ctx context.Context) error {
	s.logger.TraceContext(ctx, "checking readiness of obligations service")
	if err := s.dbClient.SQLDB.PingContext(ctx); err != nil {
		return err
	}

	return nil
}

// Close gracefully shuts down the service, closing the database client.
func (s *ObligationsService) Close() {
	s.logger.Info("gracefully shutting down obligations service")
	s.dbClient.Close()
}

func (s *ObligationsService) ListObligations(ctx context.Context, req *obligations.ListObligationsRequest) (*obligations.ListObligationsResponse, error) {
	// TODO: Implement ListObligations logic
	return &obligations.ListObligationsResponse{}, nil
}

func (s *ObligationsService) CreateObligation(ctx context.Context, req *obligations.CreateObligationRequest) (*obligations.CreateObligationResponse, error) {
	// TODO: Implement CreateObligation logic
	return &obligations.CreateObligationResponse{}, nil
}

func (s *ObligationsService) GetObligation(ctx context.Context, req *obligations.GetObligationRequest) (*obligations.GetObligationResponse, error) {
	// TODO: Implement GetObligation logic
	return &obligations.GetObligationResponse{}, nil
}

func (s *ObligationsService) UpdateObligation(ctx context.Context, req *obligations.UpdateObligationRequest) (*obligations.UpdateObligationResponse, error) {
	// TODO: Implement UpdateObligation logic
	return &obligations.UpdateObligationResponse{}, nil
}

func (s *ObligationsService) DeleteObligation(ctx context.Context, req *obligations.DeleteObligationRequest) (*obligations.DeleteObligationResponse, error) {
	// TODO: Implement DeleteObligation logic
	return &obligations.DeleteObligationResponse{}, nil
}

func (s *ObligationsService) ListObligationValues(ctx context.Context, req *obligations.ListObligationValuesRequest) (*obligations.ListObligationValuesResponse, error) {
	// TODO: Implement ListObligationValues logic
	return &obligations.ListObligationValuesResponse{}, nil
}

func (s *ObligationsService) CreateObligationValue(ctx context.Context, req *obligations.CreateObligationValueRequest) (*obligations.CreateObligationValueResponse, error) {
	// TODO: Implement CreateObligationValue logic
	return &obligations.CreateObligationValueResponse{}, nil
}

func (s *ObligationsService) GetObligationValue(ctx context.Context, req *obligations.GetObligationValueRequest) (*obligations.GetObligationValueResponse, error) {
	// TODO: Implement GetObligationValue logic
	return &obligations.GetObligationValueResponse{}, nil
}

func (s *ObligationsService) UpdateObligationValue(ctx context.Context, req *obligations.UpdateObligationValueRequest) (*obligations.UpdateObligationValueResponse, error) {
	// TODO: Implement UpdateObligationValue logic
	return &obligations.UpdateObligationValueResponse{}, nil
}

func (s *ObligationsService) DeleteObligationValue(ctx context.Context, req *obligations.DeleteObligationValueRequest) (*obligations.DeleteObligationValueResponse, error) {
	// TODO: Implement DeleteObligationValue logic
	return &obligations.DeleteObligationValueResponse{}, nil
}

func (s *ObligationsService) AddObligationTrigger(ctx context.Context, req *obligations.AddObligationTriggerRequest) (*obligations.AddObligationTriggerResponse, error) {
	// TODO: Implement AddObligationTrigger logic
	return &obligations.AddObligationTriggerResponse{}, nil
}

func (s *ObligationsService) RemoveObligationTrigger(ctx context.Context, req *obligations.RemoveObligationTriggerRequest) (*obligations.RemoveObligationTriggerResponse, error) {
	// TODO: Implement RemoveObligationTrigger logic
	return &obligations.RemoveObligationTriggerResponse{}, nil
}

func (s *ObligationsService) AddObligationFulfiller(ctx context.Context, req *obligations.AddObligationFulfillerRequest) (*obligations.AddObligationFulfillerResponse, error) {
	// TODO: Implement AddObligationFulfiller logic
	return &obligations.AddObligationFulfillerResponse{}, nil
}

func (s *ObligationsService) RemoveObligationFulfiller(ctx context.Context, req *obligations.RemoveObligationFulfillerRequest) (*obligations.RemoveObligationFulfillerResponse, error) {
	// TODO: Implement RemoveObligationFulfiller logic
	return &obligations.RemoveObligationFulfillerResponse{}, nil
}
