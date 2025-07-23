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
