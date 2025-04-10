package nondataresources

import (
	"context"
	"log/slog"

	"github.com/opentdf/platform/protocol/go/policy/nondataresources"
	"github.com/opentdf/platform/protocol/go/policy/nondataresources/nondataresourcesconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type NonDataResourcesService struct { //nolint:revive // NonDataResourcesService is a valid name
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[nondataresourcesconnect.NonDataResourcesServiceHandler] {
	return &serviceregistry.Service[nondataresourcesconnect.NonDataResourcesServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[nondataresourcesconnect.NonDataResourcesServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &nondataresources.NonDataResourcesService_ServiceDesc,
			ConnectRPCFunc: nondataresourcesconnect.NewNonDataResourcesServiceHandler,
			// todo: why does this not compile?
			// GRPCGatewayFunc: nondataresources.RegisterNonDataResourcesServiceServer,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (nondataresourcesconnect.NonDataResourcesServiceHandler, serviceregistry.HandlerServer) {
				cfg := policyconfig.GetSharedPolicyConfig(srp)
				s := &NonDataResourcesService{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault)),
					logger:   srp.Logger,
					config:   cfg,
				}

				if err := srp.RegisterReadinessCheck("policy", s.IsReady); err != nil {
					srp.Logger.Error("failed to register policy readiness check", slog.String("error", err.Error()))
				}

				return s, nil
			},
		},
	}
}

func (s NonDataResourcesService) IsReady(ctx context.Context) error {
	s.logger.TraceContext(ctx, "checking readiness of nondataresources service")
	if err := s.dbClient.SQLDB.PingContext(ctx); err != nil {
		return err
	}

	return nil
}
