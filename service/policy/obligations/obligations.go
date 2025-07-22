package obligations

import (
	"context"

	"github.com/opentdf/platform/service/logger"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type ObligationsService struct { //nolint:revive // ObligationsService is a valid name
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
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
