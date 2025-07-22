package obligations

import (
	"github.com/opentdf/platform/service/logger"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type ObligationsService struct { //nolint:revive // ObligationsService is a valid name
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

// Close gracefully shuts down the service, closing the database client.
func (s *ObligationsService) Close() {
	s.logger.Info("gracefully shutting down obligations service")
	s.dbClient.Close()
}
