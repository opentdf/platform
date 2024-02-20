package policy

import (
	"log/slog"

	"github.com/opentdf/opentdf-v2-poc/internal/db"
	policydb "github.com/opentdf/opentdf-v2-poc/services/policy/db"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/suite"
)

type NamespacesSuite struct {
	suite.Suite
	mock            pgxmock.PgxPoolIface
	namespaceServer *NamespacesService
}

func (suite *NamespacesSuite) SetupTest() {
	mock, err := pgxmock.NewPool()
	if err != nil {
		slog.Error("failed to create mock database connection", slog.String("error", err.Error()))
	}
	suite.mock = mock
	dbClient := &db.Client{
		Pgx: mock,
	}
	suite.namespaceServer = &NamespacesService{
		dbClient: policydb.WithPolicyDbClient(*dbClient),
	}
}
