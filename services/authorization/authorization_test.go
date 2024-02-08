package authorization

import (
	"log/slog"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/suite"
)

type AuthorizationSuite struct {
	suite.Suite
	mock            pgxmock.PgxPoolIface
	authorizationServer *AuthorizationService
}

func (suite *AuthorizationSuite) SetupTest() {
	mock, err := pgxmock.NewPool()
	if err != nil {
		slog.Error("failed to create mock database connection", slog.String("error", err.Error()))
	}
	suite.mock = mock
	suite.authorizationServer = &AuthorizationService{}
}

func (suite *AuthorizationSuite) TearDownSuite() {
	suite.mock.Close()
}

func TestAuthorizationSuite(t *testing.T) {
	suite.Run(t, new(AuthorizationSuite))
}