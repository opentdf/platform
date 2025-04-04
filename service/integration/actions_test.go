package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/stretchr/testify/suite"
)

type ActionsSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func (s *ActionsSuite) SetupSuite() {
	slog.Info("setting up db.Actions test suite")
	s.ctx = context.Background()
	c := *Config

	c.DB.Schema = "test_opentdf_actions"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *ActionsSuite) TearDownSuite() {
	slog.Info("tearing down db.Actions test suite")
	s.f.TearDown()
}

func TestActionsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping actions integration tests")
	}
	suite.Run(t, new(ActionsSuite))
}
