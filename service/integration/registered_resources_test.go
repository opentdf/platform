package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/stretchr/testify/suite"
)

type RegisteredResourcesSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func (s *RegisteredResourcesSuite) SetupSuite() {
	slog.Info("setting up db.RegisteredResources test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_registered_resources"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *RegisteredResourcesSuite) TearDownSuite() {
	slog.Info("tearing down db.RegisteredResources test suite")
	s.f.TearDown()
}

func TestRegisteredResourcesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping registered resources integration test")
	}
	suite.Run(t, new(RegisteredResourcesSuite))
}

///
/// Registered Resources
///

// CREATE TESTS HERE

func (s *RegisteredResourcesSuite) Test_GetRegisteredResourceWithValues_Succeeds() {
	// todo: move to a variable
	testID := "f3a1b2c4-5d6e-7f89-0a1b-2c3d4e5f6789"

	rsp, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest_ResourceId{
		ResourceId: testID,
	})
	s.Require().NoError(err)
	s.NotNil(rsp)

	s.Require().Equal(len(rsp.Values), 2)
}
