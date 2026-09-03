package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
)

type PolicyObjectCountsSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func (s *PolicyObjectCountsSuite) SetupSuite() {
	slog.Info("setting up db.PolicyObjectCounts test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_policy_object_counts"
	s.db = fixtures.NewDBInterface(s.ctx, c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision(s.ctx)
}

func (s *PolicyObjectCountsSuite) TearDownSuite() {
	slog.Info("tearing down db.PolicyObjectCounts test suite")
	s.f.TearDown(s.ctx)
}

func (s *PolicyObjectCountsSuite) Test_NamespaceScopedCounts_UnknownNamespaceFqn_Fails() {
	const unknownNamespaceFQN = "https://unknown.example.com"

	_, _, err := s.db.PolicyClient.GetResourceMappingGroupCount(s.ctx, "", unknownNamespaceFQN)
	s.Require().ErrorIs(err, db.ErrNotFound)

	_, err = s.db.PolicyClient.CountSubjectConditionSets(s.ctx, "", unknownNamespaceFQN)
	s.Require().ErrorIs(err, db.ErrNotFound)

	_, err = s.db.PolicyClient.CountActions(s.ctx, "", unknownNamespaceFQN)
	s.Require().ErrorIs(err, db.ErrNotFound)

	_, _, err = s.db.PolicyClient.CountActionsWithMissingNames(s.ctx, "", unknownNamespaceFQN, []string{"read"})
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *PolicyObjectCountsSuite) Test_ParentNamespaceLookups_UnknownIds_Fails() {
	unknownID := uuid.NewString()

	_, err := s.db.PolicyClient.GetAttributeDefinitionNamespaceID(s.ctx, unknownID)
	s.Require().ErrorIs(err, db.ErrNotFound)

	_, err = s.db.PolicyClient.GetAttributeValueNamespaceID(s.ctx, &common.IdFqnIdentifier{Id: unknownID})
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func TestPolicyObjectCountsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping policy object counts integration tests")
	}
	suite.Run(t, new(PolicyObjectCountsSuite))
}
