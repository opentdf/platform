package integration

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/suite"
)

type PolicyDBClientSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func (s *PolicyDBClientSuite) SetupSuite() {
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "text_opentdf_policy_db_client"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *PolicyDBClientSuite) TearDownSuite() {
	slog.Info("tearing down db.PolicyDbClient test suite")
	s.f.TearDown()
}

func (s *PolicyDBClientSuite) Test_RunInTx_CommitsOnSuccess() {
	var (
		nsName    = "success.com"
		attrName  = fmt.Sprintf("http://%s/attr/attr_one", nsName)
		attrValue = fmt.Sprintf("http://%s/attr/%s/value/attr_one_value", nsName, attrName)

		nsID   string
		attrID string
		valID  string
		err    error
	)

	txErr := s.db.PolicyClient.RunInTx(s.ctx, func(txClient *db.PolicyDBClient) error {
		nsID, err = txClient.Queries.CreateNamespace(s.ctx, db.CreateNamespaceParams{
			Name: nsName,
		})
		s.Require().NoError(err)
		s.Require().NotNil(nsID)

		attrID, err = txClient.Queries.CreateAttribute(s.ctx, db.CreateAttributeParams{
			NamespaceID: nsID,
			Name:        attrName,
			Rule:        db.AttributeDefinitionRuleALLOF,
		})
		s.Require().NoError(err)
		s.Require().NotNil(attrID)

		valID, err = txClient.Queries.CreateAttributeValue(s.ctx, db.CreateAttributeValueParams{
			AttributeDefinitionID: attrID,
			Value:                 attrValue,
		})
		s.Require().NoError(err)
		s.Require().NotNil(valID)

		return nil
	})
	s.Require().NoError(txErr)

	ns, err := s.db.PolicyClient.GetNamespace(s.ctx, nsID)
	s.Require().NoError(err)
	s.Equal(nsName, ns.GetName())

	attr, err := s.db.PolicyClient.GetAttribute(s.ctx, attrID)
	s.Require().NoError(err)
	s.Equal(attrName, attr.GetName())

	attrVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, valID)
	s.Require().NoError(err)
	s.Equal(attrValue, attrVal.GetValue())
}

func (s *PolicyDBClientSuite) Test_RunInTx_RollsBackOnFailure() {
	var (
		nsName   = "failure.com"
		attrName = fmt.Sprintf("http://%s/attr/attr_one", nsName)

		nsID   string
		attrID string
		err    error
	)

	txErr := s.db.PolicyClient.RunInTx(s.ctx, func(txClient *db.PolicyDBClient) error {
		nsID, err = txClient.Queries.CreateNamespace(s.ctx, db.CreateNamespaceParams{
			Name: nsName,
		})
		s.Require().NoError(err)
		s.Require().NotNil(nsID)

		attrID, err = txClient.Queries.CreateAttribute(s.ctx, db.CreateAttributeParams{
			NamespaceID: "invalid_ns_id",
			Name:        attrName,
			Rule:        db.AttributeDefinitionRuleALLOF,
		})
		s.Require().Error(err)
		s.Require().Empty(attrID)
		return err
	})
	s.Require().Error(txErr)

	ns, err := s.db.PolicyClient.GetNamespace(s.ctx, nsID)
	s.Require().Error(err)
	s.Nil(ns)

	attr, err := s.db.PolicyClient.GetAttribute(s.ctx, attrID)
	s.Require().Error(err)
	s.Nil(attr)
}

func TestPolicySuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping policy integration tests")
	}
	suite.Run(t, new(PolicyDBClientSuite))
}
