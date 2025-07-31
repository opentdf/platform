package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
)

type ObligationsSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func (s *ObligationsSuite) SetupSuite() {
	slog.Info("setting up db.Obligations test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_obligations"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *ObligationsSuite) TearDownSuite() {
	slog.Info("tearing down db.Obligations test suite")
	s.f.TearDown()
}

func TestObligationsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping obligations integration test")
	}
	suite.Run(t, new(ObligationsSuite))
}

///
/// Obligation Definitions
///

// Create

func (s *ObligationsSuite) Test_CreateObligation_Succeeds() {
	// By namespace ID and with values
	namespace := s.f.GetNamespaceKey("example.com")
	namespaceID := namespace.ID
	namespaceFQN := "https://" + namespace.Name
	oblName := "example-obligation"
	oblValPrefix := "obligation_value_"
	oblVals := []string{
		oblValPrefix + "1",
		oblValPrefix + "2",
	}
	obl, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: namespaceID,
		},
		Name:   oblName,
		Values: oblVals,
	})
	s.Require().NoError(err)
	s.NotNil(obl)
	s.Equal(oblName, obl.Name)
	s.Equal(namespaceID, obl.Namespace.Id)
	s.Equal(namespace.Name, obl.Namespace.Name)
	s.Equal(namespaceFQN, obl.Namespace.Fqn)
	for _, value := range obl.Values {
		s.Contains(value.GetValue(), oblValPrefix)
	}

	// By namespace FQN
	namespace = s.f.GetNamespaceKey("example.net")
	namespaceID = namespace.ID
	namespaceFQN = "https://" + namespace.Name
	obl, err = s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Fqn{
			Fqn: namespaceFQN,
		},
		Name: oblName,
	})
	s.Require().NoError(err)
	s.NotNil(obl)
	s.Equal(oblName, obl.Name)
	s.Equal(namespaceID, obl.Namespace.Id)
	s.Equal(namespace.Name, obl.Namespace.Name)
	s.Equal(namespaceFQN, obl.Namespace.Fqn)
}

func (s *ObligationsSuite) Test_CreateObligation_Fails() {
	// Invalid namespace ID
	fakeNamespaceID := "fake-namespace-id"
	oblName := "example-obligation"
	obl, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: fakeNamespaceID,
		},
		Name: oblName,
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(obl)

	// Non-unique namespace_id/name pair
	namespace := s.f.GetNamespaceKey("example.org")
	namespaceID := namespace.ID
	obl, err = s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: namespaceID,
		},
		Name: oblName,
	})
	s.Require().NoError(err)
	s.NotNil(obl)

	obl, err = s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: namespaceID,
		},
		Name: oblName,
	})
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(obl)
}

// Get

func (s *ObligationsSuite) Test_GetObligationDefinition_Succeeds() {
	// tcs:
	// - get obligation definition by valid id
	// - get obligation definition by valid name

	s.T().Skip("obligation_definitions table not implemented yet")
}

func (s *ObligationsSuite) Test_GetObligationDefinition_Fails() {
	// tcs:
	// - get obligation definition by invalid id
	// - get obligation definition by invalid name

	s.T().Skip("obligation_definitions table not implemented yet")
}

// List

func (s *ObligationsSuite) Test_ListObligationDefinitions_Succeeds() {
	// tcs: see registered resources

	s.T().Skip("obligation_definitions table not implemented yet")
}

func (s *ObligationsSuite) Test_ListObligationDefinitions_Fails() {
	// tcs: see registered resources

	s.T().Skip("obligation_definitions table not implemented yet")
}

// Update

func (s *ObligationsSuite) Test_UpdateObligationDefinitions_Succeeds() {
	// tcs: see registered resources

	s.T().Skip("obligation_definitions table not implemented yet")
}

func (s *ObligationsSuite) Test_UpdateObligationDefinitions_Fails() {
	// tcs: see registered resources

	s.T().Skip("obligation_definitions table not implemented yet")
}

// Delete

func (s *ObligationsSuite) Test_DeleteObligationDefinition_Succeeds() {
	// tcs:
	// - delete by id and ensure cascade removes children relationships

	s.T().Skip("obligation_definitions table not implemented yet")
}

func (s *ObligationsSuite) Test_DeleteObligationDefinition_Fails() {
	// tcs:
	// - delete by invalid id

	s.T().Skip("obligation_definitions table not implemented yet")
}
