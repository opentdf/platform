package integration

import (
	"context"
	"log/slog"
	"strconv"
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

const oblName = "example-obligation"
const oblValPrefix = "obligation_value_"

var oblVals = []string{
	oblValPrefix + "1",
	oblValPrefix + "2",
}

// Create

func (s *ObligationsSuite) Test_CreateObligation_Succeeds() {
	// By namespace ID and with values
	namespace := s.f.GetNamespaceKey("example.com")
	namespaceID := namespace.ID
	namespaceFQN := "https://" + namespace.Name
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

	// TODO: delete both obligations after tests are done
}

func (s *ObligationsSuite) Test_CreateObligation_Fails() {
	// Invalid namespace ID
	obl, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: invalidUUID,
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

	// TODO: delete obligation after tests are done
}

// Get

func (s *ObligationsSuite) Test_GetObligation_Succeeds() {
	createdObl, _ := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: s.f.GetNamespaceKey("example.com").ID,
		},
		Name:   oblName,
		Values: oblVals,
	})

	// Valid ID
	obl, err := s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Identifier: &obligations.GetObligationRequest_Id{
			Id: createdObl.GetId(),
		},
	})

	s.Require().NoError(err)
	s.NotNil(obl)
	s.Equal(oblName, obl.Name)
	s.Equal(createdObl.GetNamespace().GetId(), obl.GetNamespace().GetId())
	s.Equal(createdObl.GetNamespace().GetName(), obl.GetNamespace().GetName())
	s.Equal(createdObl.GetNamespace().GetFqn(), obl.GetNamespace().GetFqn())
	for _, value := range obl.Values {
		s.Contains(value.GetValue(), oblValPrefix)
	}

	// Valid FQN
	obl, err = s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Identifier: &obligations.GetObligationRequest_Fqn{
			Fqn: createdObl.GetNamespace().GetFqn() + "/obl/" + oblName,
		},
	})
	s.Require().NoError(err)
	s.NotNil(obl)
	s.Equal(oblName, obl.Name)
	s.Equal(createdObl.GetNamespace().GetId(), obl.GetNamespace().GetId())
	s.Equal(createdObl.GetNamespace().GetName(), obl.GetNamespace().GetName())
	s.Equal(createdObl.GetNamespace().GetFqn(), obl.GetNamespace().GetFqn())

	// TODO: delete obligation after tests are done
}

func (s *ObligationsSuite) Test_GetObligation_Fails() {
	// Invalid ID
	obl, err := s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Identifier: &obligations.GetObligationRequest_Id{
			Id: invalidUUID,
		},
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(obl)

	// Invalid FQN
	obl, err = s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Identifier: &obligations.GetObligationRequest_Fqn{
			Fqn: "invalid-fqn",
		},
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(obl)
}

// List

func (s *ObligationsSuite) Test_ListObligations_Succeeds() {
	// Create multiple obligations
	numObls := 3
	namespace := s.f.GetNamespaceKey("example.com")
	for i := 0; i < numObls; i++ {
		_, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
			NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
				Id: namespace.ID,
			},
			Name:   oblName + "-" + strconv.Itoa(i),
			Values: oblVals,
		})
		s.Require().NoError(err)
	}
	// List obligations by namespace ID
	oblList, err := s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{
		NamespaceIdentifier: &obligations.ListObligationsRequest_Id{
			Id: namespace.ID,
		},
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Len(oblList, numObls)
	for _, obl := range oblList {
		s.Contains(obl.Name, oblName)
		s.Equal(namespace.ID, obl.Namespace.Id)
		s.Equal(namespace.Name, obl.Namespace.Name)
		s.Equal("https://"+namespace.Name, obl.Namespace.Fqn)
		for _, value := range obl.Values {
			s.Contains(value.GetValue(), oblValPrefix)
		}
	}

	// TODO: delete obligations after tests are done
}

func (s *ObligationsSuite) Test_ListObligations_Fails() {
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
