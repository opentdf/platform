package integration

import (
	"context"
	"log/slog"
	"strconv"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
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

const (
	oblName      = "example-obligation"
	oblValPrefix = "obligation_value_"
	invalidFQN   = "invalid-fqn"
	nsExampleCom = "example.com"
	nsExampleNet = "example.net"
	nsExampleOrg = "example.org"
	httpsPrefix  = "https://"
)

var oblVals = []string{
	oblValPrefix + "1",
	oblValPrefix + "2",
}

// Create

func (s *ObligationsSuite) Test_CreateObligation_Succeeds() {
	// By namespace ID and with values
	namespaceID, namespaceFQN, namespace := s.getNamespaceData(nsExampleCom)
	obl := s.createObligation(namespaceID, oblName, oblVals)
	s.assertObligationBasics(obl, oblName, namespaceID, namespace.Name, namespaceFQN)
	s.assertObligationValues(obl)
	s.deleteObligation(obl.GetId())

	// By namespace FQN
	obl = s.createObligationByFQN(namespaceFQN, oblName, nil)
	s.assertObligationBasics(obl, oblName, namespaceID, namespace.Name, namespaceFQN)
	defer s.deleteObligation(obl.GetId())
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
	namespaceID, _, _ := s.getNamespaceData(nsExampleOrg)
	obl = s.createObligation(namespaceID, oblName, nil)

	pending, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: namespaceID,
		},
		Name: oblName,
	})
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(pending)

	defer s.deleteObligation(obl.GetId())
}

// Get

func (s *ObligationsSuite) Test_GetObligation_Succeeds() {
	namespaceID, namespaceFQN, namespace := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, oblVals)

	// Valid ID
	obl, err := s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Identifier: &obligations.GetObligationRequest_Id{
			Id: createdObl.GetId(),
		},
	})
	s.Require().NoError(err)
	s.assertObligationBasics(obl, oblName, namespaceID, namespace.Name, namespaceFQN)
	s.assertObligationValues(obl)

	// Valid FQN
	obl, err = s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Identifier: &obligations.GetObligationRequest_Fqn{
			Fqn: namespaceFQN + "/obl/" + oblName,
		},
	})
	s.Require().NoError(err)
	s.assertObligationBasics(obl, oblName, namespaceID, namespace.Name, namespaceFQN)

	defer s.deleteObligation(createdObl.GetId())
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
			Fqn: invalidFQN,
		},
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(obl)
}

// List

func (s *ObligationsSuite) Test_ListObligations_Succeeds() {
	// Setup test data
	numObls := 3
	namespaceID, namespaceFQN, namespace := s.getNamespaceData(nsExampleCom)
	otherNamespaceID, otherNamespaceFQN, otherNamespace := s.getNamespaceData(nsExampleNet)

	// Track created obligations for cleanup
	var createdOblIDs []string

	// Create multiple obligations in first namespace
	for i := 0; i < numObls; i++ {
		obl := s.createObligation(namespaceID, oblName+"-"+strconv.Itoa(i), oblVals)
		createdOblIDs = append(createdOblIDs, obl.GetId())
	}

	// Create one obligation in different namespace
	otherObl := s.createObligation(otherNamespaceID, oblName+"-other-namespace", oblVals)
	createdOblIDs = append(createdOblIDs, otherObl.GetId())

	// Test 1: List all obligations
	oblList, _, err := s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Len(oblList, numObls+1)

	found := 0
	for _, obl := range oblList {
		s.Contains(obl.GetName(), oblName)
		s.assertObligationValues(obl)

		if obl.GetNamespace().GetId() == namespaceID {
			found++
			s.assertObligationBasics(obl, obl.GetName(), namespaceID, namespace.Name, namespaceFQN)
		} else {
			s.assertObligationBasics(obl, obl.GetName(), otherNamespaceID, otherNamespace.Name, otherNamespaceFQN)
			s.Contains(obl.GetName(), "other-namespace")
		}
	}
	s.Equal(numObls, found)

	// Test 2: List obligations by namespace ID
	oblList, _, err = s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{
		NamespaceIdentifier: &obligations.ListObligationsRequest_Id{
			Id: namespaceID,
		},
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Len(oblList, numObls)
	for _, obl := range oblList {
		s.Contains(obl.GetName(), oblName)
		s.assertObligationBasics(obl, obl.GetName(), namespaceID, namespace.Name, namespaceFQN)
		s.assertObligationValues(obl)
	}

	// Test 3: List obligations by namespace FQN
	oblList, _, err = s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{
		NamespaceIdentifier: &obligations.ListObligationsRequest_Fqn{
			Fqn: namespaceFQN,
		},
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Len(oblList, numObls)
	for _, obl := range oblList {
		s.Contains(obl.GetName(), oblName)
		s.assertObligationBasics(obl, obl.GetName(), namespaceID, namespace.Name, namespaceFQN)
		s.assertObligationValues(obl)
	}

	// Test 4: List obligations with invalid namespace FQN (should return empty)
	oblList, _, err = s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{
		NamespaceIdentifier: &obligations.ListObligationsRequest_Fqn{
			Fqn: invalidFQN,
		},
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Empty(oblList)

	// Cleanup: Delete all created obligations
	defer s.deleteObligations(createdOblIDs)
}

func (s *ObligationsSuite) Test_ListObligations_Fails() {
	// Attempt to list obligations with an invalid namespace ID
	oblList, _, err := s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{
		NamespaceIdentifier: &obligations.ListObligationsRequest_Id{
			Id: invalidUUID,
		},
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(oblList)
}

// Update

func (s *ObligationsSuite) Test_UpdateObligation_Succeeds() {
	namespaceID, namespaceFQN, namespace := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, oblVals)

	// Update the obligation
	newName := oblName + "-updated"
	newMetadata := &common.MetadataMutable{
		Labels: map[string]string{"key": "value"},
	}
	updatedObl, err := s.db.PolicyClient.UpdateObligation(s.ctx, &obligations.UpdateObligationRequest{
		Id:                     createdObl.GetId(),
		Name:                   newName,
		Metadata:               newMetadata,
		MetadataUpdateBehavior: 1,
	})
	s.Require().NoError(err)
	s.assertObligationBasics(updatedObl, newName, namespaceID, namespace.Name, namespaceFQN)
	s.Equal(newMetadata.GetLabels(), updatedObl.GetMetadata().GetLabels())
	s.assertObligationValues(updatedObl)

	defer s.deleteObligation(updatedObl.GetId())
}

func (s *ObligationsSuite) Test_UpdateObligation_Fails() {
	// Attempt to update an obligation with an invalid ID
	obl, err := s.db.PolicyClient.UpdateObligation(s.ctx, &obligations.UpdateObligationRequest{
		Id: invalidUUID,
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(obl)
}

// Delete

func (s *ObligationsSuite) Test_DeleteObligation_Succeeds() {
	namespaceID, _, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, oblVals)

	// Get the obligation to ensure it exists
	obl, err := s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Identifier: &obligations.GetObligationRequest_Id{
			Id: createdObl.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(obl)

	// Delete the obligation
	obl, err = s.db.PolicyClient.DeleteObligationDefinition(s.ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Id{
			Id: createdObl.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(obl)
	s.Equal(createdObl.GetId(), obl.GetId())

	// Attempt to get the obligation again to ensure it has been deleted
	obl, err = s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Identifier: &obligations.GetObligationRequest_Id{
			Id: createdObl.GetId(),
		},
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(obl)
}

func (s *ObligationsSuite) Test_DeleteObligation_Fails() {
	// Attempt to delete an obligation with an invalid ID
	obl, err := s.db.PolicyClient.DeleteObligationDefinition(s.ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Id{
			Id: invalidUUID,
		},
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(obl)
}

// Helper functions for common operations

func (s *ObligationsSuite) getNamespaceData(nsName string) (string, string, fixtures.FixtureDataNamespace) {
	fixture := s.f.GetNamespaceKey(nsName)
	return fixture.ID, httpsPrefix + fixture.Name, fixture
}

func (s *ObligationsSuite) assertObligationBasics(obl *policy.Obligation, name, namespaceID, namespaceName, namespaceFQN string) {
	s.Require().NotNil(obl)
	s.Equal(name, obl.GetName())
	s.Equal(namespaceID, obl.GetNamespace().GetId())
	s.Equal(namespaceName, obl.GetNamespace().GetName())
	s.Equal(namespaceFQN, obl.GetNamespace().GetFqn())
}

func (s *ObligationsSuite) assertObligationValues(obl *policy.Obligation) {
	for _, value := range obl.GetValues() {
		s.Contains(value.GetValue(), oblValPrefix)
	}
}

func (s *ObligationsSuite) createObligation(namespaceID, name string, values []string) *policy.Obligation {
	obl, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: namespaceID,
		},
		Name:   name,
		Values: values,
	})
	s.Require().NoError(err)
	return obl
}

func (s *ObligationsSuite) createObligationByFQN(namespaceFQN, name string, values []string) *policy.Obligation {
	obl, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Fqn{
			Fqn: namespaceFQN,
		},
		Name:   name,
		Values: values,
	})
	s.Require().NoError(err)
	return obl
}

func (s *ObligationsSuite) deleteObligation(oblID string) {
	_, err := s.db.PolicyClient.DeleteObligationDefinition(s.ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Id{
			Id: oblID,
		},
	})
	s.Require().NoError(err)
}

func (s *ObligationsSuite) deleteObligations(oblIDs []string) {
	for _, oblID := range oblIDs {
		s.deleteObligation(oblID)
	}
}
