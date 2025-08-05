package integration

import (
	"context"
	"log/slog"
	"strconv"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
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
const invalidFQN = "invalid-fqn"

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

	// Delete the obligation
	_, err = s.db.PolicyClient.DeleteObligationDefinition(s.ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Id{
			Id: obl.GetId(),
		},
	})
	s.Require().NoError(err)

	// By namespace FQN
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

	// Delete the obligation
	_, err = s.db.PolicyClient.DeleteObligationDefinition(s.ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Id{
			Id: obl.GetId(),
		},
	})
	s.Require().NoError(err)
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

	pending, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: namespaceID,
		},
		Name: oblName,
	})
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(pending)

	// Delete obligation after tests are done
	_, err = s.db.PolicyClient.DeleteObligationDefinition(s.ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Id{
			Id: obl.GetId(),
		},
	})
	s.Require().NoError(err)
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

	// Delete obligation after tests are done
	_, err = s.db.PolicyClient.DeleteObligationDefinition(s.ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Id{
			Id: createdObl.GetId(),
		},
	})
	s.Require().NoError(err)
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
	namespace := s.f.GetNamespaceKey("example.com")
	otherNamespace := s.f.GetNamespaceKey("example.net")
	namespaceFQN := "https://" + namespace.Name
	otherNamespaceFQN := "https://" + otherNamespace.Name

	// Track created obligations for cleanup
	var createdOblIDs []string

	// Create multiple obligations in first namespace
	for i := 0; i < numObls; i++ {
		obl, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
			NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
				Id: namespace.ID,
			},
			Name:   oblName + "-" + strconv.Itoa(i),
			Values: oblVals,
		})
		s.Require().NoError(err)
		createdOblIDs = append(createdOblIDs, obl.GetId())
	}

	// Create one obligation in different namespace
	otherObl, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: otherNamespace.ID,
		},
		Name:   oblName + "-other-namespace",
		Values: oblVals,
	})
	s.Require().NoError(err)
	createdOblIDs = append(createdOblIDs, otherObl.GetId())

	// Test 1: List all obligations
	oblList, _, err := s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Equal(numObls+1, len(oblList))

	found := 0
	for _, obl := range oblList {
		s.Contains(obl.Name, oblName)
		for _, value := range obl.Values {
			s.Contains(value.GetValue(), oblValPrefix)
		}

		if obl.Namespace.Id == namespace.ID {
			found++
			s.Equal(namespace.ID, obl.Namespace.Id)
			s.Equal(namespace.Name, obl.Namespace.Name)
			s.Equal(namespaceFQN, obl.Namespace.Fqn)
		} else {
			s.Equal(otherNamespace.ID, obl.Namespace.Id)
			s.Equal(otherNamespace.Name, obl.Namespace.Name)
			s.Equal(otherNamespaceFQN, obl.Namespace.Fqn)
			s.Contains(obl.Name, "other-namespace")
		}
	}
	s.Equal(numObls, found)

	// Test 2: List obligations by namespace ID
	oblList, _, err = s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{
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
		s.Equal(namespaceFQN, obl.Namespace.Fqn)
		for _, value := range obl.Values {
			s.Contains(value.GetValue(), oblValPrefix)
		}
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
		s.Contains(obl.Name, oblName)
		s.Equal(namespace.ID, obl.Namespace.Id)
		s.Equal(namespace.Name, obl.Namespace.Name)
		s.Equal(namespaceFQN, obl.Namespace.Fqn)
		for _, value := range obl.Values {
			s.Contains(value.GetValue(), oblValPrefix)
		}
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
	for _, oblID := range createdOblIDs {
		_, err = s.db.PolicyClient.DeleteObligationDefinition(s.ctx, &obligations.DeleteObligationRequest{
			Identifier: &obligations.DeleteObligationRequest_Id{
				Id: oblID,
			},
		})
		s.Require().NoError(err)
	}
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
	// Create an obligation to update
	createdObl, _ := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: s.f.GetNamespaceKey("example.com").ID,
		},
		Name:   oblName,
		Values: oblVals,
	})

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
	s.NotNil(updatedObl)
	s.Equal(newName, updatedObl.Name)
	s.Equal(newMetadata.GetLabels(), updatedObl.Metadata.GetLabels())
	s.Equal(createdObl.GetNamespace().GetId(), updatedObl.GetNamespace().GetId())
	s.Equal(createdObl.GetNamespace().GetName(), updatedObl.GetNamespace().GetName())
	s.Equal(createdObl.GetNamespace().GetFqn(), updatedObl.GetNamespace().GetFqn())

	for _, value := range updatedObl.Values {
		s.Contains(value.GetValue(), oblValPrefix)
	}

	// Delete the obligation after tests are done
	_, err = s.db.PolicyClient.DeleteObligationDefinition(s.ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Id{
			Id: updatedObl.GetId(),
		},
	})
	s.Require().NoError(err)
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
	// Create an obligation to delete
	createdObl, _ := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: s.f.GetNamespaceKey("example.com").ID,
		},
		Name:   oblName,
		Values: oblVals,
	})

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
