package integration

import (
	"context"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	policydb "github.com/opentdf/platform/service/policy/db"
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
	s.deleteObligations([]string{obl.GetId()})
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

	s.deleteObligations([]string{obl.GetId()})
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

	s.deleteObligations([]string{createdObl.GetId()})
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

// GetObligationsByFQNs

func (s *ObligationsSuite) Test_GetObligationsByFQNs_Succeeds() {
	// Setup test data
	namespaceID1, namespaceFQN1, namespace1 := s.getNamespaceData(nsExampleCom)
	namespaceID2, namespaceFQN2, namespace2 := s.getNamespaceData(nsExampleNet)
	namespaceID3, _, _ := s.getNamespaceData(nsExampleOrg)

	// Create obligations in different namespaces
	obl1 := s.createObligation(namespaceID1, oblName+"-1", oblVals)
	obl2 := s.createObligation(namespaceID2, oblName+"-2", oblVals)
	obl3 := s.createObligation(namespaceID3, oblName+"-3", oblVals)

	// Test 1: Get multiple obligations by FQNs
	fqns := []string{
		namespaceFQN1 + "/obl/" + oblName + "-1",
		namespaceFQN2 + "/obl/" + oblName + "-2",
	}

	oblList, err := s.db.PolicyClient.GetObligationsByFQNs(s.ctx, &obligations.GetObligationsByFQNsRequest{
		Fqns: fqns,
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Len(oblList, 2)

	// Verify first obligation
	found1 := false
	found2 := false
	for _, obl := range oblList {
		if obl.GetId() == obl1.GetId() {
			s.assertObligationBasics(obl, oblName+"-1", namespaceID1, namespace1.Name, namespaceFQN1)
			s.assertObligationValues(obl)
			found1 = true
		} else if obl.GetId() == obl2.GetId() {
			s.assertObligationBasics(obl, oblName+"-2", namespaceID2, namespace2.Name, namespaceFQN2)
			s.assertObligationValues(obl)
			found2 = true
		}
	}
	s.True(found1, "First obligation should be found")
	s.True(found2, "Second obligation should be found")

	// Test 2: Get single obligation by FQN
	singleFQN := []string{namespaceFQN1 + "/obl/" + oblName + "-1"}
	oblList, err = s.db.PolicyClient.GetObligationsByFQNs(s.ctx, &obligations.GetObligationsByFQNsRequest{
		Fqns: singleFQN,
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Len(oblList, 1)
	s.assertObligationBasics(oblList[0], oblName+"-1", namespaceID1, namespace1.Name, namespaceFQN1)
	s.assertObligationValues(oblList[0])

	// Test 3: Empty FQN list should return empty result
	oblList, err = s.db.PolicyClient.GetObligationsByFQNs(s.ctx, &obligations.GetObligationsByFQNsRequest{
		Fqns: []string{},
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Empty(oblList)

	// Cleanup
	s.deleteObligations([]string{obl1.GetId(), obl2.GetId(), obl3.GetId()})
}

func (s *ObligationsSuite) Test_GetObligationsByFQNs_Fails() {
	// Setup test data
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	obl := s.createObligation(namespaceID, oblName, oblVals)

	// Test 1: Invalid FQN should return empty result (not error)
	invalidFQNs := []string{invalidFQN}
	oblList, err := s.db.PolicyClient.GetObligationsByFQNs(s.ctx, &obligations.GetObligationsByFQNsRequest{
		Fqns: invalidFQNs,
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Empty(oblList)

	// Test 2: Mix of valid and invalid FQNs should return only valid ones
	mixedFQNs := []string{
		namespaceFQN + "/obl/" + oblName,
		invalidFQN,
		"https://nonexistent.com/obl/nonexistent",
	}
	oblList, err = s.db.PolicyClient.GetObligationsByFQNs(s.ctx, &obligations.GetObligationsByFQNsRequest{
		Fqns: mixedFQNs,
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Len(oblList, 1)
	s.Equal(obl.GetId(), oblList[0].GetId())

	// Test 3: Non-existent obligation names should return empty result
	nonExistentFQNs := []string{
		namespaceFQN + "/obl/nonexistent-obligation",
	}
	oblList, err = s.db.PolicyClient.GetObligationsByFQNs(s.ctx, &obligations.GetObligationsByFQNsRequest{
		Fqns: nonExistentFQNs,
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Empty(oblList)

	// Cleanup
	s.deleteObligations([]string{obl.GetId()})
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
	s.deleteObligations(createdOblIDs)
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

	// Update the obligation (with name change)
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

	// Update the obligation (with no name change)
	newMetadata = &common.MetadataMutable{
		Labels: map[string]string{"diffKey": "diffVal"},
	}
	updatedObl, err = s.db.PolicyClient.UpdateObligation(s.ctx, &obligations.UpdateObligationRequest{
		Id:                     createdObl.GetId(),
		Metadata:               newMetadata,
		MetadataUpdateBehavior: 2,
	})
	s.Require().NoError(err)
	s.assertObligationBasics(updatedObl, newName, namespaceID, namespace.Name, namespaceFQN)
	s.Equal(newMetadata.GetLabels(), updatedObl.GetMetadata().GetLabels())
	s.assertObligationValues(updatedObl)

	s.deleteObligations([]string{updatedObl.GetId()})
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
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, oblVals)

	// Get the obligation to ensure it exists
	obl, err := s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Identifier: &obligations.GetObligationRequest_Id{
			Id: createdObl.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(obl)

	// Delete the obligation by ID
	obl, err = s.db.PolicyClient.DeleteObligation(s.ctx, &obligations.DeleteObligationRequest{
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

	createdObl = s.createObligation(namespaceID, oblName, oblVals)

	// Delete the obligation by FQN
	fqn := policydb.BuildOblFQN(namespaceFQN, oblName)
	obl, err = s.db.PolicyClient.DeleteObligation(s.ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Fqn{
			Fqn: fqn,
		},
	})
	s.Require().NoError(err)
	s.NotNil(obl)
	s.Equal(createdObl.GetId(), obl.GetId())
}

func (s *ObligationsSuite) Test_DeleteObligation_Fails() {
	// Attempt to delete an obligation with an invalid ID
	obl, err := s.db.PolicyClient.DeleteObligation(s.ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Id{
			Id: invalidUUID,
		},
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(obl)
}

///
/// Obligation Values
///

// Create

func (s *ObligationsSuite) Test_CreateObligationValue_Succeeds() {
	namespaceID, namespaceFQN, namespace := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, nil) // Create obligation without values

	// Test 1: Create obligation value by obligation ID
	oblValue, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{
			Id: createdObl.GetId(),
		},
		Value: oblValPrefix + "test-1",
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"test": "value"},
		},
	})
	s.Require().NoError(err)
	s.NotNil(oblValue)
	s.Equal("value", oblValue.GetMetadata().GetLabels()["test"])
	s.assertObligationValueBasics(oblValue, oblValPrefix+"test-1", namespaceID, namespace.Name, namespaceFQN)

	// Test 2: Create obligation value by obligation FQN
	oblFQN := policydb.BuildOblFQN(namespaceFQN, oblName)
	oblValue2, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationIdentifier: &obligations.CreateObligationValueRequest_Fqn{
			Fqn: oblFQN,
		},
		Value: oblValPrefix + "test-2",
	})
	s.Require().NoError(err)
	s.NotNil(oblValue2)
	s.assertObligationValueBasics(oblValue2, oblValPrefix+"test-2", namespaceID, namespace.Name, namespaceFQN)

	// Cleanup
	s.deleteObligations([]string{createdObl.GetId()})
}

func (s *ObligationsSuite) Test_CreateObligationValue_Fails() {
	// Test 1: Invalid obligation ID
	oblValue, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{
			Id: invalidUUID,
		},
		Value: oblValPrefix + "test",
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(oblValue)

	// Test 2: Non-existent obligation ID
	oblValue, err = s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{
			Id: invalidID,
		},
		Value: oblValPrefix + "test",
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(oblValue)

	// Test 3: Invalid obligation FQN
	oblValue, err = s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationIdentifier: &obligations.CreateObligationValueRequest_Fqn{
			Fqn: invalidFQN,
		},
		Value: oblValPrefix + "test",
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(oblValue)

	// Test 4: Non-existent obligation name in valid namespace
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, nil)
	nonExistentFQN := policydb.BuildOblFQN(namespaceFQN, "non-existent-obligation")

	oblValue, err = s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationIdentifier: &obligations.CreateObligationValueRequest_Fqn{
			Fqn: nonExistentFQN,
		},
		Value: oblValPrefix + "test",
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(oblValue)

	// Cleanup
	s.deleteObligations([]string{createdObl.GetId()})
}

// Get

func (s *ObligationsSuite) Test_GetObligationValue_Succeeds() {
	namespaceID, namespaceFQN, namespace := s.getNamespaceData(nsExampleCom)
	value := oblValPrefix + "get-test"
	createdObl := s.createObligation(namespaceID, oblName, []string{value})
	oblValue := createdObl.GetValues()[0]

	// Test 1: Get obligation value by ID
	retrievedValue, err := s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Identifier: &obligations.GetObligationValueRequest_Id{
			Id: oblValue.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(retrievedValue)
	s.Equal(oblValue.GetId(), retrievedValue.GetId())
	s.assertObligationValueBasics(retrievedValue, oblValPrefix+"get-test", namespaceID, namespace.Name, namespaceFQN)

	// Test 2: Get obligation value by FQN
	oblValFQN := policydb.BuildOblValFQN(namespaceFQN, oblName, oblValPrefix+"get-test")
	retrievedValue2, err := s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Identifier: &obligations.GetObligationValueRequest_Fqn{
			Fqn: oblValFQN,
		},
	})
	s.Require().NoError(err)
	s.NotNil(retrievedValue2)
	s.Equal(oblValue.GetId(), retrievedValue2.GetId())
	s.assertObligationValueBasics(retrievedValue2, oblValPrefix+"get-test", namespaceID, namespace.Name, namespaceFQN)

	// Cleanup
	s.deleteObligations([]string{createdObl.GetId()})
}

func (s *ObligationsSuite) Test_GetObligationValue_Fails() {
	// Test 1: Invalid value ID
	retrievedValue, err := s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Identifier: &obligations.GetObligationValueRequest_Id{
			Id: invalidUUID,
		},
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(retrievedValue)

	// Test 2: Non-existent value ID
	retrievedValue, err = s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Identifier: &obligations.GetObligationValueRequest_Id{
			Id: invalidID,
		},
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(retrievedValue)

	// Test 3: Invalid value FQN
	retrievedValue, err = s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Identifier: &obligations.GetObligationValueRequest_Fqn{
			Fqn: invalidFQN,
		},
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(retrievedValue)

	// Test 4: Non-existent value name in valid obligation
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, nil)
	nonExistentValFQN := policydb.BuildOblValFQN(namespaceFQN, oblName, "non-existent-value")

	retrievedValue, err = s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Identifier: &obligations.GetObligationValueRequest_Fqn{
			Fqn: nonExistentValFQN,
		},
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(retrievedValue)

	// Test 5: Non-existent obligation name in valid namespace
	nonExistentOblFQN := policydb.BuildOblValFQN(namespaceFQN, "non-existent-obligation", oblValPrefix+"test")
	retrievedValue, err = s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Identifier: &obligations.GetObligationValueRequest_Fqn{
			Fqn: nonExistentOblFQN,
		},
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(retrievedValue)

	// Cleanup
	s.deleteObligations([]string{createdObl.GetId()})
}

// Delete

func (s *ObligationsSuite) Test_DeleteObligationValue_Succeeds() {
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	values := []string{oblValPrefix + "delete-1", oblValPrefix + "delete-2"}
	createdObl := s.createObligation(namespaceID, oblName, values)
	oblValues := createdObl.GetValues()

	// Delete by value ID
	deleted, err := s.db.PolicyClient.DeleteObligationValue(s.ctx, &obligations.DeleteObligationValueRequest{
		Identifier: &obligations.DeleteObligationValueRequest_Id{
			Id: oblValues[0].GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(deleted)
	s.Equal(oblValues[0].GetId(), deleted.GetId())

	// Delete by FQN + value name
	oblValFQN := policydb.BuildOblValFQN(namespaceFQN, oblName, values[1])
	deleted2, err := s.db.PolicyClient.DeleteObligationValue(s.ctx, &obligations.DeleteObligationValueRequest{
		Identifier: &obligations.DeleteObligationValueRequest_Fqn{
			Fqn: oblValFQN,
		},
	})
	s.Require().NoError(err)
	s.NotNil(deleted2)
	s.Equal(oblValues[1].GetId(), deleted2.GetId())

	// Cleanup
	s.deleteObligations([]string{createdObl.GetId()})
}

func (s *ObligationsSuite) Test_DeleteObligationValue_Fails() {
	// Invalid value ID
	deleted, err := s.db.PolicyClient.DeleteObligationValue(s.ctx, &obligations.DeleteObligationValueRequest{
		Identifier: &obligations.DeleteObligationValueRequest_Id{
			Id: invalidUUID,
		},
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(deleted)

	// Non-existent value ID
	deleted, err = s.db.PolicyClient.DeleteObligationValue(s.ctx, &obligations.DeleteObligationValueRequest{
		Identifier: &obligations.DeleteObligationValueRequest_Id{
			Id: invalidID,
		},
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(deleted)

	// Invalid value FQN
	deleted, err = s.db.PolicyClient.DeleteObligationValue(s.ctx, &obligations.DeleteObligationValueRequest{
		Identifier: &obligations.DeleteObligationValueRequest_Fqn{
			Fqn: invalidFQN,
		},
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(deleted)

	// Non-existent value name in valid obligation
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, nil)
	nonExistentValFQN := policydb.BuildOblValFQN(namespaceFQN, oblName, "non-existent-value")
	deleted, err = s.db.PolicyClient.DeleteObligationValue(s.ctx, &obligations.DeleteObligationValueRequest{
		Identifier: &obligations.DeleteObligationValueRequest_Fqn{
			Fqn: nonExistentValFQN,
		},
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(deleted)

	// Cleanup
	s.deleteObligations([]string{createdObl.GetId()})
}

// Helper functions for common operations

func (s *ObligationsSuite) getNamespaceData(nsName string) (string, string, fixtures.FixtureDataNamespace) {
	fixture := s.f.GetNamespaceKey(nsName)
	return fixture.ID, httpsPrefix + fixture.Name, fixture
}

func (s *ObligationsSuite) assertObligationBasics(obl *policy.Obligation, name, namespaceID, namespaceName, namespaceFQN string) {
	s.Require().NotNil(obl)
	s.Equal(name, obl.GetName())
	s.assertNamespace(obl.GetNamespace(), namespaceID, namespaceName, namespaceFQN)
	s.assertMetadata(obl.GetMetadata())
}

func (s *ObligationsSuite) assertNamespace(ns *policy.Namespace, namespaceID, namespaceName, namespaceFQN string) {
	s.Require().NotNil(ns)
	s.Equal(namespaceID, ns.GetId())
	s.Equal(namespaceName, ns.GetName())
	s.Equal(namespaceFQN, ns.GetFqn())
}

func (s *ObligationsSuite) assertMetadata(meta *common.Metadata) {
	s.Require().NotNil(meta)
	// Assert that timestamps in metadata are recent
	threshold := int64(5)
	now := time.Now().Unix()
	diff := now - meta.GetUpdatedAt().GetSeconds()
	s.LessOrEqual(diff, threshold)
	diff = now - meta.GetCreatedAt().GetSeconds()
	s.LessOrEqual(diff, threshold)
}

func (s *ObligationsSuite) assertObligationValues(obl *policy.Obligation) {
	s.NotEmpty(obl.GetValues())
	for _, value := range obl.GetValues() {
		s.Contains(value.GetValue(), oblValPrefix)
	}
}

func (s *ObligationsSuite) assertObligationValueBasics(oblValue *policy.ObligationValue, value, namespaceID, namespaceName, namespaceFQN string) {
	s.Require().NotNil(oblValue)
	s.Equal(value, oblValue.GetValue())
	s.assertNamespace(oblValue.GetObligation().GetNamespace(), namespaceID, namespaceName, namespaceFQN)
	s.assertMetadata(oblValue.GetMetadata())
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
	_, err := s.db.PolicyClient.DeleteObligation(s.ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Id{
			Id: oblID,
		},
	})
	s.Require().NoError(err)
}

func (s *ObligationsSuite) deleteObligations(oblIDs []string) {
	for _, oblID := range oblIDs {
		defer s.deleteObligation(oblID)
	}
}
