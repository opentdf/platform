package integration

import (
	"context"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/proto"
)

type ObligationsSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

type TriggerSetup struct {
	createdObl      *policy.Obligation
	namespace       *fixtures.FixtureDataNamespace
	action          *policy.Action
	attributeValues []*fixtures.FixtureDataAttributeValue
}

type TriggerAssertion struct {
	expectedAction            *policy.Action
	expectedObligation        *policy.Obligation
	expectedAttributeValue    *fixtures.FixtureDataAttributeValue
	expectedAttributeValueFQN string
	expectedObligationValue   *policy.ObligationValue
	expectedClientID          string
}

type ValueTriggerExpectation struct {
	ID               string // Value ID
	ExpectedTriggers []*policy.ObligationTrigger
}

func (s *ObligationsSuite) SetupSuite() {
	slog.Info("setting up db.Obligations test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_obligations"
	s.db = fixtures.NewDBInterface(s.ctx, c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision(s.ctx)
}

func (s *ObligationsSuite) TearDownSuite() {
	slog.Info("tearing down db.Obligations test suite")
	s.f.TearDown(s.ctx)
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
		NamespaceId: invalidUUID,
		Name:        oblName,
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(obl)

	// Non-unique namespace_id/name pair
	namespaceID, _, _ := s.getNamespaceData(nsExampleOrg)
	obl = s.createObligation(namespaceID, oblName, nil)

	pending, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceId: namespaceID,
		Name:        oblName,
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
		Id: createdObl.GetId(),
	})
	s.Require().NoError(err)
	s.assertObligationBasics(obl, oblName, namespaceID, namespace.Name, namespaceFQN)
	s.assertObligationValues(obl)

	// Valid FQN
	obl, err = s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Fqn: namespaceFQN + "/obl/" + oblName,
	})
	s.Require().NoError(err)
	s.assertObligationBasics(obl, oblName, namespaceID, namespace.Name, namespaceFQN)
	s.Require().Empty(obl.GetValues()[0].GetTriggers())
	s.Require().Empty(obl.GetValues()[1].GetTriggers())

	s.deleteObligations([]string{createdObl.GetId()})
}

func (s *ObligationsSuite) Test_GetObligation_WithTriggers_Succeeds() {
	namespaceID, namespaceFQN, namespace := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName+"-with-triggers", nil)

	defer s.deleteObligations([]string{createdObl.GetId()})

	// Create obligation value with triggers
	createdOblVal := s.createObligationValueWithDefaultTriggers(createdObl.GetId(), oblValPrefix+"trigger-test")

	// Get obligation by ID and verify triggers are returned
	obl, err := s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Id: createdObl.GetId(),
	})
	s.Require().NoError(err)
	s.assertObligationBasics(obl, oblName+"-with-triggers", namespaceID, namespace.Name, namespaceFQN)
	s.assertObligationValuesSpecificTriggers(obl, []*ValueTriggerExpectation{
		{
			ID:               createdOblVal.GetId(),
			ExpectedTriggers: createdOblVal.GetTriggers(),
		},
	})
}

func (s *ObligationsSuite) Test_GetObligation_Fails() {
	// Invalid ID
	obl, err := s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Id: invalidUUID,
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(obl)

	// Invalid FQN
	obl, err = s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Fqn: invalidFQN,
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

func (s *ObligationsSuite) Test_GetObligationsByFQNs_WithTriggers_Succeeds() {
	// Setup test data
	namespaceID1, namespaceFQN1, namespace1 := s.getNamespaceData(nsExampleCom)
	namespaceID2, namespaceFQN2, namespace2 := s.getNamespaceData(nsExampleNet)

	// Create obligations with values that have different triggers
	obl1 := s.createObligation(namespaceID1, oblName+"-triggers-1", nil)

	defer s.deleteObligations([]string{obl1.GetId()})

	obl1Triggers := []*obligations.ValueTriggerRequest{
		{
			Action:         &common.IdNameIdentifier{Name: "read"},
			AttributeValue: &common.IdFqnIdentifier{Fqn: "https://example.com/attr/attr1/value/value1"},
			Context: &policy.RequestContext{
				Pep: &policy.PolicyEnforcementPoint{
					ClientId: clientID,
				},
			},
		},
	}
	oblValue1 := s.createObligationValueWithTriggers(obl1.GetId(), oblValPrefix+"trigger-val1", obl1Triggers)

	obl2 := s.createObligation(namespaceID2, oblName+"-triggers-2", nil)

	defer s.deleteObligations([]string{obl2.GetId()})

	obl2Triggers := []*obligations.ValueTriggerRequest{
		{
			Action:         &common.IdNameIdentifier{Name: "create"},
			AttributeValue: &common.IdFqnIdentifier{Fqn: "https://example.net/attr/attr1/value/value1"},
		},
	}
	oblValue2 := s.createObligationValueWithTriggers(obl2.GetId(), oblValPrefix+"trigger-val2", obl2Triggers) // Get multiple obligations by FQNs and verify triggers are returned
	fqns := []string{
		namespaceFQN1 + "/obl/" + oblName + "-triggers-1",
		namespaceFQN2 + "/obl/" + oblName + "-triggers-2",
	}

	oblList, err := s.db.PolicyClient.GetObligationsByFQNs(s.ctx, &obligations.GetObligationsByFQNsRequest{
		Fqns: fqns,
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Len(oblList, 2)

	// Verify both obligations have triggers
	found1 := false
	found2 := false
	for _, obl := range oblList {
		if obl.GetId() == obl1.GetId() {
			s.assertObligationBasics(obl, oblName+"-triggers-1", namespaceID1, namespace1.Name, namespaceFQN1)

			// Use the actual triggers from the created obligation value as expected triggers
			expectedValues := []*ValueTriggerExpectation{
				{
					ID:               oblValue1.GetId(),
					ExpectedTriggers: oblValue1.GetTriggers(),
				},
			}
			s.assertObligationValuesSpecificTriggers(obl, expectedValues)
			found1 = true
		} else if obl.GetId() == obl2.GetId() {
			s.assertObligationBasics(obl, oblName+"-triggers-2", namespaceID2, namespace2.Name, namespaceFQN2)

			// Use the actual triggers from the created obligation value as expected triggers
			expectedValues := []*ValueTriggerExpectation{
				{
					ID:               oblValue2.GetId(),
					ExpectedTriggers: oblValue2.GetTriggers(),
				},
			}
			s.assertObligationValuesSpecificTriggers(obl, expectedValues)
			found2 = true
		}
	}
	s.True(found1, "First obligation with triggers should be found")
	s.True(found2, "Second obligation with triggers should be found")
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
		NamespaceId: namespaceID,
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
		NamespaceFqn: namespaceFQN,
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
		NamespaceFqn: invalidFQN,
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
		NamespaceId: invalidUUID,
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(oblList)
}

func (s *ObligationsSuite) Test_ListObligations_WithTriggers_Succeeds() {
	// Setup test data
	namespaceID, namespaceFQN, namespace := s.getNamespaceData(nsExampleCom)
	otherNamespaceID, otherNamespaceFQN, otherNamespace := s.getNamespaceData(nsExampleNet)

	// Create obligations with values that have different triggers
	obl1 := s.createObligation(namespaceID, oblName+"-list-triggers-1", nil)
	obl1Triggers := []*obligations.ValueTriggerRequest{
		{
			Action:         &common.IdNameIdentifier{Name: "read"},
			AttributeValue: &common.IdFqnIdentifier{Fqn: "https://example.com/attr/attr1/value/value1"},
			Context: &policy.RequestContext{
				Pep: &policy.PolicyEnforcementPoint{
					ClientId: clientID,
				},
			},
		},
	}
	createdValue1 := s.createObligationValueWithTriggers(obl1.GetId(), oblValPrefix+"list-trigger-val1", obl1Triggers)
	defer s.deleteObligations([]string{obl1.GetId()})

	obl2 := s.createObligation(namespaceID, oblName+"-list-triggers-2", nil)
	obl2Triggers := []*obligations.ValueTriggerRequest{
		{
			Action:         &common.IdNameIdentifier{Name: "update"},
			AttributeValue: &common.IdFqnIdentifier{Fqn: "https://example.com/attr/attr1/value/value2"},
			Context: &policy.RequestContext{
				Pep: &policy.PolicyEnforcementPoint{
					ClientId: clientID,
				},
			},
		},
	}
	createdValue2 := s.createObligationValueWithTriggers(obl2.GetId(), oblValPrefix+"list-trigger-val2", obl2Triggers)
	defer s.deleteObligations([]string{obl2.GetId()})

	otherObl := s.createObligation(otherNamespaceID, oblName+"-other-list-triggers", nil)
	otherOblTriggers := []*obligations.ValueTriggerRequest{
		{
			Action:         &common.IdNameIdentifier{Name: "create"},
			AttributeValue: &common.IdFqnIdentifier{Fqn: "https://example.net/attr/attr1/value/value1"},
		},
	}
	createdValue3 := s.createObligationValueWithTriggers(otherObl.GetId(), oblValPrefix+"other-trigger-val", otherOblTriggers)
	defer s.deleteObligations([]string{otherObl.GetId()})

	// Create a map of obligation IDs to created values for easier lookup
	oblValueMap := make(map[string]*policy.ObligationValue)
	oblValueMap[obl1.GetId()] = createdValue1
	oblValueMap[obl2.GetId()] = createdValue2
	oblValueMap[otherObl.GetId()] = createdValue3

	// Test 1: List all obligations and verify triggers are returned
	oblList, _, err := s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Len(oblList, 3)

	validateTriggers := func(oblValueMap map[string]*policy.ObligationValue, obl *policy.Obligation) {
		expectedOblValue, ok := oblValueMap[obl.GetId()]
		s.Require().True(ok, "Obligation value should exist for obligation ID: %s", obl.GetId())
		expectedValues := []*ValueTriggerExpectation{
			{
				ID:               expectedOblValue.GetId(),
				ExpectedTriggers: expectedOblValue.GetTriggers(),
			},
		}
		s.assertObligationValuesSpecificTriggers(obl, expectedValues)
	}

	for _, obl := range oblList {
		if obl.GetNamespace().GetId() == namespaceID {
			s.assertObligationBasics(obl, obl.GetName(), namespaceID, namespace.Name, namespaceFQN)
		} else {
			s.assertObligationBasics(obl, obl.GetName(), otherNamespaceID, otherNamespace.Name, otherNamespaceFQN)
		}

		validateTriggers(oblValueMap, obl)
	}

	// Test 2: List obligations by namespace ID and verify triggers
	oblList, _, err = s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{
		NamespaceId: namespaceID,
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Len(oblList, 2)
	for _, obl := range oblList {
		s.assertObligationBasics(obl, obl.GetName(), namespaceID, namespace.Name, namespaceFQN)
		validateTriggers(oblValueMap, obl)
	}

	// Test 3: List obligations by namespace FQN and verify triggers
	oblList, _, err = s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{
		NamespaceFqn: namespaceFQN,
	})
	s.Require().NoError(err)
	s.NotNil(oblList)
	s.Len(oblList, 2)
	for _, obl := range oblList {
		s.assertObligationBasics(obl, obl.GetName(), namespaceID, namespace.Name, namespaceFQN)
		validateTriggers(oblValueMap, obl)
	}
}

// Update

func (s *ObligationsSuite) Test_UpdateObligation_Succeeds() {
	namespaceID, namespaceFQN, namespace := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName+"-update-succeeds", oblVals)

	// Test 1: Update obligation with name and metadata change
	newName := oblName + "-updated"
	newMetadata := &common.MetadataMutable{
		Labels: map[string]string{"updated": "true", "version": "2"},
	}
	updatedObl, err := s.db.PolicyClient.UpdateObligation(s.ctx, &obligations.UpdateObligationRequest{
		Id:                     createdObl.GetId(),
		Name:                   newName,
		Metadata:               newMetadata,
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.assertObligationBasics(updatedObl, newName, namespaceID, namespace.Name, namespaceFQN)
	s.Equal("true", updatedObl.GetMetadata().GetLabels()["updated"])
	s.Equal("2", updatedObl.GetMetadata().GetLabels()["version"])
	s.assertObligationValues(updatedObl)

	// Test 2: Update only metadata (no name change)
	newMetadata2 := &common.MetadataMutable{
		Labels: map[string]string{"metadata_only": "true"},
	}
	updatedObl2, err := s.db.PolicyClient.UpdateObligation(s.ctx, &obligations.UpdateObligationRequest{
		Id:                     createdObl.GetId(),
		Metadata:               newMetadata2,
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	})
	s.Require().NoError(err)
	s.assertObligationBasics(updatedObl2, newName, namespaceID, namespace.Name, namespaceFQN) // Name should remain the same
	s.Equal("true", updatedObl2.GetMetadata().GetLabels()["metadata_only"])
	s.NotContains(updatedObl2.GetMetadata().GetLabels(), "updated") // Should be replaced, not extended
	s.assertObligationValues(updatedObl2)

	// Test 3: Update only name (no metadata change)
	newName2 := oblName + "-name-only-update"
	updatedObl3, err := s.db.PolicyClient.UpdateObligation(s.ctx, &obligations.UpdateObligationRequest{
		Id:   createdObl.GetId(),
		Name: newName2,
	})
	s.Require().NoError(err)
	s.assertObligationBasics(updatedObl3, newName2, namespaceID, namespace.Name, namespaceFQN)
	s.assertObligationValues(updatedObl3)

	s.deleteObligations([]string{updatedObl3.GetId()})
}

func (s *ObligationsSuite) Test_UpdateObligation_Fails() {
	oblName := oblName + "-update-fails"
	// Test 1: Invalid obligation ID
	updatedObl, err := s.db.PolicyClient.UpdateObligation(s.ctx, &obligations.UpdateObligationRequest{
		Id:   invalidID,
		Name: oblName + "-test",
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(updatedObl)

	// Test 2: Empty obligation ID
	updatedObl, err = s.db.PolicyClient.UpdateObligation(s.ctx, &obligations.UpdateObligationRequest{
		Id:   "",
		Name: oblName + "-test",
	})
	s.Require().Error(err) // Should fail due to empty ID
	s.Nil(updatedObl)

	// Test 3: No updates provided (both name and metadata are empty/nil)
	namespaceID, _, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName+"-no-updates", oblVals)

	updatedObl, err = s.db.PolicyClient.UpdateObligation(s.ctx, &obligations.UpdateObligationRequest{
		Id: createdObl.GetId(),
		// No name or metadata provided
	})
	s.Require().NoError(err) // Should succeed but not change anything
	s.NotNil(updatedObl)
	s.Equal(createdObl.GetId(), updatedObl.GetId())
	s.Equal(createdObl.GetName(), updatedObl.GetName()) // Name should remain unchanged

	// Cleanup
	s.deleteObligations([]string{createdObl.GetId()})
}

// Delete

func (s *ObligationsSuite) Test_DeleteObligation_Succeeds() {
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, oblVals)

	// Get the obligation to ensure it exists
	obl, err := s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Id: createdObl.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(obl)

	// Delete the obligation by ID
	obl, err = s.db.PolicyClient.DeleteObligation(s.ctx, &obligations.DeleteObligationRequest{
		Id: createdObl.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(obl)
	s.Equal(createdObl.GetId(), obl.GetId())

	// Attempt to get the obligation again to ensure it has been deleted
	obl, err = s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Id: createdObl.GetId(),
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(obl)

	createdObl = s.createObligation(namespaceID, oblName, oblVals)

	// Delete the obligation by FQN
	fqn := identifier.BuildOblFQN(namespaceFQN, oblName)
	obl, err = s.db.PolicyClient.DeleteObligation(s.ctx, &obligations.DeleteObligationRequest{
		Fqn: fqn,
	})
	s.Require().NoError(err)
	s.NotNil(obl)
	s.Equal(createdObl.GetId(), obl.GetId())
}

func (s *ObligationsSuite) Test_DeleteObligation_Fails() {
	// Attempt to delete an obligation with an invalid ID
	obl, err := s.db.PolicyClient.DeleteObligation(s.ctx, &obligations.DeleteObligationRequest{
		Id: invalidUUID,
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
		ObligationId: createdObl.GetId(),
		Value:        oblValPrefix + "test-1",
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"test": "value"},
		},
	})
	s.Require().NoError(err)
	s.NotNil(oblValue)
	s.Equal("value", oblValue.GetMetadata().GetLabels()["test"])
	s.assertObligationValueBasics(oblValue, oblValPrefix+"test-1", namespaceID, namespace.Name, namespaceFQN)

	// Test 2: Create obligation value by obligation FQN
	oblFQN := identifier.BuildOblFQN(namespaceFQN, oblName)
	oblValue2, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationFqn: oblFQN,
		Value:         oblValPrefix + "test-2",
	})
	s.Require().NoError(err)
	s.NotNil(oblValue2)
	s.assertObligationValueBasics(oblValue2, oblValPrefix+"test-2", namespaceID, namespace.Name, namespaceFQN)

	// Cleanup
	s.deleteObligations([]string{createdObl.GetId()})
}

func (s *ObligationsSuite) Test_CreateObligationValue_WithTriggers_IDs_Succeeds() {
	// Set up the obligation
	triggerSetup := s.setupTriggerTests()
	defer s.deleteObligations([]string{triggerSetup.createdObl.GetId()})

	// Create the obligation value with a trigger
	oblValue, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: triggerSetup.createdObl.GetId(),
		Value:        oblValPrefix + "test-1",
		Triggers: []*obligations.ValueTriggerRequest{
			{
				Action:         &common.IdNameIdentifier{Id: triggerSetup.action.GetId()},
				AttributeValue: &common.IdFqnIdentifier{Id: triggerSetup.attributeValues[0].ID},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: clientID,
					},
				},
			},
			{
				Action:         &common.IdNameIdentifier{Id: triggerSetup.action.GetId()},
				AttributeValue: &common.IdFqnIdentifier{Id: triggerSetup.attributeValues[1].ID},
			},
		},
	})

	// Assert the results
	s.Require().NoError(err)
	s.NotNil(oblValue)
	s.assertObligationValueBasics(oblValue, oblValPrefix+"test-1", triggerSetup.namespace.ID, triggerSetup.namespace.Name, httpsPrefix+triggerSetup.namespace.Name)
	s.assertTriggers(oblValue, []*TriggerAssertion{
		{
			expectedAction:            triggerSetup.action,
			expectedObligation:        triggerSetup.createdObl,
			expectedAttributeValue:    triggerSetup.attributeValues[0],
			expectedAttributeValueFQN: "https://example.com/attr/attr1/value/value1",
			expectedObligationValue:   oblValue,
			expectedClientID:          clientID,
		},
		{
			expectedAction:            triggerSetup.action,
			expectedObligation:        triggerSetup.createdObl,
			expectedAttributeValue:    triggerSetup.attributeValues[1],
			expectedAttributeValueFQN: "https://example.com/attr/attr1/value/value2",
			expectedObligationValue:   oblValue,
		},
	})
}

func (s *ObligationsSuite) Test_CreateObligationValue_WithTriggers_FQNsNames_Succeeds() {
	// Set up the obligation
	triggerSetup := s.setupTriggerTests()
	defer s.deleteObligations([]string{triggerSetup.createdObl.GetId()})

	// Create the obligation value with a trigger
	oblValue, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: triggerSetup.createdObl.GetId(),
		Value:        oblValPrefix + "test-1",
		Triggers: []*obligations.ValueTriggerRequest{
			{
				Action:         &common.IdNameIdentifier{Name: triggerSetup.action.GetName()},
				AttributeValue: &common.IdFqnIdentifier{Fqn: "https://example.com/attr/attr1/value/value1"},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: clientID,
					},
				},
			},
			{
				Action:         &common.IdNameIdentifier{Name: triggerSetup.action.GetName()},
				AttributeValue: &common.IdFqnIdentifier{Fqn: "https://example.com/attr/attr1/value/value2"},
			},
		},
	})

	// Assert the results
	s.Require().NoError(err)
	s.NotNil(oblValue)
	s.assertObligationValueBasics(oblValue, oblValPrefix+"test-1", triggerSetup.namespace.ID, triggerSetup.namespace.Name, httpsPrefix+triggerSetup.namespace.Name)
	s.assertTriggers(oblValue, []*TriggerAssertion{
		{
			expectedAction:            triggerSetup.action,
			expectedObligation:        triggerSetup.createdObl,
			expectedAttributeValue:    triggerSetup.attributeValues[0],
			expectedAttributeValueFQN: "https://example.com/attr/attr1/value/value1",
			expectedObligationValue:   oblValue,
			expectedClientID:          clientID,
		},
		{
			expectedAction:            triggerSetup.action,
			expectedObligation:        triggerSetup.createdObl,
			expectedAttributeValue:    triggerSetup.attributeValues[1],
			expectedAttributeValueFQN: "https://example.com/attr/attr1/value/value2",
			expectedObligationValue:   oblValue,
		},
	})
}

func (s *ObligationsSuite) Test_CreateObligationValue_Fails() {
	// Test 1: Invalid obligation ID
	oblValue, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: invalidUUID,
		Value:        oblValPrefix + "test",
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(oblValue)

	// Test 2: Non-existent obligation ID
	oblValue, err = s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: invalidID,
		Value:        oblValPrefix + "test",
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(oblValue)

	// Test 3: Invalid obligation FQN
	oblValue, err = s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationFqn: invalidFQN,
		Value:         oblValPrefix + "test",
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(oblValue)

	// Test 4: Non-existent obligation name in valid namespace
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, nil)
	nonExistentFQN := identifier.BuildOblFQN(namespaceFQN, "non-existent-obligation")

	oblValue, err = s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationFqn: nonExistentFQN,
		Value:         oblValPrefix + "test",
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
		Id: oblValue.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(retrievedValue)
	s.Equal(oblValue.GetId(), retrievedValue.GetId())
	s.assertObligationValueBasics(retrievedValue, oblValPrefix+"get-test", namespaceID, namespace.Name, namespaceFQN)

	// Test 2: Get obligation value by FQN
	oblValFQN := identifier.BuildOblValFQN(namespaceFQN, oblName, oblValPrefix+"get-test")
	retrievedValue2, err := s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Fqn: oblValFQN,
	})
	s.Require().NoError(err)
	s.NotNil(retrievedValue2)
	s.Equal(oblValue.GetId(), retrievedValue2.GetId())
	s.assertObligationValueBasics(retrievedValue2, oblValPrefix+"get-test", namespaceID, namespace.Name, namespaceFQN)

	// Cleanup
	s.deleteObligations([]string{createdObl.GetId()})
}

func (s *ObligationsSuite) Test_GetObligationValue_WithTriggers_Succeeds() {
	namespaceID, namespaceFQN, namespace := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName+"-val-triggers", nil)
	defer s.deleteObligations([]string{createdObl.GetId()})

	// Create obligation value with triggers
	oblValue := s.createObligationValueWithDefaultTriggers(createdObl.GetId(), oblValPrefix+"get-trigger-test")

	// Test 1: Get obligation value by ID and verify triggers are returned
	retrievedValue, err := s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Id: oblValue.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(retrievedValue)
	s.Equal(oblValue.GetId(), retrievedValue.GetId())
	s.assertObligationValueBasics(retrievedValue, oblValPrefix+"get-trigger-test", namespaceID, namespace.Name, namespaceFQN)
	s.assertObligationValuesSpecificTriggers(&policy.Obligation{
		Values: []*policy.ObligationValue{retrievedValue},
	}, []*ValueTriggerExpectation{
		{
			ID:               oblValue.GetId(),
			ExpectedTriggers: oblValue.GetTriggers(),
		},
	})

	// Test 2: Get obligation value by FQN and verify triggers are returned
	oblValFQN := identifier.BuildOblValFQN(namespaceFQN, oblName+"-val-triggers", oblValPrefix+"get-trigger-test")
	retrievedValue2, err := s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Fqn: oblValFQN,
	})
	s.Require().NoError(err)
	s.NotNil(retrievedValue2)
	s.Equal(oblValue.GetId(), retrievedValue2.GetId())
	s.assertObligationValueBasics(retrievedValue2, oblValPrefix+"get-trigger-test", namespaceID, namespace.Name, namespaceFQN)
	s.assertObligationValuesSpecificTriggers(&policy.Obligation{
		Values: []*policy.ObligationValue{retrievedValue2},
	}, []*ValueTriggerExpectation{
		{
			ID:               oblValue.GetId(),
			ExpectedTriggers: oblValue.GetTriggers(),
		},
	})
}

func (s *ObligationsSuite) Test_GetObligationValue_Fails() {
	// Test 1: Invalid value ID
	retrievedValue, err := s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Id: invalidUUID,
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(retrievedValue)

	// Test 2: Non-existent value ID
	retrievedValue, err = s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Id: invalidID,
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(retrievedValue)

	// Test 3: Invalid value FQN
	retrievedValue, err = s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Fqn: invalidFQN,
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(retrievedValue)

	// Test 4: Non-existent value name in valid obligation
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, nil)
	nonExistentValFQN := identifier.BuildOblValFQN(namespaceFQN, oblName, "non-existent-value")

	retrievedValue, err = s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Fqn: nonExistentValFQN,
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(retrievedValue)

	// Test 5: Non-existent obligation name in valid namespace
	nonExistentOblFQN := identifier.BuildOblValFQN(namespaceFQN, "non-existent-obligation", oblValPrefix+"test")
	retrievedValue, err = s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Fqn: nonExistentOblFQN,
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(retrievedValue)

	// Cleanup
	s.deleteObligations([]string{createdObl.GetId()})
}

// GetObligationValuesByFQNs

func (s *ObligationsSuite) Test_GetObligationValuesByFQNs_Succeeds() {
	// Setup test data
	namespaceID1, namespaceFQN1, namespace1 := s.getNamespaceData(nsExampleCom)
	namespaceID2, namespaceFQN2, namespace2 := s.getNamespaceData(nsExampleNet)
	namespaceID3, _, _ := s.getNamespaceData(nsExampleOrg)

	// Create obligations with values in different namespaces
	obl1 := s.createObligation(namespaceID1, oblName+"-1", []string{oblValPrefix + "val1", oblValPrefix + "val2"})
	obl2 := s.createObligation(namespaceID2, oblName+"-2", []string{oblValPrefix + "val3", oblValPrefix + "val4"})
	obl3 := s.createObligation(namespaceID3, oblName+"-3", []string{oblValPrefix + "val5"})

	// Test 1: Get multiple obligation values by FQNs
	fqns := []string{
		identifier.BuildOblValFQN(namespaceFQN1, oblName+"-1", oblValPrefix+"val1"),
		identifier.BuildOblValFQN(namespaceFQN1, oblName+"-1", oblValPrefix+"val2"),
		identifier.BuildOblValFQN(namespaceFQN2, oblName+"-2", oblValPrefix+"val3"),
	}

	oblValueList, err := s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: fqns,
	})
	s.Require().NoError(err)
	s.NotNil(oblValueList)
	s.Len(oblValueList, 3)

	// Create maps for easier verification
	expectedValues := map[string]struct{}{
		oblValPrefix + "val1": {},
		oblValPrefix + "val2": {},
		oblValPrefix + "val3": {},
	}
	foundValues := make(map[string]*policy.ObligationValue)

	for _, oblValue := range oblValueList {
		s.Contains(expectedValues, oblValue.GetValue())
		foundValues[oblValue.GetValue()] = oblValue
	}
	s.Len(foundValues, 3)

	// Verify each obligation value
	val1 := foundValues[oblValPrefix+"val1"]
	s.assertObligationValueBasics(val1, oblValPrefix+"val1", namespaceID1, namespace1.Name, namespaceFQN1)
	s.Equal(oblName+"-1", val1.GetObligation().GetName())

	val2 := foundValues[oblValPrefix+"val2"]
	s.assertObligationValueBasics(val2, oblValPrefix+"val2", namespaceID1, namespace1.Name, namespaceFQN1)
	s.Equal(oblName+"-1", val2.GetObligation().GetName())

	val3 := foundValues[oblValPrefix+"val3"]
	s.assertObligationValueBasics(val3, oblValPrefix+"val3", namespaceID2, namespace2.Name, namespaceFQN2)
	s.Equal(oblName+"-2", val3.GetObligation().GetName())

	// Test 2: Get single obligation value by FQN
	singleFQN := []string{identifier.BuildOblValFQN(namespaceFQN2, oblName+"-2", oblValPrefix+"val4")}
	oblValueList, err = s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: singleFQN,
	})
	s.Require().NoError(err)
	s.NotNil(oblValueList)
	s.Len(oblValueList, 1)
	s.assertObligationValueBasics(oblValueList[0], oblValPrefix+"val4", namespaceID2, namespace2.Name, namespaceFQN2)
	s.Equal(oblName+"-2", oblValueList[0].GetObligation().GetName())

	// Test 3: Empty FQN list should return empty result
	oblValueList, err = s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: []string{},
	})
	s.Require().NoError(err)
	s.NotNil(oblValueList)
	s.Empty(oblValueList)

	// Test 4: Get all values from a single obligation
	allValuesFromObl1 := []string{
		identifier.BuildOblValFQN(namespaceFQN1, oblName+"-1", oblValPrefix+"val1"),
		identifier.BuildOblValFQN(namespaceFQN1, oblName+"-1", oblValPrefix+"val2"),
	}
	oblValueList, err = s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: allValuesFromObl1,
	})
	s.Require().NoError(err)
	s.NotNil(oblValueList)
	s.Len(oblValueList, 2)
	for _, oblValue := range oblValueList {
		s.Contains([]string{oblValPrefix + "val1", oblValPrefix + "val2"}, oblValue.GetValue())
		s.Equal(oblName+"-1", oblValue.GetObligation().GetName())
		s.assertObligationValueBasics(oblValue, oblValue.GetValue(), namespaceID1, namespace1.Name, namespaceFQN1)
	}

	// Cleanup
	s.deleteObligations([]string{obl1.GetId(), obl2.GetId(), obl3.GetId()})
}

func (s *ObligationsSuite) Test_GetObligationValuesByFQNs_WithTriggers_Succeeds() {
	// Setup test data
	namespaceID1, namespaceFQN1, namespace1 := s.getNamespaceData(nsExampleCom)
	namespaceID2, namespaceFQN2, namespace2 := s.getNamespaceData(nsExampleNet)

	// Create obligations with values that have different triggers
	obl1 := s.createObligation(namespaceID1, oblName+"-vals-triggers-1", nil)
	obl1Val1Triggers := []*obligations.ValueTriggerRequest{
		{
			Action:         &common.IdNameIdentifier{Name: "read"},
			AttributeValue: &common.IdFqnIdentifier{Fqn: "https://example.com/attr/attr1/value/value1"},
			Context: &policy.RequestContext{
				Pep: &policy.PolicyEnforcementPoint{
					ClientId: clientID,
				},
			},
		},
	}
	oblVal1 := s.createObligationValueWithTriggers(obl1.GetId(), oblValPrefix+"trigger-val1", obl1Val1Triggers)

	obl1Val2Triggers := []*obligations.ValueTriggerRequest{
		{
			Action:         &common.IdNameIdentifier{Name: "update"},
			AttributeValue: &common.IdFqnIdentifier{Fqn: "https://example.com/attr/attr1/value/value2"},
			Context: &policy.RequestContext{
				Pep: &policy.PolicyEnforcementPoint{
					ClientId: clientID,
				},
			},
		},
	}
	obl1Val2 := s.createObligationValueWithTriggers(obl1.GetId(), oblValPrefix+"trigger-val2", obl1Val2Triggers)

	obl2 := s.createObligation(namespaceID2, oblName+"-vals-triggers-2", nil)
	obl2Triggers := []*obligations.ValueTriggerRequest{
		{
			Action:         &common.IdNameIdentifier{Name: "create"},
			AttributeValue: &common.IdFqnIdentifier{Fqn: "https://example.net/attr/attr1/value/value1"},
		},
	}
	oblVal2 := s.createObligationValueWithTriggers(obl2.GetId(), oblValPrefix+"trigger-val3", obl2Triggers) // Test 1: Get multiple obligation values by FQNs and verify triggers are returned
	fqns := []string{
		identifier.BuildOblValFQN(namespaceFQN1, oblName+"-vals-triggers-1", oblValPrefix+"trigger-val1"),
		identifier.BuildOblValFQN(namespaceFQN1, oblName+"-vals-triggers-1", oblValPrefix+"trigger-val2"),
		identifier.BuildOblValFQN(namespaceFQN2, oblName+"-vals-triggers-2", oblValPrefix+"trigger-val3"),
	}

	defer s.deleteObligations([]string{obl1.GetId(), obl2.GetId()})

	// Create a map of obligation IDs to created values for easier lookup
	oblValueMap := make(map[string][]*policy.ObligationTrigger)
	oblValueMap[oblVal1.GetId()] = oblVal1.GetTriggers()
	oblValueMap[obl1Val2.GetId()] = obl1Val2.GetTriggers()
	oblValueMap[oblVal2.GetId()] = oblVal2.GetTriggers()

	oblValueList, err := s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: fqns,
	})
	s.Require().NoError(err)
	s.NotNil(oblValueList)
	s.Len(oblValueList, 3)

	foundValues := make(map[string]*policy.ObligationValue)
	for _, oblValue := range oblValueList {
		triggers, ok := oblValueMap[oblValue.GetId()]
		s.Require().True(ok, "Obligation value ID %s not found in created values map", oblValue.GetId())

		s.assertObligationValuesSpecificTriggers(&policy.Obligation{
			Values: []*policy.ObligationValue{oblValue},
		}, []*ValueTriggerExpectation{
			{
				ID:               oblValue.GetId(),
				ExpectedTriggers: triggers,
			},
		})
		foundValues[oblValue.GetValue()] = oblValue
	}

	// Verify namespace assignments
	val1 := foundValues[oblValPrefix+"trigger-val1"]
	s.assertObligationValueBasics(val1, oblValPrefix+"trigger-val1", namespaceID1, namespace1.Name, namespaceFQN1)
	s.Equal(oblName+"-vals-triggers-1", val1.GetObligation().GetName())

	val2 := foundValues[oblValPrefix+"trigger-val2"]
	s.assertObligationValueBasics(val2, oblValPrefix+"trigger-val2", namespaceID1, namespace1.Name, namespaceFQN1)
	s.Equal(oblName+"-vals-triggers-1", val2.GetObligation().GetName())

	val3 := foundValues[oblValPrefix+"trigger-val3"]
	s.assertObligationValueBasics(val3, oblValPrefix+"trigger-val3", namespaceID2, namespace2.Name, namespaceFQN2)
	s.Equal(oblName+"-vals-triggers-2", val3.GetObligation().GetName())

	// Test 2: Get single obligation value by FQN and verify triggers
	singleFQN := []string{identifier.BuildOblValFQN(namespaceFQN1, oblName+"-vals-triggers-1", oblValPrefix+"trigger-val1")}
	oblValueList, err = s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: singleFQN,
	})
	s.Require().NoError(err)
	s.Require().NotNil(oblValueList)
	s.Require().Len(oblValueList, 1)
	s.assertObligationValueBasics(oblValueList[0], oblValPrefix+"trigger-val1", namespaceID1, namespace1.Name, namespaceFQN1)
	s.Require().Equal(oblName+"-vals-triggers-1", oblValueList[0].GetObligation().GetName())

	// Verify triggers are returned for single value
	triggers := oblValueList[0].GetTriggers()
	s.Require().NotNil(triggers)
	s.assertObligationValuesSpecificTriggers(&policy.Obligation{
		Values: oblValueList,
	}, []*ValueTriggerExpectation{
		{
			ID:               oblVal1.GetId(),
			ExpectedTriggers: triggers,
		},
	})
}

func (s *ObligationsSuite) Test_GetObligationValuesByFQNs_Fails() {
	// Setup test data
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	obl := s.createObligation(namespaceID, oblName, []string{oblValPrefix + "test-value"})

	// Test 1: Invalid FQN should return empty result (not error)
	invalidFQNs := []string{invalidFQN}
	oblValueList, err := s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: invalidFQNs,
	})
	s.Require().NoError(err)
	s.NotNil(oblValueList)
	s.Empty(oblValueList)

	// Test 2: Mix of valid and invalid FQNs should return only valid ones
	validFQN := identifier.BuildOblValFQN(namespaceFQN, oblName, oblValPrefix+"test-value")
	mixedFQNs := []string{
		validFQN,
		invalidFQN,
		"https://nonexistent.com/obl/nonexistent/val/nonexistent",
	}
	oblValueList, err = s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: mixedFQNs,
	})
	s.Require().NoError(err)
	s.NotNil(oblValueList)
	s.Len(oblValueList, 1)
	s.Equal(oblValPrefix+"test-value", oblValueList[0].GetValue())

	// Test 3: Non-existent obligation value names should return empty result
	nonExistentFQNs := []string{
		identifier.BuildOblValFQN(namespaceFQN, oblName, "nonexistent-value"),
	}
	oblValueList, err = s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: nonExistentFQNs,
	})
	s.Require().NoError(err)
	s.NotNil(oblValueList)
	s.Empty(oblValueList)

	// Test 4: Non-existent obligation names should return empty result
	nonExistentOblFQNs := []string{
		identifier.BuildOblValFQN(namespaceFQN, "nonexistent-obligation", oblValPrefix+"test-value"),
	}
	oblValueList, err = s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: nonExistentOblFQNs,
	})
	s.Require().NoError(err)
	s.NotNil(oblValueList)
	s.Empty(oblValueList)

	// Test 5: Non-existent namespace should return empty result
	nonExistentNsFQNs := []string{
		identifier.BuildOblValFQN("https://nonexistent.com", oblName, oblValPrefix+"test-value"),
	}
	oblValueList, err = s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: nonExistentNsFQNs,
	})
	s.Require().NoError(err)
	s.NotNil(oblValueList)
	s.Empty(oblValueList)

	// Test 6: Malformed FQNs should return empty result
	malformedFQNs := []string{
		namespaceFQN + "/obl/" + oblName,                                             // Missing /val/ part
		namespaceFQN + "/invalid/" + oblName + "/val/" + oblValPrefix + "test-value", // Invalid path
		namespaceFQN + "/obl/" + oblName + "/val/",                                   // Empty value name
	}
	oblValueList, err = s.db.PolicyClient.GetObligationValuesByFQNs(s.ctx, &obligations.GetObligationValuesByFQNsRequest{
		Fqns: malformedFQNs,
	})
	s.Require().NoError(err)
	s.NotNil(oblValueList)
	s.Empty(oblValueList)

	// Cleanup
	s.deleteObligations([]string{obl.GetId()})
}

// Update

func (s *ObligationsSuite) Test_UpdateObligationValue_Succeeds() {
	namespaceID, namespaceFQN, namespace := s.getNamespaceData(nsExampleCom)
	value := oblValPrefix + "update-test"
	createdObl := s.createObligation(namespaceID, oblName+"-update-succeeds", []string{value})
	oblValue := createdObl.GetValues()[0]

	// Test 1: Update obligation value by ID
	newValue := oblValPrefix + "updated-value"
	newMetadata := &common.MetadataMutable{
		Labels: map[string]string{"updated": "true", "version": "2"},
	}
	updatedValue, err := s.db.PolicyClient.UpdateObligationValue(s.ctx, &obligations.UpdateObligationValueRequest{
		Id:                     oblValue.GetId(),
		Value:                  newValue,
		Metadata:               newMetadata,
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.NotNil(updatedValue)
	s.Equal(oblValue.GetId(), updatedValue.GetId())
	s.Equal(newValue, updatedValue.GetValue())
	s.Equal("true", updatedValue.GetMetadata().GetLabels()["updated"])
	s.Equal("2", updatedValue.GetMetadata().GetLabels()["version"])
	s.assertObligationValueBasics(updatedValue, newValue, namespaceID, namespace.Name, namespaceFQN)

	// Test 2: Update only metadata (no value change)
	newMetadata2 := &common.MetadataMutable{
		Labels: map[string]string{"metadata_only": "true"},
	}
	updatedValue2, err := s.db.PolicyClient.UpdateObligationValue(s.ctx, &obligations.UpdateObligationValueRequest{
		Id:                     oblValue.GetId(),
		Metadata:               newMetadata2,
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	})
	s.Require().NoError(err)
	s.NotNil(updatedValue2)
	s.Equal(oblValue.GetId(), updatedValue2.GetId())
	s.Equal(newValue, updatedValue2.GetValue()) // Value should remain the same
	s.Equal("true", updatedValue2.GetMetadata().GetLabels()["metadata_only"])
	s.NotContains(updatedValue2.GetMetadata().GetLabels(), "updated") // Should be replaced, not extended

	// Test 3: Update only value (no metadata change)
	newValue2 := oblValPrefix + "value-only-update"
	updatedValue3, err := s.db.PolicyClient.UpdateObligationValue(s.ctx, &obligations.UpdateObligationValueRequest{
		Id:    oblValue.GetId(),
		Value: newValue2,
	})
	s.Require().NoError(err)
	s.NotNil(updatedValue3)
	s.Equal(oblValue.GetId(), updatedValue3.GetId())
	s.Equal(newValue2, updatedValue3.GetValue())
	s.assertObligationValueBasics(updatedValue3, newValue2, namespaceID, namespace.Name, namespaceFQN)

	// Cleanup
	s.deleteObligations([]string{createdObl.GetId()})
}

func (s *ObligationsSuite) Test_UpdateObligationValue_WithTriggers_Succeeds() {
	triggerSetup := s.setupTriggerTests()
	defer s.deleteObligations([]string{triggerSetup.createdObl.GetId()})

	oblValue, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: triggerSetup.createdObl.GetId(),
		Value:        oblValPrefix + "test-1",
		Triggers: []*obligations.ValueTriggerRequest{
			{
				Action:         &common.IdNameIdentifier{Id: triggerSetup.action.GetId()},
				AttributeValue: &common.IdFqnIdentifier{Id: triggerSetup.attributeValues[0].ID},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: clientID,
					},
				},
			},
			{
				Action:         &common.IdNameIdentifier{Id: triggerSetup.action.GetId()},
				AttributeValue: &common.IdFqnIdentifier{Id: triggerSetup.attributeValues[1].ID},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: clientID,
					},
				},
			},
		},
	})

	// Assert the results
	s.Require().NoError(err)
	s.NotNil(oblValue)
	s.assertObligationValueBasics(oblValue, oblValPrefix+"test-1", triggerSetup.namespace.ID, triggerSetup.namespace.Name, httpsPrefix+triggerSetup.namespace.Name)
	s.assertTriggers(oblValue, []*TriggerAssertion{
		{
			expectedAction:            triggerSetup.action,
			expectedObligation:        triggerSetup.createdObl,
			expectedAttributeValue:    triggerSetup.attributeValues[0],
			expectedAttributeValueFQN: "https://example.com/attr/attr1/value/value1",
			expectedObligationValue:   oblValue,
			expectedClientID:          clientID,
		},
		{
			expectedAction:            triggerSetup.action,
			expectedObligation:        triggerSetup.createdObl,
			expectedAttributeValueFQN: "https://example.com/attr/attr1/value/value2",
			expectedAttributeValue:    triggerSetup.attributeValues[1],
			expectedObligationValue:   oblValue,
			expectedClientID:          clientID,
		},
	})

	updatedClientID := "updated-client-id"
	updatedOblValue, err := s.db.PolicyClient.UpdateObligationValue(s.ctx, &obligations.UpdateObligationValueRequest{
		Id:    oblValue.GetId(),
		Value: oblValPrefix + "test-1-updated",
		Triggers: []*obligations.ValueTriggerRequest{
			{
				Action:         &common.IdNameIdentifier{Id: triggerSetup.action.GetId()},
				AttributeValue: &common.IdFqnIdentifier{Id: triggerSetup.attributeValues[0].ID},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: updatedClientID,
					},
				},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(updatedOblValue)
	s.assertObligationValueBasics(updatedOblValue, oblValPrefix+"test-1-updated", triggerSetup.namespace.ID, triggerSetup.namespace.Name, httpsPrefix+triggerSetup.namespace.Name)
	s.assertTriggers(updatedOblValue, []*TriggerAssertion{
		{
			expectedAction:            triggerSetup.action,
			expectedObligation:        triggerSetup.createdObl,
			expectedAttributeValue:    triggerSetup.attributeValues[0],
			expectedAttributeValueFQN: "https://example.com/attr/attr1/value/value1",
			expectedObligationValue:   updatedOblValue,
			expectedClientID:          updatedClientID,
		},
	})
	s.Require().NotEqual(oblValue.GetTriggers()[1].GetAttributeValue().GetFqn(), updatedOblValue.GetTriggers()[0].GetAttributeValue().GetFqn(), "The second trigger should have been removed")

	// Ensure oblValue has new triggers after update
	oblValueAfterUpdate, err := s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Id: oblValue.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(oblValueAfterUpdate)
	s.assertObligationValuesSpecificTriggers(&policy.Obligation{
		Values: []*policy.ObligationValue{oblValueAfterUpdate},
	}, []*ValueTriggerExpectation{
		{
			ID:               updatedOblValue.GetId(),
			ExpectedTriggers: updatedOblValue.GetTriggers(),
		},
	})

	// Update by FQN values
	updatedOblValue, err = s.db.PolicyClient.UpdateObligationValue(s.ctx, &obligations.UpdateObligationValueRequest{
		Id:    oblValue.GetId(),
		Value: oblValPrefix + "test-1-updated",
		Triggers: []*obligations.ValueTriggerRequest{
			{
				Action:         &common.IdNameIdentifier{Name: "read"},
				AttributeValue: &common.IdFqnIdentifier{Fqn: "https://example.com/attr/attr1/value/value2"},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(updatedOblValue)
	s.assertObligationValueBasics(updatedOblValue, oblValPrefix+"test-1-updated", triggerSetup.namespace.ID, triggerSetup.namespace.Name, httpsPrefix+triggerSetup.namespace.Name)
	s.assertTriggers(updatedOblValue, []*TriggerAssertion{
		{
			expectedAction:            triggerSetup.action,
			expectedObligation:        triggerSetup.createdObl,
			expectedAttributeValue:    triggerSetup.attributeValues[1],
			expectedAttributeValueFQN: "https://example.com/attr/attr1/value/value2",
			expectedObligationValue:   updatedOblValue,
		},
	})
	s.Require().Equal(oblValue.GetTriggers()[1].GetAttributeValue().GetFqn(), updatedOblValue.GetTriggers()[0].GetAttributeValue().GetFqn())

	oblValueAfterUpdate, err = s.db.PolicyClient.GetObligationValue(s.ctx, &obligations.GetObligationValueRequest{
		Id: oblValue.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(oblValueAfterUpdate)
	s.assertObligationValuesSpecificTriggers(&policy.Obligation{
		Values: []*policy.ObligationValue{oblValueAfterUpdate},
	}, []*ValueTriggerExpectation{
		{
			ID:               updatedOblValue.GetId(),
			ExpectedTriggers: updatedOblValue.GetTriggers(),
		},
	})
}

func (s *ObligationsSuite) Test_UpdateObligationValue_Fails() {
	oblName := oblName + "-update-fails"
	// Test 1: Invalid value ID
	updatedValue, err := s.db.PolicyClient.UpdateObligationValue(s.ctx, &obligations.UpdateObligationValueRequest{
		Id:    invalidID,
		Value: oblValPrefix + "test",
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(updatedValue)

	// Test 2: Empty value ID
	updatedValue, err = s.db.PolicyClient.UpdateObligationValue(s.ctx, &obligations.UpdateObligationValueRequest{
		Id:    "",
		Value: oblValPrefix + "test",
	})
	s.Require().Error(err) // Should fail due to empty ID
	s.Nil(updatedValue)

	// Test 3: No updates provided (both value and metadata are empty/nil)
	namespaceID, _, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName+"-no-updates", []string{oblValPrefix + "test"})
	oblValue := createdObl.GetValues()[0]

	updatedValue, err = s.db.PolicyClient.UpdateObligationValue(s.ctx, &obligations.UpdateObligationValueRequest{
		Id: oblValue.GetId(),
		// No value or metadata provided
	})
	s.Require().NoError(err) // Should succeed but not change anything
	s.NotNil(updatedValue)
	s.Equal(oblValue.GetId(), updatedValue.GetId())
	s.Equal(oblValue.GetValue(), updatedValue.GetValue()) // Value should remain unchanged

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
		Id: oblValues[0].GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(deleted)
	s.Equal(oblValues[0].GetId(), deleted.GetId())

	// Delete by FQN + value name
	oblValFQN := identifier.BuildOblValFQN(namespaceFQN, oblName, values[1])
	deleted2, err := s.db.PolicyClient.DeleteObligationValue(s.ctx, &obligations.DeleteObligationValueRequest{
		Fqn: oblValFQN,
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
		Id: invalidUUID,
	})
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
	s.Nil(deleted)

	// Non-existent value ID
	deleted, err = s.db.PolicyClient.DeleteObligationValue(s.ctx, &obligations.DeleteObligationValueRequest{
		Id: invalidID,
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(deleted)

	// Invalid value FQN
	deleted, err = s.db.PolicyClient.DeleteObligationValue(s.ctx, &obligations.DeleteObligationValueRequest{
		Fqn: invalidFQN,
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(deleted)

	// Non-existent value name in valid obligation
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, nil)
	nonExistentValFQN := identifier.BuildOblValFQN(namespaceFQN, oblName, "non-existent-value")
	deleted, err = s.db.PolicyClient.DeleteObligationValue(s.ctx, &obligations.DeleteObligationValueRequest{
		Fqn: nonExistentValFQN,
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
	s.Equal(identifier.BuildOblFQN(namespaceFQN, name), obl.GetFqn())
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
	s.Equal(identifier.BuildOblValFQN(namespaceFQN, oblValue.GetObligation().GetName(), value), oblValue.GetFqn())
}

func (s *ObligationsSuite) setupTriggerTests() *TriggerSetup {
	namespaceID, _, namespace := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName, nil)
	triggerAction := s.f.GetStandardAction("read")
	triggerAttributeValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	triggerAttributeValue2 := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2")

	return &TriggerSetup{
		createdObl: createdObl,
		namespace:  &namespace,
		action:     triggerAction,
		attributeValues: []*fixtures.FixtureDataAttributeValue{
			&triggerAttributeValue,
			&triggerAttributeValue2,
		},
	}
}

func (s *ObligationsSuite) assertTriggers(oblVal *policy.ObligationValue, expectedTriggers []*TriggerAssertion) {
	triggers := oblVal.GetTriggers()
	s.Require().NotNil(triggers)
	s.Require().Len(triggers, len(expectedTriggers))
	found := 0
	for _, t := range triggers {
		for _, expected := range expectedTriggers {
			if t.GetAction().GetId() == expected.expectedAction.GetId() &&
				t.GetAttributeValue().GetId() == expected.expectedAttributeValue.ID &&
				t.GetObligationValue().GetId() == expected.expectedObligationValue.GetId() {
				found++
				s.Require().Equal(expected.expectedAction.GetName(), t.GetAction().GetName())
				s.Require().Equal(expected.expectedAttributeValue.Value, t.GetAttributeValue().GetValue())
				s.Require().Equal(expected.expectedAttributeValueFQN, t.GetAttributeValue().GetFqn())
				s.Require().Equal(expected.expectedObligationValue.GetValue(), t.GetObligationValue().GetValue())
				s.Require().Equal(expected.expectedObligationValue.GetObligation().GetId(), t.GetObligationValue().GetObligation().GetId())
				s.Require().Equal(oblVal.GetObligation().GetId(), t.GetObligationValue().GetObligation().GetId())
				if expected.expectedClientID != "" {
					s.Require().Len(t.GetContext(), 1)
					s.Require().Equal(expected.expectedClientID, t.GetContext()[0].GetPep().GetClientId())
				} else {
					s.Require().Empty(t.GetContext())
				}
			}
		}
	}
	s.Require().Equal(len(expectedTriggers), found)
}

func (s *ObligationsSuite) createObligation(namespaceID, name string, values []string) *policy.Obligation {
	obl, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceId: namespaceID,
		Name:        name,
		Values:      values,
	})
	s.Require().NoError(err)
	return obl
}

func (s *ObligationsSuite) createObligationByFQN(namespaceFQN, name string, values []string) *policy.Obligation {
	obl, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceFqn: namespaceFQN,
		Name:         name,
		Values:       values,
	})
	s.Require().NoError(err)
	return obl
}

func (s *ObligationsSuite) deleteObligation(oblID string) {
	_, err := s.db.PolicyClient.DeleteObligation(s.ctx, &obligations.DeleteObligationRequest{
		Id: oblID,
	})
	s.Require().NoError(err)
}

func (s *ObligationsSuite) deleteObligations(oblIDs []string) {
	for _, oblID := range oblIDs {
		defer s.deleteObligation(oblID)
	}
}

// Helper function to create obligation value with triggers
func (s *ObligationsSuite) createObligationValueWithTriggers(obligationID string, value string, customTriggers []*obligations.ValueTriggerRequest) *policy.ObligationValue {
	var triggers []*obligations.ValueTriggerRequest

	if customTriggers != nil {
		triggers = customTriggers
	} else {
		// Default triggers for backward compatibility
		triggerAction := s.f.GetStandardAction("read")
		triggerAttributeValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
		triggerAttributeValue2 := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2")

		triggers = []*obligations.ValueTriggerRequest{
			{
				Action:         &common.IdNameIdentifier{Id: triggerAction.GetId()},
				AttributeValue: &common.IdFqnIdentifier{Id: triggerAttributeValue.ID},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: clientID,
					},
				},
			},
			{
				Action:         &common.IdNameIdentifier{Id: triggerAction.GetId()},
				AttributeValue: &common.IdFqnIdentifier{Id: triggerAttributeValue2.ID},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: clientID,
					},
				},
			},
		}
	}

	oblValue, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: obligationID,
		Value:        value,
		Triggers:     triggers,
	})
	s.Require().NoError(err)
	return oblValue
}

// Helper function to create obligation value with default triggers (backward compatibility)
func (s *ObligationsSuite) createObligationValueWithDefaultTriggers(obligationID string, value string) *policy.ObligationValue {
	return s.createObligationValueWithTriggers(obligationID, value, nil)
}

// Enhanced helper function to assert specific triggers for specific obligation values
func (s *ObligationsSuite) assertObligationValuesSpecificTriggers(obl *policy.Obligation, expectedValues []*ValueTriggerExpectation) {
	values := obl.GetValues()
	s.Require().Len(values, len(expectedValues))

	// Create a map of actual values for easy lookup
	actualValueMap := make(map[string]*policy.ObligationValue)
	for _, value := range values {
		actualValueMap[value.GetId()] = value
	}

	// Validate each expected value and its triggers
	for _, expectedValue := range expectedValues {
		actualValue, found := actualValueMap[expectedValue.ID]
		s.Require().True(found, "Expected obligation value '%s' not found", expectedValue.ID)

		triggers := actualValue.GetTriggers()
		s.Require().Len(triggers, len(expectedValue.ExpectedTriggers),
			"Expected %d triggers for value '%s', but got %d",
			len(expectedValue.ExpectedTriggers), expectedValue.ID, len(triggers))

		// Create a map of actual triggers for easier comparison
		actualTriggerMap := make(map[string]*policy.ObligationTrigger)
		for _, trigger := range triggers {
			actualTriggerMap[trigger.GetId()] = trigger
		}

		// Validate each expected trigger
		for _, expectedTrigger := range expectedValue.ExpectedTriggers {
			actualTrigger, triggerFound := actualTriggerMap[expectedTrigger.GetId()]
			s.Require().True(triggerFound,
				"Expected trigger with action '%s' and attribute value ID '%s' not found for value '%s'",
				expectedTrigger.GetAction().GetName(), expectedTrigger.GetAttributeValue().GetId(), expectedValue.ID)

			// Verify action details
			s.Require().NotNil(actualTrigger.GetAction())
			s.Require().Equal(expectedTrigger.GetAction().GetId(), actualTrigger.GetAction().GetId())
			s.Require().Equal(expectedTrigger.GetAction().GetName(), actualTrigger.GetAction().GetName())

			// Verify attribute_value details
			s.Require().NotNil(actualTrigger.GetAttributeValue())
			s.Require().Equal(expectedTrigger.GetAttributeValue().GetId(), actualTrigger.GetAttributeValue().GetId())
			s.Require().Equal(expectedTrigger.GetAttributeValue().GetValue(), actualTrigger.GetAttributeValue().GetValue())
			s.Require().Equal(expectedTrigger.GetAttributeValue().GetFqn(), actualTrigger.GetAttributeValue().GetFqn())
			s.Require().Nil(actualTrigger.GetObligationValue(),
				"Trigger's obligation_value field should be empty to avoid circular references")
			s.Require().Len(actualTrigger.GetContext(), len(expectedTrigger.GetContext()))
			expectedClientIDs := make(map[string]bool)
			for _, expReqContext := range expectedTrigger.GetContext() {
				expectedClientIDs[expReqContext.GetPep().GetClientId()] = true
			}
			for _, actReqContext := range actualTrigger.GetContext() {
				s.Require().True(expectedClientIDs[actReqContext.GetPep().GetClientId()], "unexpected client id %s", actReqContext.GetPep().GetClientId())
			}
		}
	}
}

// Test_ListObligations_EmptyNamespaceId_ReturnsAll validates that empty string parameters
// are properly treated as NULL
func (s *ObligationsSuite) Test_ListObligations_EmptyNamespaceId_ReturnsAll() {
	// Create obligations in different namespaces
	namespaceID1, _, _ := s.getNamespaceData(nsExampleCom)
	namespaceID2, _, _ := s.getNamespaceData(nsExampleNet)

	obl1 := s.createObligation(namespaceID1, oblName+"-empty-test-1", nil)
	obl2 := s.createObligation(namespaceID2, oblName+"-empty-test-2", nil)

	defer s.deleteObligations([]string{obl1.GetId(), obl2.GetId()})

	// List with empty namespace_id should return all obligations
	allObligations, _, err := s.db.PolicyClient.ListObligations(s.ctx, &obligations.ListObligationsRequest{
		NamespaceId: "", // Empty string should be treated as NULL
	})
	s.Require().NoError(err)
	s.NotNil(allObligations)
	s.GreaterOrEqual(len(allObligations), 2, "Should return at least our two test obligations")

	// Verify our test obligations are in the results
	found1, found2 := false, false
	for _, obl := range allObligations {
		if obl.GetId() == obl1.GetId() {
			found1 = true
		}
		if obl.GetId() == obl2.GetId() {
			found2 = true
		}
	}
	s.True(found1, "Should find obligation from namespace 1")
	s.True(found2, "Should find obligation from namespace 2")
}

// Test_GetObligation_ByIdAndFqn_ReturnSameResult validates that getObligation works correctly
// with both ID and FQN lookups
func (s *ObligationsSuite) Test_GetObligation_ByIdAndFqn_ReturnSameResult() {
	namespaceID, namespaceFQN, _ := s.getNamespaceData(nsExampleCom)
	createdObl := s.createObligation(namespaceID, oblName+"-dual-lookup-test", oblVals)

	defer s.deleteObligations([]string{createdObl.GetId()})

	// Get by ID
	oblByID, err := s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Id: createdObl.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(oblByID)

	// Get by FQN
	oblByFQN, err := s.db.PolicyClient.GetObligation(s.ctx, &obligations.GetObligationRequest{
		Fqn: namespaceFQN + "/obl/" + oblName + "-dual-lookup-test",
	})
	s.Require().NoError(err)
	s.NotNil(oblByFQN)

	// Verify both return the same obligation
	s.True(proto.Equal(oblByID, oblByFQN))
}
