package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/fixtures"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	policydb "github.com/opentdf/platform/services/policy/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type NamespacesSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context
}

const nonExistentNamespaceId = "88888888-2222-3333-4444-999999999999"

var (
	deactivatedNsId        string
	deactivatedAttrId      string
	deactivatedAttrValueId string
	stillActiveNsId        string
	stillActiveAttributeId string
)

func (s *NamespacesSuite) SetupSuite() {
	slog.Info("setting up db.Namespaces test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_namespaces"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
	deactivatedNsId, deactivatedAttrId, deactivatedAttrValueId = setupCascadeDeactivateNamespace(s)
}

func (s *NamespacesSuite) TearDownSuite() {
	slog.Info("tearing down db.Namespaces test suite")
	s.f.TearDown()
}

func (s *NamespacesSuite) getActiveNamespaceFixtures() []fixtures.FixtureDataNamespace {
	return []fixtures.FixtureDataNamespace{
		s.f.GetNamespaceKey("example.com"),
		s.f.GetNamespaceKey("example.net"),
		s.f.GetNamespaceKey("example.org"),
	}
}

func (s *NamespacesSuite) Test_CreateNamespace() {
	testData := s.getActiveNamespaceFixtures()

	for _, ns := range testData {
		ns.Name = strings.Replace(ns.Name, "example", "test", 1)
		createdNamespace, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: ns.Name})
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), createdNamespace)
	}

	// Creating a namespace with a name conflict should fail
	for _, ns := range testData {
		_, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: ns.Name})
		assert.NotNil(s.T(), err)
		assert.ErrorIs(s.T(), err, db.ErrUniqueConstraintViolation)
	}
}

func (s *NamespacesSuite) Test_GetNamespace() {
	testData := s.getActiveNamespaceFixtures()

	for _, test := range testData {
		gotNamespace, err := s.db.PolicyClient.GetNamespace(s.ctx, test.Id)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), gotNamespace)
		// name retrieved by ID equal to name used to create
		assert.Equal(s.T(), test.Name, gotNamespace.Name)
	}

	// Getting a namespace with an nonExistent id should fail
	_, err := s.db.PolicyClient.GetNamespace(s.ctx, nonExistentNamespaceId)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *NamespacesSuite) Test_GetNamespace_InactiveState_Succeeds() {
	inactive := s.f.GetNamespaceKey("deactivated_ns")
	// Ensure our fixtures matches expected string enum
	assert.Equal(s.T(), inactive.Active, false)

	got, err := s.db.PolicyClient.GetNamespace(s.ctx, inactive.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), inactive.Name, got.Name)
}

func (s *NamespacesSuite) Test_GetNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.GetNamespace(s.ctx, nonExistentNamespaceId)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
	assert.Nil(s.T(), ns)
}

func (s *NamespacesSuite) Test_ListNamespaces() {
	testData := s.getActiveNamespaceFixtures()

	gotNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, policydb.StateActive)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespaces)
	assert.GreaterOrEqual(s.T(), len(gotNamespaces), len(testData))
}

func (s *NamespacesSuite) Test_UpdateNamespace() {
	fixedLabel := "fixed label"
	updateLabel := "update label"
	updatedLabel := "true"
	newLabel := "new label"

	labels := map[string]string{
		"fixed":  fixedLabel,
		"update": updateLabel,
	}
	updateLabels := map[string]string{
		"update": updatedLabel,
		"new":    newLabel,
	}
	expectedLabels := map[string]string{
		"fixed":  fixedLabel,
		"update": updatedLabel,
		"new":    newLabel,
	}

	created, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "updating-namespace.com",
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	updatedWithoutChange, err := s.db.PolicyClient.UpdateNamespace(s.ctx, created.Id, &namespaces.UpdateNamespaceRequest{})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updatedWithoutChange)
	assert.Equal(s.T(), created.Id, updatedWithoutChange.Id)

	updatedWithChange, err := s.db.PolicyClient.UpdateNamespace(s.ctx, created.Id, &namespaces.UpdateNamespaceRequest{
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updatedWithChange)
	assert.Equal(s.T(), created.Id, updatedWithChange.Id)

	got, err := s.db.PolicyClient.GetNamespace(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), created.Id, got.Id)
	assert.EqualValues(s.T(), expectedLabels, got.Metadata.GetLabels())
}

func (s *NamespacesSuite) Test_UpdateNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.UpdateNamespace(s.ctx, nonExistentNamespaceId, &namespaces.UpdateNamespaceRequest{
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"updated": "true"},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
	assert.Nil(s.T(), ns)
}

func (s *NamespacesSuite) Test_DeleteNamespace() {
	testData := s.getActiveNamespaceFixtures()

	// Deletion should fail when the namespace is referenced as FK in attribute(s)
	for _, ns := range testData {
		deleted, err := s.db.PolicyClient.DeleteNamespace(s.ctx, ns.Id)
		assert.NotNil(s.T(), err)
		assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
		assert.Nil(s.T(), deleted)
	}

	// Deletion should succeed when NOT referenced as FK in attribute(s)
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "deleting-namespace.com"})
	assert.Nil(s.T(), err)
	assert.NotEqual(s.T(), "", n)

	deleted, err := s.db.PolicyClient.DeleteNamespace(s.ctx, n.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deleted)

	// Deleted namespace should not be found on List
	gotNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, policydb.StateActive)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespaces)
	for _, ns := range gotNamespaces {
		assert.NotEqual(s.T(), n.Id, ns.Id)
	}

	// Deleted namespace should not be found on Get
	_, err = s.db.PolicyClient.GetNamespace(s.ctx, n.Id)
	fmt.Println(err)
	assert.NotNil(s.T(), err)
}

func (s *NamespacesSuite) Test_DeactivateNamespace() {
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "deactivating-namespace.com"})
	assert.Nil(s.T(), err)
	assert.NotEqual(s.T(), "", n)

	inactive, err := s.db.PolicyClient.DeactivateNamespace(s.ctx, n.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), inactive)

	// Deactivated namespace should not be found on List
	gotNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, policydb.StateActive)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespaces)
	for _, ns := range gotNamespaces {
		assert.NotEqual(s.T(), n.Id, ns.Id)
	}

	// inactive namespace should still be found on Get
	gotNamespace, err := s.db.PolicyClient.GetNamespace(s.ctx, n.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespace)
	assert.Equal(s.T(), n.Id, gotNamespace.Id)
	assert.Equal(s.T(), false, gotNamespace.Active.Value)
}

// reusable setup for creating a namespace -> attr -> value and then deactivating the namespace (cascades down)
func setupCascadeDeactivateNamespace(s *NamespacesSuite) (string, string, string) {
	// create a namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "cascading-deactivate-namespace"})
	assert.Nil(s.T(), err)
	assert.NotEqual(s.T(), "", n)

	// add an attribute under that namespaces
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__cascading-deactivate-attribute",
		NamespaceId: n.Id,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)

	// add a value under that attribute
	val := &attributes.CreateAttributeValueRequest{
		Value: "test__cascading-deactivate-value",
	}
	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.Id, val)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdVal)

	// deactivate the namespace
	deletedNs, err := s.db.PolicyClient.DeactivateNamespace(s.ctx, n.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deletedNs)

	return n.Id, createdAttr.Id, createdVal.Id
}

func (s *NamespacesSuite) Test_DeactivateNamespace_Cascades_List() {
	type test struct {
		name     string
		testFunc func(state string) bool
		state    string
		isFound  bool
	}

	listNamespaces := func(state string) bool {
		listedNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, state)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), listedNamespaces)
		for _, ns := range listedNamespaces {
			if deactivatedNsId == ns.Id {
				return true
			}
		}
		return false
	}

	listAttributes := func(state string) bool {
		listedAttrs, err := s.db.PolicyClient.ListAllAttributes(s.ctx, state)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), listedAttrs)
		for _, a := range listedAttrs {
			if deactivatedAttrId == a.Id {
				return true
			}
		}
		return false
	}

	listValues := func(state string) bool {
		listedVals, err := s.db.PolicyClient.ListAttributeValues(s.ctx, deactivatedAttrId, state)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), listedVals)
		for _, v := range listedVals {
			if deactivatedAttrValueId == v.Id {
				return true
			}
		}
		return false
	}

	tests := []test{
		{
			name:     "namespace is NOT found in LIST of ACTIVE",
			testFunc: listNamespaces,
			state:    policydb.StateActive,
			isFound:  false,
		},
		{
			name:     "namespace is found when filtering for INACTIVE state",
			testFunc: listNamespaces,
			state:    policydb.StateInactive,
			isFound:  true,
		},
		{
			name:     "namespace is found when filtering for ANY state",
			testFunc: listNamespaces,
			state:    policydb.StateAny,
			isFound:  true,
		},
		{
			name:     "attribute is found when filtering for INACTIVE state",
			testFunc: listAttributes,
			state:    policydb.StateInactive,
			isFound:  true,
		},
		{
			name:     "attribute is found when filtering for ANY state",
			testFunc: listAttributes,
			state:    policydb.StateAny,
			isFound:  true,
		},
		{
			name:     "attribute is NOT found when filtering for ACTIVE state",
			testFunc: listAttributes,
			state:    policydb.StateActive,
			isFound:  false,
		},
		{
			name:     "value is NOT found in LIST of ACTIVE",
			testFunc: listValues,
			state:    policydb.StateActive,
			isFound:  false,
		},
		{
			name:     "value is found when filtering for INACTIVE state",
			testFunc: listValues,
			state:    policydb.StateInactive,
			isFound:  true,
		},
		{
			name:     "value is found when filtering for ANY state",
			testFunc: listValues,
			state:    policydb.StateAny,
			isFound:  true,
		},
	}

	for _, tableTest := range tests {
		s.T().Run(tableTest.name, func(t *testing.T) {
			found := tableTest.testFunc(tableTest.state)
			assert.Equal(t, tableTest.isFound, found)
		})
	}
}

func (s *NamespacesSuite) Test_DeactivateNamespace_Cascades_ToAttributesAndValues_Get() {
	// ensure the namespace has state inactive
	gotNs, err := s.db.PolicyClient.GetNamespace(s.ctx, deactivatedNsId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNs)
	assert.Equal(s.T(), false, gotNs.Active.Value)

	// ensure the attribute has state inactive
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, deactivatedAttrId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotAttr)
	assert.Equal(s.T(), false, gotAttr.Active.Value)

	// ensure the value has state inactive
	gotVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, deactivatedAttrValueId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotVal)
	assert.Equal(s.T(), false, gotVal.Active.Value)
}

func (s *NamespacesSuite) Test_DeleteNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.DeleteNamespace(s.ctx, nonExistentNamespaceId)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
	assert.Nil(s.T(), ns)

	ns, err = s.db.PolicyClient.DeleteNamespace(s.ctx, nonExistentNamespaceId)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
	assert.Nil(s.T(), ns)
}

func (s *NamespacesSuite) Test_DeactivateNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.DeactivateNamespace(s.ctx, nonExistentNamespaceId)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
	assert.Nil(s.T(), ns)

	ns, err = s.db.PolicyClient.DeactivateNamespace(s.ctx, nonExistentNamespaceId)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
	assert.Nil(s.T(), ns)
}

func TestNamespacesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping namespaces integration tests")
	}
	suite.Run(t, new(NamespacesSuite))
}
