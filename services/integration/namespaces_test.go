package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/services/internal/db"
	"github.com/opentdf/platform/services/internal/fixtures"
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
		s.NoError(err)
		s.NotNil(createdNamespace)
	}

	// Creating a namespace with a name conflict should fail
	for _, ns := range testData {
		_, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: ns.Name})
		s.NotNil(err)
		s.ErrorIs(err, db.ErrUniqueConstraintViolation)
	}
}

func (s *NamespacesSuite) Test_GetNamespace() {
	testData := s.getActiveNamespaceFixtures()

	for _, test := range testData {
		gotNamespace, err := s.db.PolicyClient.GetNamespace(s.ctx, test.Id)
		s.NoError(err)
		s.NotNil(gotNamespace)
		// name retrieved by ID equal to name used to create
		s.Equal(test.Name, gotNamespace.GetName())
	}

	// Getting a namespace with an nonExistent id should fail
	_, err := s.db.PolicyClient.GetNamespace(s.ctx, nonExistentNamespaceId)
	s.NotNil(err)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *NamespacesSuite) Test_GetNamespace_InactiveState_Succeeds() {
	inactive := s.f.GetNamespaceKey("deactivated_ns")
	// Ensure our fixtures matches expected string enum
	s.Equal(inactive.Active, false)

	got, err := s.db.PolicyClient.GetNamespace(s.ctx, inactive.Id)
	s.NoError(err)
	s.NotNil(got)
	s.Equal(inactive.Name, got.GetName())
}

func (s *NamespacesSuite) Test_GetNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.GetNamespace(s.ctx, nonExistentNamespaceId)
	s.NotNil(err)
	s.ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)
}

func (s *NamespacesSuite) Test_ListNamespaces() {
	testData := s.getActiveNamespaceFixtures()

	gotNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, policydb.StateActive)
	s.NoError(err)
	s.NotNil(gotNamespaces)
	s.GreaterOrEqual(len(gotNamespaces), len(testData))
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
	s.NoError(err)
	s.NotNil(created)

	updatedWithoutChange, err := s.db.PolicyClient.UpdateNamespace(s.ctx, created.GetId(), &namespaces.UpdateNamespaceRequest{})
	s.NoError(err)
	s.NotNil(updatedWithoutChange)
	s.Equal(created.GetId(), updatedWithoutChange.GetId())

	updatedWithChange, err := s.db.PolicyClient.UpdateNamespace(s.ctx, created.GetId(), &namespaces.UpdateNamespaceRequest{
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.NoError(err)
	s.NotNil(updatedWithChange)
	s.Equal(created.GetId(), updatedWithChange.GetId())

	got, err := s.db.PolicyClient.GetNamespace(s.ctx, created.GetId())
	s.NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.EqualValues(expectedLabels, got.GetMetadata().GetLabels())
}

func (s *NamespacesSuite) Test_UpdateNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.UpdateNamespace(s.ctx, nonExistentNamespaceId, &namespaces.UpdateNamespaceRequest{
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"updated": "true"},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.NotNil(err)
	s.ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)
}

func (s *NamespacesSuite) Test_DeleteNamespace() {
	testData := s.getActiveNamespaceFixtures()

	// Deletion should fail when the namespace is referenced as FK in attribute(s)
	for _, ns := range testData {
		deleted, err := s.db.PolicyClient.DeleteNamespace(s.ctx, ns.Id)
		s.NotNil(err)
		s.ErrorIs(err, db.ErrForeignKeyViolation)
		s.Nil(deleted)
	}

	// Deletion should succeed when NOT referenced as FK in attribute(s)
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "deleting-namespace.com"})
	s.NoError(err)
	s.NotEqual("", n)

	deleted, err := s.db.PolicyClient.DeleteNamespace(s.ctx, n.GetId())
	s.NoError(err)
	s.NotNil(deleted)

	// Deleted namespace should not be found on List
	gotNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, policydb.StateActive)
	s.NoError(err)
	s.NotNil(gotNamespaces)
	for _, ns := range gotNamespaces {
		s.NotEqual(n.GetId(), ns.GetId())
	}

	// Deleted namespace should not be found on Get
	_, err = s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	fmt.Println(err)
	s.NotNil(err)
}

func (s *NamespacesSuite) Test_DeactivateNamespace() {
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "deactivating-namespace.com"})
	s.NoError(err)
	s.NotEqual("", n)

	inactive, err := s.db.PolicyClient.DeactivateNamespace(s.ctx, n.GetId())
	s.NoError(err)
	s.NotNil(inactive)

	// Deactivated namespace should not be found on List
	gotNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, policydb.StateActive)
	s.NoError(err)
	s.NotNil(gotNamespaces)
	for _, ns := range gotNamespaces {
		s.NotEqual(n.GetId(), ns.GetId())
	}

	// inactive namespace should still be found on Get
	gotNamespace, err := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.NoError(err)
	s.NotNil(gotNamespace)
	s.Equal(n.GetId(), gotNamespace.GetId())
	s.Equal(false, gotNamespace.GetActive().GetValue())
}

// reusable setup for creating a namespace -> attr -> value and then deactivating the namespace (cascades down)
func setupCascadeDeactivateNamespace(s *NamespacesSuite) (string, string, string) {
	// create a namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "cascading-deactivate-namespace"})
	s.NoError(err)
	s.NotEqual("", n)

	// add an attribute under that namespaces
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__cascading-deactivate-attribute",
		NamespaceId: n.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NoError(err)
	s.NotNil(createdAttr)

	// add a value under that attribute
	val := &attributes.CreateAttributeValueRequest{
		Value: "test__cascading-deactivate-value",
	}
	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.GetId(), val)
	s.NoError(err)
	s.NotNil(createdVal)

	// deactivate the namespace
	deletedNs, err := s.db.PolicyClient.DeactivateNamespace(s.ctx, n.GetId())
	s.NoError(err)
	s.NotNil(deletedNs)

	return n.GetId(), createdAttr.GetId(), createdVal.GetId()
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
		s.NoError(err)
		s.NotNil(listedNamespaces)
		for _, ns := range listedNamespaces {
			if deactivatedNsId == ns.GetId() {
				return true
			}
		}
		return false
	}

	listAttributes := func(state string) bool {
		listedAttrs, err := s.db.PolicyClient.ListAllAttributes(s.ctx, state, "")
		s.NoError(err)
		s.NotNil(listedAttrs)
		for _, a := range listedAttrs {
			if deactivatedAttrId == a.GetId() {
				return true
			}
		}
		return false
	}

	listValues := func(state string) bool {
		listedVals, err := s.db.PolicyClient.ListAttributeValues(s.ctx, deactivatedAttrId, state)
		s.NoError(err)
		s.NotNil(listedVals)
		for _, v := range listedVals {
			if deactivatedAttrValueId == v.GetId() {
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
	s.NoError(err)
	s.NotNil(gotNs)
	s.Equal(false, gotNs.GetActive().GetValue())

	// ensure the attribute has state inactive
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, deactivatedAttrId)
	s.NoError(err)
	s.NotNil(gotAttr)
	s.Equal(false, gotAttr.GetActive().GetValue())

	// ensure the value has state inactive
	gotVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, deactivatedAttrValueId)
	s.NoError(err)
	s.NotNil(gotVal)
	s.Equal(false, gotVal.GetActive().GetValue())
}

func (s *NamespacesSuite) Test_DeleteNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.DeleteNamespace(s.ctx, nonExistentNamespaceId)
	s.NotNil(err)
	s.ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)

	ns, err = s.db.PolicyClient.DeleteNamespace(s.ctx, nonExistentNamespaceId)
	s.NotNil(err)
	s.ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)
}

func (s *NamespacesSuite) Test_DeactivateNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.DeactivateNamespace(s.ctx, nonExistentNamespaceId)
	s.NotNil(err)
	s.ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)

	ns, err = s.db.PolicyClient.DeactivateNamespace(s.ctx, nonExistentNamespaceId)
	s.NotNil(err)
	s.ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)
}

func TestNamespacesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping namespaces integration tests")
	}
	suite.Run(t, new(NamespacesSuite))
}
